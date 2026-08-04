use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{
        atomic::{AtomicU32, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hns_consensus::Network;
use hns_p2p_experimental::DENUO_EXTENSION_SERVICE;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, Mutex, RwLock},
    task::JoinSet,
};

use crate::{
    brontide::{inbound_handshake, outbound_handshake, BrontideIdentity, BrontideSession},
    constants::{DEFAULT_USER_AGENT, PROTOCOL_VERSION, SERVICE_NETWORK},
    denuo::{DenuoRuntimeMetrics, DenuoSummary},
    handshake::{PeerDirection, PeerState},
    hip76::{hip76_advertised_services, Hip76ProviderPolicy, Hip76SessionConfig, Hip76Summary},
    odoh::{
        DirectTargetLocator, OdohFailureReason, OdohPendingRequest, OdohPeerProvenance,
        OdohDurableFloor, OdohNetworkBinding, OdohProxyAdmission, OdohRequesterConfig,
        OdohRequesterRuntime, OdohRequesterStatus, OdohTargetCacheSnapshot,
    },
    runtime::{
        spawn_brontide_peer_runtime, spawn_peer_runtime, OutboundPriority, PeerEvent, PeerHandle,
        PeerId, PeerRuntimeConfig, PeerRuntimeParameters, PeerSnapshot,
    },
    wire::{NetAddress, NetworkMagic, Packet, VersionPacket},
    P2pError,
};

#[derive(Clone, Debug)]
pub enum PeerTransport {
    Plaintext,
    Brontide(BrontideIdentity),
}

#[derive(Clone, Debug)]
pub struct LivePeerConfig {
    pub network: Network,
    pub transport: PeerTransport,
    pub maximum_inbound: usize,
    pub maximum_outbound: usize,
    pub event_capacity: usize,
    pub connect_timeout: Duration,
    pub critical_broadcast_timeout: Duration,
    pub ban_score: u32,
    pub ban_time: Duration,
    pub protocol_version: u32,
    pub services: u64,
    pub user_agent: String,
    pub no_relay: bool,
    pub runtime: PeerRuntimeConfig,
    pub hip76: Hip76SessionConfig,
    pub odoh: OdohRequesterConfig,
    /// Canonical target-cache snapshot loaded before peer startup. Live
    /// proxy sessions and in-flight HPKE state are never accepted here.
    pub odoh_target_cache: Option<Vec<u8>>,
    /// Independently checksummed minimum generations and trusted-time
    /// high-water loaded alongside the cache. A cache without its durable
    /// floor (or a floor without its cache) is never restored.
    pub odoh_durable_floor: Option<Vec<u8>>,
}

impl LivePeerConfig {
    pub fn for_network(network: Network) -> Self {
        let transport = match network {
            // Public HSD networks expose authenticated Brontide peers. Never
            // silently fall back to the legacy plaintext port on mainnet.
            Network::Mainnet | Network::Testnet => {
                PeerTransport::Brontide(BrontideIdentity::generate())
            }
            Network::Regtest | Network::Simnet => PeerTransport::Plaintext,
        };
        let mut odoh = OdohRequesterConfig::default();
        odoh.allow_private_targets = matches!(network, Network::Regtest | Network::Simnet);
        Self {
            network,
            transport,
            maximum_inbound: 32,
            maximum_outbound: 8,
            event_capacity: 1_024,
            connect_timeout: Duration::from_secs(10),
            critical_broadcast_timeout: Duration::from_millis(250),
            ban_score: 100,
            ban_time: Duration::from_secs(24 * 60 * 60),
            protocol_version: PROTOCOL_VERSION,
            services: SERVICE_NETWORK | DENUO_EXTENSION_SERVICE.value(),
            user_agent: DEFAULT_USER_AGENT.to_owned(),
            no_relay: false,
            runtime: PeerRuntimeConfig::default(),
            hip76: Hip76SessionConfig::default(),
            odoh,
            odoh_target_cache: None,
            odoh_durable_floor: None,
        }
    }

    pub fn validate(&self) -> Result<(), P2pError> {
        if self.maximum_inbound == 0 && self.maximum_outbound == 0 {
            return Err(P2pError::Configuration(
                "at least one inbound or outbound peer slot is required".to_owned(),
            ));
        }
        if self.event_capacity == 0 {
            return Err(P2pError::Configuration(
                "peer event capacity must be non-zero".to_owned(),
            ));
        }
        if self.connect_timeout.is_zero() || self.critical_broadcast_timeout.is_zero() {
            return Err(P2pError::Configuration(
                "connect and critical broadcast timeouts must be non-zero".to_owned(),
            ));
        }
        if self.ban_time.as_secs() == 0 {
            return Err(P2pError::Configuration(
                "peer ban time must be at least one second".to_owned(),
            ));
        }
        if self.ban_score == 0 || self.ban_score > i32::MAX as u32 {
            return Err(P2pError::Configuration(
                "peer ban score must be within 1..=i32::MAX".to_owned(),
            ));
        }
        if self.user_agent.len() > u8::MAX as usize || !self.user_agent.is_ascii() {
            return Err(P2pError::Configuration(
                "user agent must be ASCII and fit in one byte".to_owned(),
            ));
        }
        if matches!(self.network, Network::Mainnet | Network::Testnet)
            && !matches!(self.transport, PeerTransport::Brontide(_))
        {
            return Err(P2pError::Configuration(
                "mainnet and testnet peer transport must use authenticated Brontide".to_owned(),
            ));
        }
        self.hip76
            .validate()
            .map_err(|error| P2pError::Configuration(error.to_string()))?;
        self.odoh
            .validate()
            .map_err(|error| P2pError::Configuration(error.to_string()))?;
        if self.odoh.allow_private_targets
            && !matches!(self.network, Network::Regtest | Network::Simnet)
        {
            return Err(P2pError::Configuration(
                "private ODoH targets are restricted to regtest and simnet".to_owned(),
            ));
        }
        self.runtime.validate()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct BroadcastReport {
    pub attempted: usize,
    /// Generic broadcasts count queue admissions. The critical broadcast
    /// methods count packets whose peer writer completed the socket write.
    pub queued: usize,
    pub failed: Vec<(PeerId, String)>,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PeerTrafficTotals {
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerBan {
    pub address: IpAddr,
    pub banned_at: u64,
    pub ban_until: u64,
    pub score: i32,
}

#[derive(Clone, Debug)]
pub struct LivePeerManager {
    config: LivePeerConfig,
    peers: Arc<RwLock<HashMap<PeerId, PeerHandle>>>,
    events: mpsc::Sender<PeerEvent>,
    next_peer_id: Arc<AtomicU64>,
    local_height: Arc<AtomicU32>,
    retired_bytes_sent: Arc<AtomicU64>,
    retired_bytes_received: Arc<AtomicU64>,
    denuo_metrics: DenuoRuntimeMetrics,
    odoh: Arc<Mutex<OdohRequesterRuntime>>,
    local_nonce: [u8; 8],
    registration_lock: Arc<Mutex<()>>,
    banned: Arc<RwLock<HashMap<IpAddr, u64>>>,
    pending_bans: Arc<Mutex<Vec<PeerBan>>>,
}

impl LivePeerManager {
    pub fn new(config: LivePeerConfig) -> Result<(Self, mpsc::Receiver<PeerEvent>), P2pError> {
        config.validate()?;
        let (events, receiver) = mpsc::channel(config.event_capacity);
        let seed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        let first_odoh_request_id = rand::random::<u64>().max(1);
        let binding = OdohNetworkBinding::for_network(config.network);
        let trusted_now = unix_time();
        let odoh = match (
            config.odoh_target_cache.as_deref(),
            config.odoh_durable_floor.as_deref(),
        ) {
            (Some(snapshot), Some(encoded_floor)) =>
                OdohDurableFloor::decode(encoded_floor, binding.magic).and_then(|floor| {
                    OdohRequesterRuntime::restore(
                        binding,
                        config.odoh,
                        first_odoh_request_id,
                        snapshot,
                        floor,
                        trusted_now,
                    )
                }),
            (None, None) => OdohRequesterRuntime::new(
                binding,
                config.odoh,
                first_odoh_request_id,
                trusted_now,
            ),
            _ => Err(crate::OdohCacheError::InvalidDurableFloor),
        }
        .map_err(|error| P2pError::Configuration(format!(
            "ODoH requester initialization failed: {error}"
        )))?;
        Ok((
            Self {
                config,
                peers: Arc::new(RwLock::new(HashMap::new())),
                events,
                next_peer_id: Arc::new(AtomicU64::new(1)),
                local_height: Arc::new(AtomicU32::new(0)),
                retired_bytes_sent: Arc::new(AtomicU64::new(0)),
                retired_bytes_received: Arc::new(AtomicU64::new(0)),
                denuo_metrics: DenuoRuntimeMetrics::default(),
                odoh: Arc::new(Mutex::new(odoh)),
                // Use one unpredictable process-local nonce across all live
                // connections. A loopback outbound/inbound pair will therefore
                // observe its own nonce and fail the VERSION handshake.
                local_nonce: seed.rotate_left(23).to_le_bytes(),
                registration_lock: Arc::new(Mutex::new(())),
                banned: Arc::new(RwLock::new(HashMap::new())),
                pending_bans: Arc::new(Mutex::new(Vec::new())),
            },
            receiver,
        ))
    }

    pub fn config(&self) -> &LivePeerConfig {
        &self.config
    }

    pub fn set_local_height(&self, height: u32) {
        self.local_height.store(height, Ordering::Release);
    }

    pub async fn replace_bans(&self, bans: Vec<(IpAddr, u64)>) {
        let _registration = self.registration_lock.lock().await;
        let now = unix_time();
        let mut state = self.banned.write().await;
        state.clear();
        state.extend(bans.into_iter().filter_map(|(address, ban_until)| {
            (now <= ban_until).then_some((normalize_peer_ip(address), ban_until))
        }));
        let active = state.keys().copied().collect::<Vec<_>>();
        drop(state);
        self.disconnect_ips(&active).await;
    }

    pub async fn is_banned(&self, address: IpAddr) -> bool {
        let address = normalize_peer_ip(address);
        let now = unix_time();
        let mut banned = self.banned.write().await;
        let Some(ban_until) = banned.get(&address).copied() else {
            return false;
        };
        if now > ban_until {
            banned.remove(&address);
            return false;
        }
        true
    }

    pub async fn take_pending_bans(&self) -> Vec<PeerBan> {
        std::mem::take(&mut *self.pending_bans.lock().await)
    }

    pub async fn connect(&self, address: SocketAddr) -> Result<PeerId, P2pError> {
        if matches!(self.config.transport, PeerTransport::Brontide(_)) {
            return Err(P2pError::Configuration(
                "Brontide outbound connections require a NetAddress with an authenticated remote static key"
                    .to_owned(),
            ));
        }
        self.ensure_capacity(PeerDirection::Outbound, address)
            .await?;
        let stream = tokio::time::timeout(self.config.connect_timeout, TcpStream::connect(address))
            .await
            .map_err(|_| P2pError::Timeout(format!("connection to {address} timed out")))??;
        stream.set_nodelay(true)?;
        self.register_stream(stream, address, PeerDirection::Outbound, None)
            .await
    }

    /// Connect to a key-bearing HSD network address. On Brontide networks the
    /// advertised static key authenticates the remote endpoint; plaintext mode
    /// accepts the socket portion for local development compatibility.
    pub async fn connect_net_address(&self, peer: &NetAddress) -> Result<PeerId, P2pError> {
        let address = peer.socket_addr().ok_or_else(|| {
            P2pError::Configuration("peer network address is not an IP endpoint".to_owned())
        })?;
        match &self.config.transport {
            PeerTransport::Plaintext => self.connect(address).await,
            PeerTransport::Brontide(identity) => {
                self.ensure_capacity(PeerDirection::Outbound, address)
                    .await?;
                if !matches!(peer.key[0], 0x02 | 0x03) {
                    return Err(P2pError::Configuration(format!(
                        "Brontide peer {address} has no valid compressed static key"
                    )));
                }
                let mut stream =
                    tokio::time::timeout(self.config.connect_timeout, TcpStream::connect(address))
                        .await
                        .map_err(|_| {
                            P2pError::Timeout(format!("connection to {address} timed out"))
                        })??;
                stream.set_nodelay(true)?;
                let session = tokio::time::timeout(
                    self.config.runtime.handshake_timeout,
                    outbound_handshake(&mut stream, identity, peer.key),
                )
                .await
                .map_err(|_| {
                    P2pError::Timeout(format!("Brontide handshake with {address} timed out"))
                })??;
                self.register_stream(stream, address, PeerDirection::Outbound, Some(session))
                    .await
            }
        }
    }

    pub async fn accept_stream(
        &self,
        mut stream: TcpStream,
        address: SocketAddr,
    ) -> Result<PeerId, P2pError> {
        self.ensure_capacity(PeerDirection::Inbound, address)
            .await?;
        stream.set_nodelay(true)?;
        let session = match &self.config.transport {
            PeerTransport::Plaintext => None,
            PeerTransport::Brontide(identity) => Some(
                tokio::time::timeout(
                    self.config.runtime.handshake_timeout,
                    inbound_handshake(&mut stream, identity),
                )
                .await
                .map_err(|_| {
                    P2pError::Timeout(format!(
                        "inbound Brontide handshake with {address} timed out"
                    ))
                })??,
            ),
        };
        self.register_stream(stream, address, PeerDirection::Inbound, session)
            .await
    }

    pub async fn serve_listener<F>(
        &self,
        listener: TcpListener,
        shutdown: F,
    ) -> Result<(), P2pError>
    where
        F: Future<Output = ()> + Send,
    {
        tokio::pin!(shutdown);
        loop {
            tokio::select! {
                _ = &mut shutdown => return Ok(()),
                accepted = listener.accept() => {
                    let (stream, address) = accepted?;
                    if let Err(error) = self.accept_stream(stream, address).await {
                        let _ = self.events.send(PeerEvent::InboundRejected {
                            address,
                            reason: error.to_string(),
                        }).await;
                    }
                }
            }
        }
    }

    pub async fn connect_all(
        &self,
        addresses: &[SocketAddr],
    ) -> Vec<(SocketAddr, Result<PeerId, String>)> {
        let mut results = Vec::with_capacity(addresses.len());
        for address in addresses {
            let result = self
                .connect(*address)
                .await
                .map_err(|error| error.to_string());
            results.push((*address, result));
        }
        results
    }

    pub async fn snapshots(&self) -> Vec<PeerSnapshot> {
        let handles = self
            .peers
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut snapshots = Vec::with_capacity(handles.len());
        for handle in handles {
            snapshots.push(handle.snapshot().await);
        }
        snapshots.sort_by_key(|snapshot| snapshot.id.0);
        snapshots
    }

    pub async fn denuo_summary(&self) -> DenuoSummary {
        self.snapshots_with_denuo_summary().await.1
    }

    /// Aggregate qname-free HIP-76 state across the currently live peer map.
    /// Session counters leave this summary when their peer disconnects.
    pub async fn hip76_summary(&self) -> Hip76Summary {
        let mut summary = Hip76Summary::default();
        for snapshot in self.snapshots().await {
            summary.observe(&snapshot.hip76);
        }
        summary
    }

    pub async fn snapshots_with_denuo_summary(&self) -> (Vec<PeerSnapshot>, DenuoSummary) {
        let snapshots = self.snapshots().await;
        let diagnostics = snapshots
            .iter()
            .map(|snapshot| snapshot.denuo.clone())
            .collect::<Vec<_>>();
        let summary = self
            .denuo_metrics
            .summary(self.config.services, &diagnostics);
        (snapshots, summary)
    }

    /// Return process-lifetime traffic counters without losing completed peer
    /// sessions. The peer-map read lock makes the handoff from a final live
    /// snapshot to the retired counters atomic to this observation.
    pub async fn traffic_totals(&self) -> PeerTrafficTotals {
        let handles = self.peers.read().await;
        let mut totals = PeerTrafficTotals {
            bytes_sent: self.retired_bytes_sent.load(Ordering::Acquire),
            bytes_received: self.retired_bytes_received.load(Ordering::Acquire),
        };
        for handle in handles.values() {
            let snapshot = handle.snapshot().await;
            totals.bytes_sent = totals.bytes_sent.saturating_add(snapshot.bytes_sent);
            totals.bytes_received = totals
                .bytes_received
                .saturating_add(snapshot.bytes_received);
        }
        totals
    }

    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }

    pub async fn ready_peer_count(&self) -> usize {
        self.snapshots()
            .await
            .into_iter()
            .filter(|peer| peer.state == PeerState::Ready)
            .count()
    }

    pub async fn try_send(
        &self,
        peer: PeerId,
        packet: Arc<Packet>,
        priority: OutboundPriority,
    ) -> Result<(), P2pError> {
        let handle = self
            .peers
            .read()
            .await
            .get(&peer)
            .cloned()
            .ok_or(P2pError::PeerUnavailable(peer))?;
        handle.try_send(packet, priority)
    }

    pub async fn begin_hip76_request(
        &self,
        peer: PeerId,
        query: Vec<u8>,
    ) -> Result<crate::Hip76PendingRequest, P2pError> {
        let handle = self
            .peers
            .read()
            .await
            .get(&peer)
            .cloned()
            .ok_or(P2pError::PeerUnavailable(peer))?;
        handle.begin_hip76_request(query).await
    }

    /// Install one target-signed HIP-77 configuration in the restart-safe
    /// anti-rollback cache. The record is public metadata; no HPKE context or
    /// live peer authority is persisted with it.
    pub async fn install_odoh_target(
        &self,
        locator: DirectTargetLocator,
        signed_record: &[u8],
        configuration_index: usize,
    ) -> Result<[u8; 32], P2pError> {
        self.odoh
            .lock()
            .await
            .install_target(locator, signed_record, configuration_index, unix_time())
            .map_err(|error| P2pError::Configuration(format!(
                "ODoH target record rejected: {error}"
            )))
    }

    /// Begin one HPKE-sealed query through a distinct authenticated proxy.
    /// The returned response bytes remain untrusted DNS input for the caller's
    /// parser and DNSSEC validation path.
    pub async fn begin_odoh_request(
        &self,
        target_record_id: [u8; 32],
        query: Vec<u8>,
    ) -> Result<OdohPendingRequest, P2pError> {
        let candidates = self.odoh_candidates().await;
        let mut runtime = self.odoh.lock().await;
        let now_unix = unix_time();
        let target_key = runtime
            .target_peer_key(target_record_id, now_unix)
            .map_err(|reason| P2pError::Odoh {
                peer: PeerId(0),
                reason,
            })?;
        let proxy = candidates
            .into_iter()
            .find(|candidate| {
                candidate.provenance.authenticated_remote_static != Some(target_key)
                    && !runtime.proxy_faulted(candidate.provenance.peer)
            })
            .ok_or(P2pError::Odoh {
                peer: PeerId(0),
                reason: OdohFailureReason::UnauthenticatedProxy,
            })?;
        self.send_odoh_locked(
            &mut runtime,
            proxy,
            |runtime, proxy, now| {
                runtime.begin_query(proxy, target_record_id, query, now_unix, now)
            },
        )
        .await
    }

    /// Request one target-signed configuration from an authenticated ODoH
    /// peer. A successful response is verified and installed atomically in
    /// the same anti-rollback cache used by direct installation.
    pub async fn begin_odoh_configuration_request(
        &self,
        locator: DirectTargetLocator,
        configuration_index: usize,
    ) -> Result<OdohPendingRequest, P2pError> {
        let candidates = self.odoh_candidates().await;
        let mut runtime = self.odoh.lock().await;
        let now_unix = unix_time();
        let target_key = crate::AuthenticatedPeerKey::new(locator.target_peer_key);
        let proxy = candidates
            .into_iter()
            .find(|candidate| {
                candidate.provenance.authenticated_remote_static != Some(target_key)
                    && !runtime.proxy_faulted(candidate.provenance.peer)
            })
            .ok_or(P2pError::Odoh {
                peer: PeerId(0),
                reason: OdohFailureReason::UnauthenticatedProxy,
            })?;
        self.send_odoh_locked(
            &mut runtime,
            proxy,
            |runtime, proxy, now| {
                runtime.begin_configuration(
                    proxy,
                    locator,
                    configuration_index,
                    now_unix,
                    now,
                )
            },
        )
        .await
    }

    async fn send_odoh_locked(
        &self,
        runtime: &mut OdohRequesterRuntime,
        proxy: OdohProxyAdmission,
        prepare: impl FnOnce(
            &mut OdohRequesterRuntime,
            OdohProxyAdmission,
            tokio::time::Instant,
        ) -> Result<crate::odoh::PreparedOdohRequest, OdohFailureReason>,
    ) -> Result<OdohPendingRequest, P2pError> {
        let peer = proxy.provenance.peer;
        let handle = self
            .peers
            .read()
            .await
            .get(&peer)
            .cloned()
            .ok_or(P2pError::PeerUnavailable(peer))?;
        let prepared = prepare(runtime, proxy, tokio::time::Instant::now())
            .map_err(|reason| P2pError::Odoh { peer, reason })?;
        let request_id = prepared.request_id;
        let generation = prepared.generation;
        let deadline = prepared.deadline;
        match handle
            .send_critical(
                Arc::new(prepared.packet),
                self.config.critical_broadcast_timeout,
            )
            .await
        {
            Ok(()) => runtime.socket_written(request_id, generation),
            Err(error) => {
                runtime.socket_failed(request_id, generation);
                // A timed-out socket acknowledgement can mean the writer was
                // already inside a partial frame write. Retire the exact
                // connection so no later bytes or response can be mistaken
                // for live requester work after the state lock is released.
                handle.disconnect();
                return Err(error);
            }
        }
        let pending = prepared.pending;
        let runtime = Arc::clone(&self.odoh);
        tokio::spawn(async move {
            tokio::time::sleep_until(deadline).await;
            runtime.lock().await.expire(tokio::time::Instant::now());
        });
        Ok(pending)
    }

    pub async fn odoh_status(&self, now: u64) -> OdohRequesterStatus {
        let candidates = self.odoh_candidates().await;
        let mut runtime = self.odoh.lock().await;
        let eligible = candidates
            .iter()
            .filter(|candidate| !runtime.proxy_faulted(candidate.provenance.peer))
            .count();
        runtime.status(now, eligible)
    }

    pub async fn odoh_target_cache_snapshot(
        &self,
        now: u64,
    ) -> Result<OdohTargetCacheSnapshot, P2pError> {
        self.odoh
            .lock()
            .await
            .target_cache_snapshot(now)
            .map_err(|error| P2pError::State(format!(
                "ODoH target-cache snapshot failed: {error}"
            )))
    }

    pub async fn acknowledge_odoh_target_cache_persisted(&self, floor: OdohDurableFloor) {
        self.odoh
            .lock()
            .await
            .acknowledge_target_cache_persisted(floor);
    }

    pub async fn replace_odoh_requester_policy(
        &self,
        enabled: bool,
        generation: u64,
    ) -> Result<usize, P2pError> {
        self.odoh
            .lock()
            .await
            .replace_enabled(enabled, generation)
            .map_err(|reason| P2pError::Odoh {
                peer: PeerId(0),
                reason,
            })
    }

    pub async fn revoke_odoh_requester(&self, generation: u64) -> Result<usize, P2pError> {
        self.odoh
            .lock()
            .await
            .revoke(generation)
            .map_err(|reason| P2pError::Odoh {
                peer: PeerId(0),
                reason,
            })
    }

    async fn odoh_candidates(&self) -> Vec<OdohProxyAdmission> {
        let mut candidates = self
            .snapshots()
            .await
            .into_iter()
            .filter_map(|snapshot| {
                let wire_profile = snapshot.denuo_wire_profile?;
                let negotiated = snapshot.denuo_negotiated_registry?;
                (snapshot.state == PeerState::Ready
                    && snapshot.transport == crate::PeerTransportKind::Brontide
                    && snapshot.authenticated_remote_static.is_some()
                    && snapshot.services & DENUO_EXTENSION_SERVICE.value() != 0
                    && snapshot.services & hns_p2p_experimental::ODOH_SERVICE.value() != 0
                    && snapshot.denuo.phase == crate::DenuoPeerPhase::Negotiated
                    && wire_profile == hns_p2p_experimental::ExperimentalWireProfile::DenuoV1)
                    .then_some(OdohProxyAdmission {
                        provenance: OdohPeerProvenance {
                            peer: snapshot.id,
                            address: snapshot.address,
                            direction: snapshot.direction,
                            transport: snapshot.transport,
                            authenticated_remote_static: snapshot.authenticated_remote_static,
                        },
                        remote_services: snapshot.services,
                        wire_profile,
                        negotiated,
                    })
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|candidate| {
            (
                candidate.provenance.direction != PeerDirection::Outbound,
                candidate.provenance.peer.0,
            )
        });
        candidates
    }

    pub async fn finish_hip76_provider_request(
        &self,
        peer: PeerId,
        work: crate::Hip76ProviderWork,
        status: crate::DnsRelayStatus,
        response: Vec<u8>,
    ) -> Result<(), P2pError> {
        let handle = self
            .peers
            .read()
            .await
            .get(&peer)
            .cloned()
            .ok_or(P2pError::PeerUnavailable(peer))?;
        handle
            .finish_hip76_provider_request(work, status, response)
            .await
    }

    pub async fn subscribe_peer_hip76(
        &self,
        peer: PeerId,
    ) -> Result<tokio::sync::watch::Receiver<crate::Hip76SessionDiagnostics>, P2pError> {
        let handle = self
            .peers
            .read()
            .await
            .get(&peer)
            .cloned()
            .ok_or(P2pError::PeerUnavailable(peer))?;
        Ok(handle.subscribe_hip76())
    }

    /// Replace a connected peer's HIP-76 policy generation. Provider changes
    /// that alter VERSION advertisement require a reconnect and are rejected
    /// here so the service mask can never drift from live admission.
    pub async fn replace_peer_hip76_policy(
        &self,
        peer: PeerId,
        requester: crate::DnsRelayRequesterPolicy,
        provider: Hip76ProviderPolicy,
        generation: u64,
    ) -> Result<crate::Hip76RevokedWork, P2pError> {
        let current_services =
            hip76_advertised_services(self.config.services, self.config.hip76.provider_policy);
        let next_services = hip76_advertised_services(self.config.services, provider);
        if current_services != next_services {
            return Err(P2pError::Configuration(
                "HIP-76 provider advertisement changes require reconnecting the peer".to_owned(),
            ));
        }
        let handle = self
            .peers
            .read()
            .await
            .get(&peer)
            .cloned()
            .ok_or(P2pError::PeerUnavailable(peer))?;
        handle
            .replace_hip76_policy(requester, provider, generation)
            .await
    }

    pub async fn revoke_peer_hip76(
        &self,
        peer: PeerId,
        generation: u64,
    ) -> Result<crate::Hip76RevokedWork, P2pError> {
        let handle = self
            .peers
            .read()
            .await
            .get(&peer)
            .cloned()
            .ok_or(P2pError::PeerUnavailable(peer))?;
        let revoked = handle.revoke_hip76(generation).await?;
        if self.config.hip76.provider_policy.is_available() {
            // VERSION service bits are immutable for a connected peer.
            handle.disconnect();
        }
        Ok(revoked)
    }

    pub async fn broadcast(
        &self,
        packet: Arc<Packet>,
        priority: OutboundPriority,
    ) -> BroadcastReport {
        let handles = self.ready_handles().await;
        let mut report = BroadcastReport {
            attempted: handles.len(),
            ..BroadcastReport::default()
        };
        for handle in handles {
            match handle.try_send(Arc::clone(&packet), priority) {
                Ok(()) => report.queued += 1,
                Err(error) => report.failed.push((handle.id(), error.to_string())),
            }
        }
        report
    }

    pub async fn broadcast_critical(&self, packet: Arc<Packet>) -> BroadcastReport {
        let handles = self.ready_handles().await;
        let mut report = BroadcastReport {
            attempted: handles.len(),
            ..BroadcastReport::default()
        };
        for handle in handles {
            match handle
                .send_critical(Arc::clone(&packet), self.config.critical_broadcast_timeout)
                .await
            {
                Ok(()) => report.queued += 1,
                Err(error) => report.failed.push((handle.id(), error.to_string())),
            }
        }
        report
    }

    /// Write a solved block or equivalent latency-critical packet through
    /// every ready peer concurrently. Each task waits for its peer writer to
    /// complete the socket write; slow or congested peers are isolated by the
    /// per-peer critical timeout and cannot serialize fan-out to healthy peers.
    pub async fn broadcast_critical_parallel(&self, packet: Arc<Packet>) -> BroadcastReport {
        let handles = self.ready_handles().await;
        let mut report = BroadcastReport {
            attempted: handles.len(),
            ..BroadcastReport::default()
        };
        let mut tasks = JoinSet::new();
        for handle in handles {
            let peer = handle.id();
            let packet = Arc::clone(&packet);
            let timeout = self.config.critical_broadcast_timeout;
            tasks.spawn(async move { (peer, handle.send_critical(packet, timeout).await) });
        }
        while let Some(result) = tasks.join_next().await {
            match result {
                Ok((_peer, Ok(()))) => report.queued += 1,
                Ok((peer, Err(error))) => report.failed.push((peer, error.to_string())),
                Err(error) => report
                    .failed
                    .push((PeerId(0), format!("critical fan-out task failed: {error}"))),
            }
        }
        report
    }

    async fn ready_handles(&self) -> Vec<PeerHandle> {
        let handles = self
            .peers
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let mut ready = Vec::with_capacity(handles.len());
        for handle in handles {
            if handle.snapshot().await.state == PeerState::Ready {
                ready.push(handle);
            }
        }
        ready
    }

    pub async fn penalize(&self, peer: PeerId, score: u32) -> Result<i32, P2pError> {
        let handle = self
            .peers
            .read()
            .await
            .get(&peer)
            .cloned()
            .ok_or(P2pError::PeerUnavailable(peer))?;
        let delta = i32::try_from(score).unwrap_or(i32::MAX);
        let mut snapshot = handle.snapshot.write().await;
        let previous = snapshot.score;
        snapshot.score = snapshot.score.saturating_add(delta);
        let total = snapshot.score;
        let address = normalize_peer_ip(snapshot.address.ip());
        drop(snapshot);

        let threshold = i32::try_from(self.config.ban_score).unwrap_or(i32::MAX);
        if previous < threshold && total >= threshold {
            // Serialize installation with final stream registration. A racing
            // stream is therefore either rejected by `ensure_capacity` or is
            // present when the IP-wide disconnect snapshot is taken.
            let _registration = self.registration_lock.lock().await;
            let banned_at = unix_time();
            let ban_until = banned_at.saturating_add(self.config.ban_time.as_secs());
            self.banned.write().await.insert(address, ban_until);
            self.pending_bans.lock().await.push(PeerBan {
                address,
                banned_at,
                ban_until,
                score: total,
            });
            self.disconnect_ips(&[address]).await;
        }
        Ok(total)
    }

    async fn disconnect_ips(&self, addresses: &[IpAddr]) {
        if addresses.is_empty() {
            return;
        }
        let handles = self
            .peers
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for handle in handles {
            let address = normalize_peer_ip(handle.snapshot().await.address.ip());
            if addresses.contains(&address) {
                handle.disconnect();
            }
        }
    }

    pub async fn disconnect(&self, peer: PeerId) -> Result<(), P2pError> {
        let handle = self
            .peers
            .read()
            .await
            .get(&peer)
            .cloned()
            .ok_or(P2pError::PeerUnavailable(peer))?;
        handle.disconnect();
        Ok(())
    }

    pub async fn disconnect_all(&self) {
        let handles = self
            .peers
            .read()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for handle in handles {
            handle.disconnect();
        }
    }

    async fn ensure_capacity(
        &self,
        direction: PeerDirection,
        address: SocketAddr,
    ) -> Result<(), P2pError> {
        let ip = normalize_peer_ip(address.ip());
        let now = unix_time();
        let mut banned = self.banned.write().await;
        if let Some(ban_until) = banned.get(&ip).copied() {
            if now <= ban_until {
                return Err(P2pError::BannedAddress {
                    address: ip,
                    ban_until,
                });
            }
            banned.remove(&ip);
        }
        drop(banned);
        let snapshots = self.snapshots().await;
        if snapshots.iter().any(|peer| peer.address == address) {
            return Err(P2pError::DuplicatePeer(address));
        }
        let count = snapshots
            .iter()
            .filter(|peer| peer.direction == direction)
            .count();
        let limit = match direction {
            PeerDirection::Inbound => self.config.maximum_inbound,
            PeerDirection::Outbound => self.config.maximum_outbound,
        };
        if count >= limit {
            return Err(P2pError::PeerLimit { direction, limit });
        }
        Ok(())
    }

    async fn register_stream(
        &self,
        stream: TcpStream,
        address: SocketAddr,
        direction: PeerDirection,
        brontide: Option<BrontideSession>,
    ) -> Result<PeerId, P2pError> {
        let _registration = self.registration_lock.lock().await;
        self.ensure_capacity(direction, address).await?;
        let id = PeerId(self.next_peer_id.fetch_add(1, Ordering::Relaxed));
        let nonce = self.local_nonce;
        let services =
            hip76_advertised_services(self.config.services, self.config.hip76.provider_policy);
        let local_version = VersionPacket {
            version: self.config.protocol_version,
            services,
            time: unix_time(),
            remote: NetAddress::from_socket_addr(address, unix_time(), services),
            nonce,
            agent: self.config.user_agent.clone(),
            height: self.local_height.load(Ordering::Acquire),
            no_relay: self.config.no_relay,
        };
        let magic = NetworkMagic::from(self.config.network);
        let (reader, writer) = stream.into_split();
        let parameters = PeerRuntimeParameters {
            id,
            address,
            direction,
            network: self.config.network,
            magic,
            local_version,
            config: self.config.runtime.clone(),
            events: self.events.clone(),
            denuo_metrics: self.denuo_metrics.clone(),
            hip76_config: self.config.hip76.clone(),
            odoh: Arc::clone(&self.odoh),
        };
        let spawned = match brontide {
            Some(session) => spawn_brontide_peer_runtime(parameters, reader, writer, session)?,
            None => spawn_peer_runtime(parameters, reader, writer)?,
        };
        self.peers.write().await.insert(id, spawned.handle.clone());

        let peers = Arc::clone(&self.peers);
        let events = self.events.clone();
        let retired_bytes_sent = Arc::clone(&self.retired_bytes_sent);
        let retired_bytes_received = Arc::clone(&self.retired_bytes_received);
        let handle = spawned.handle.clone();
        let task = spawned.task;
        tokio::spawn(async move {
            let reason = match task.await {
                Ok(Ok(())) => "peer task completed".to_owned(),
                Ok(Err(error)) => error.to_string(),
                Err(error) => format!("peer task join failed: {error}"),
            };
            let final_snapshot = handle.snapshot().await;
            let mut active_peers = peers.write().await;
            if active_peers.remove(&id).is_some() {
                atomic_saturating_add(&retired_bytes_sent, final_snapshot.bytes_sent);
                atomic_saturating_add(&retired_bytes_received, final_snapshot.bytes_received);
            }
            drop(active_peers);
            let _ = events
                .send(PeerEvent::Disconnected {
                    peer: id,
                    address,
                    direction,
                    reason,
                })
                .await;
        });
        Ok(id)
    }
}

fn atomic_saturating_add(counter: &AtomicU64, value: u64) {
    let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
        Some(current.saturating_add(value))
    });
}

pub fn normalize_peer_ip(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        address => address,
    }
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        denuo::DenuoPeerPhase,
        handshake::PeerState,
        runtime::{Hip76RequestOutcome, PeerTransportKind},
        wire::Packet,
        DnsRelayRequesterPolicy, DnsRelayStatus, Hip76ConnectionPhase,
    };
    use hns_p2p_experimental::{
        DENUO_EXTENSION_MAX_NESTED_PAYLOAD, DENUO_EXTENSION_MAX_PACKET_PAYLOAD, DNS_RELAY_SERVICE,
        REGISTRY_NEGOTIATION_MAX_PAYLOAD,
    };

    const LIVE_EVENT_TIMEOUT: Duration = Duration::from_secs(5);

    fn strict_nonrecursive_dnssec_query(transaction_id: u16) -> Vec<u8> {
        let mut query = Vec::new();
        query.extend_from_slice(&transaction_id.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes()); // QR=0, RD=0.
        query.extend_from_slice(&1_u16.to_be_bytes()); // One question.
        query.extend_from_slice(&0_u16.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes()); // One EDNS OPT.
        for label in ["hip76", "integration"] {
            query.push(u8::try_from(label.len()).expect("test label length"));
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&48_u16.to_be_bytes()); // DNSKEY.
        query.extend_from_slice(&1_u16.to_be_bytes()); // IN.
        query.push(0);
        query.extend_from_slice(&41_u16.to_be_bytes()); // OPT.
        query.extend_from_slice(&1232_u16.to_be_bytes());
        query.extend_from_slice(&0x0000_8000_u32.to_be_bytes()); // EDNS DO.
        query.extend_from_slice(&0_u16.to_be_bytes()); // No EDNS options, including ECS.
        query
    }

    fn correlated_dns_response(query: &[u8]) -> Vec<u8> {
        let mut question_end = 12;
        loop {
            let label_length = usize::from(query[question_end]);
            question_end += 1;
            if label_length == 0 {
                break;
            }
            question_end += label_length;
        }
        question_end += 4;
        let mut response = query[..question_end].to_vec();
        response[2..4].copy_from_slice(&0x8000_u16.to_be_bytes()); // QR=1, RD=0.
        response[6..12].fill(0);
        response
    }

    fn assert_not_generic_hip76(packet: &Packet) {
        assert!(
            !crate::is_hip76_packet_type(packet.packet_type()),
            "HIP-76 f0/f1 packet leaked through PeerEvent::Packet"
        );
    }

    async fn await_ready(
        events: &mut mpsc::Receiver<PeerEvent>,
        expected_peer: PeerId,
    ) -> VersionPacket {
        tokio::time::timeout(LIVE_EVENT_TIMEOUT, async {
            loop {
                match events.recv().await.expect("live peer event channel") {
                    PeerEvent::Ready { peer, version } if peer == expected_peer => break version,
                    PeerEvent::Packet { packet, .. } => assert_not_generic_hip76(&packet),
                    _ => {}
                }
            }
        })
        .await
        .expect("peer readiness event")
    }

    async fn await_hip76_capability(
        status: &mut tokio::sync::watch::Receiver<crate::Hip76SessionDiagnostics>,
        requester_eligible: bool,
        provider_available: bool,
    ) -> crate::Hip76SessionDiagnostics {
        tokio::time::timeout(LIVE_EVENT_TIMEOUT, async {
            loop {
                let diagnostics = status.borrow().clone();
                if diagnostics.phase == Hip76ConnectionPhase::Active
                    && diagnostics.registry_negotiated
                    && diagnostics.requester_eligible == requester_eligible
                    && diagnostics.provider_available == provider_available
                {
                    break diagnostics;
                }
                status.changed().await.expect("HIP-76 status sender");
            }
        })
        .await
        .expect("HIP-76 capability")
    }

    async fn await_ordinary_packet(
        events: &mut mpsc::Receiver<PeerEvent>,
        expected_peer: PeerId,
        expected_packet: Packet,
    ) {
        tokio::time::timeout(LIVE_EVENT_TIMEOUT, async {
            loop {
                if let PeerEvent::Packet { peer, packet } =
                    events.recv().await.expect("live peer event channel")
                {
                    assert_not_generic_hip76(&packet);
                    if peer == expected_peer && packet == expected_packet {
                        break;
                    }
                }
            }
        })
        .await
        .expect("ordinary packet after HIP-76 exchange");
    }

    #[tokio::test]
    async fn live_manager_connects_two_local_peers_and_completes_handshake() {
        let mut config = LivePeerConfig::for_network(Network::Regtest);
        config.maximum_inbound = 2;
        config.maximum_outbound = 2;
        config.runtime.ping_interval = Duration::from_secs(60);
        let (server_manager, mut server_events) =
            LivePeerManager::new(config.clone()).expect("server");
        let (client_manager, mut client_events) = LivePeerManager::new(config).expect("client");
        server_manager.set_local_height(10);
        client_manager.set_local_height(11);

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = {
            let manager = server_manager.clone();
            tokio::spawn(async move {
                let (stream, peer_address) = listener.accept().await.expect("accept");
                manager
                    .accept_stream(stream, peer_address)
                    .await
                    .expect("register")
            })
        };
        let client_peer = client_manager.connect(address).await.expect("connect");
        let server_peer = server.await.expect("join");

        let client_ready = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(PeerEvent::Ready { peer, .. }) = client_events.recv().await {
                    break peer;
                }
            }
        })
        .await
        .expect("client ready");
        let server_ready = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(PeerEvent::Ready { peer, .. }) = server_events.recv().await {
                    break peer;
                }
            }
        })
        .await
        .expect("server ready");
        assert_eq!(client_ready, client_peer);
        assert_eq!(server_ready, server_peer);
        assert_eq!(client_manager.snapshots().await[0].state, PeerState::Ready);
        assert_eq!(server_manager.snapshots().await[0].state, PeerState::Ready);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let client_phase = client_manager.snapshots().await[0].denuo.phase;
                let server_phase = server_manager.snapshots().await[0].denuo.phase;
                if client_phase == DenuoPeerPhase::Negotiated
                    && server_phase == DenuoPeerPhase::Negotiated
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("Denuo negotiation");
        let (client_snapshots, client_denuo) = client_manager.snapshots_with_denuo_summary().await;
        let (_, server_denuo) = server_manager.snapshots_with_denuo_summary().await;
        assert_eq!(client_snapshots.len(), 1);
        let negotiated = client_snapshots[0]
            .denuo
            .negotiated
            .as_ref()
            .expect("negotiated parameters");
        assert_eq!(negotiated.protocols.len(), 1);
        assert_eq!(negotiated.protocols[0].protocol_id, 0);
        assert_eq!(negotiated.protocols[0].protocol_version, 1);
        assert_eq!(negotiated.maximum_live_requests, 64);
        assert_eq!(negotiated.feature_flags, 0);
        assert_eq!(
            negotiated.maximum_send_size,
            DENUO_EXTENSION_MAX_PACKET_PAYLOAD as u32
        );
        assert!(client_denuo.advertised());
        assert_eq!(client_denuo.live.negotiated, 1);
        assert_eq!(client_denuo.process.hello_admitted, 1);
        assert_eq!(client_denuo.process.hello_ack_received, 1);
        assert_eq!(client_denuo.process.agreements_computed, 1);
        assert_eq!(server_denuo.live.negotiated, 1);
        assert_eq!(server_denuo.process.hello_received, 1);
        assert_eq!(server_denuo.process.hello_ack_admitted, 1);
        assert_eq!(server_denuo.process.agreements_computed, 1);
        assert_eq!(
            client_denuo.identity.maximum_packet_payload,
            DENUO_EXTENSION_MAX_PACKET_PAYLOAD as u32
        );
        assert_eq!(
            client_denuo.identity.maximum_nested_payload,
            DENUO_EXTENSION_MAX_NESTED_PAYLOAD as u32
        );
        assert_eq!(
            client_denuo.identity.maximum_registry_negotiation_payload,
            REGISTRY_NEGOTIATION_MAX_PAYLOAD as u32
        );

        client_manager
            .try_send(
                client_peer,
                Arc::new(Packet::GetAddr),
                OutboundPriority::Control,
            )
            .await
            .expect("send");
        let packet = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(PeerEvent::Packet { packet, .. }) = server_events.recv().await {
                    if packet == Packet::GetAddr {
                        break packet;
                    }
                    assert_eq!(packet, Packet::SendHeaders);
                }
            }
        })
        .await
        .expect("packet");
        assert_eq!(packet, Packet::GetAddr);
        let traffic_before_disconnect = client_manager.traffic_totals().await;
        assert!(traffic_before_disconnect.bytes_sent > 0);
        assert!(traffic_before_disconnect.bytes_received > 0);

        assert_eq!(
            client_manager
                .penalize(client_peer, 99)
                .await
                .expect("score"),
            99
        );
        assert!(client_manager.take_pending_bans().await.is_empty());
        assert!(!client_manager.is_banned(address.ip()).await);
        assert_eq!(
            client_manager.penalize(client_peer, 1).await.expect("ban"),
            100
        );
        let pending = client_manager.take_pending_bans().await;
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].address, address.ip());
        assert_eq!(pending[0].score, 100);
        assert_eq!(
            pending[0].ban_until.saturating_sub(pending[0].banned_at),
            24 * 60 * 60
        );
        assert!(client_manager.is_banned(address.ip()).await);
        let error = client_manager
            .connect(address)
            .await
            .expect_err("ban must reject before socket work");
        assert!(matches!(error, P2pError::BannedAddress { .. }));
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if matches!(
                    client_events.recv().await,
                    Some(PeerEvent::Disconnected { peer, .. }) if peer == client_peer
                ) {
                    break;
                }
            }
        })
        .await
        .expect("client disconnect");
        let traffic_after_disconnect = client_manager.traffic_totals().await;
        assert!(traffic_after_disconnect.bytes_sent >= traffic_before_disconnect.bytes_sent);
        assert!(
            traffic_after_disconnect.bytes_received >= traffic_before_disconnect.bytes_received
        );
        assert_eq!(client_manager.peer_count().await, 0);
        let retired_denuo = client_manager.denuo_summary().await;
        assert_eq!(retired_denuo.live.negotiated, 0);
        assert_eq!(retired_denuo.process.agreements_computed, 1);
        assert_eq!(retired_denuo.process.admitted(), 1);
        assert_eq!(retired_denuo.process.received(), 1);
        assert_eq!(retired_denuo.process.disabled, 0);
        client_manager.disconnect_all().await;
        server_manager.disconnect_all().await;
    }

    #[tokio::test]
    async fn live_managers_complete_hip76_request_without_leaking_private_packets() {
        let mut provider_config = LivePeerConfig::for_network(Network::Regtest);
        provider_config.runtime.ping_interval = Duration::from_secs(60);
        provider_config.hip76.provider_policy = Hip76ProviderPolicy::opted_in(true);
        assert!(matches!(
            provider_config.transport,
            PeerTransport::Plaintext
        ));
        assert!(provider_config.hip76.provider_policy.is_available());

        let mut requester_config = LivePeerConfig::for_network(Network::Regtest);
        requester_config.runtime.ping_interval = Duration::from_secs(60);
        assert!(matches!(
            requester_config.transport,
            PeerTransport::Plaintext
        ));
        assert!(!requester_config.hip76.provider_policy.is_opted_in());

        let (provider_manager, mut provider_events) =
            LivePeerManager::new(provider_config).expect("provider manager");
        let (requester_manager, mut requester_events) =
            LivePeerManager::new(requester_config).expect("requester manager");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let provider_address = listener.local_addr().expect("provider address");
        let provider_accept = {
            let manager = provider_manager.clone();
            tokio::spawn(async move {
                let (stream, requester_address) = listener.accept().await.expect("accept");
                manager
                    .accept_stream(stream, requester_address)
                    .await
                    .expect("register provider peer")
            })
        };
        let requester_peer = requester_manager
            .connect(provider_address)
            .await
            .expect("connect requester");
        let provider_peer = provider_accept.await.expect("provider accept task");

        let mut requester_hip76 = requester_manager
            .subscribe_peer_hip76(requester_peer)
            .await
            .expect("requester HIP-76 subscription");
        let mut provider_hip76 = provider_manager
            .subscribe_peer_hip76(provider_peer)
            .await
            .expect("provider HIP-76 subscription");

        let requester_remote_version = await_ready(&mut requester_events, requester_peer).await;
        let provider_remote_version = await_ready(&mut provider_events, provider_peer).await;
        assert_ne!(
            requester_remote_version.services & DNS_RELAY_SERVICE.value(),
            0,
            "the opted-in provider must advertise the DNS output service"
        );
        assert_eq!(
            provider_remote_version.services & DNS_RELAY_SERVICE.value(),
            0,
            "the default requester must not advertise the DNS output service"
        );

        let requester_diagnostics = await_hip76_capability(&mut requester_hip76, true, false).await;
        assert!(requester_diagnostics.remote_provider_advertised);
        assert!(!requester_diagnostics.local_provider_advertised);
        let provider_diagnostics = await_hip76_capability(&mut provider_hip76, false, true).await;
        assert!(provider_diagnostics.local_provider_advertised);
        assert!(!provider_diagnostics.remote_provider_advertised);

        let query = strict_nonrecursive_dnssec_query(0x76);
        assert_eq!(u16::from_be_bytes([query[2], query[3]]), 0);
        assert_eq!(
            u32::from_be_bytes([
                query[query.len() - 6],
                query[query.len() - 5],
                query[query.len() - 4],
                query[query.len() - 3],
            ]),
            0x0000_8000
        );
        let pending = requester_manager
            .begin_hip76_request(requester_peer, query.clone())
            .await
            .expect("admit requester request");
        let request_id = pending.admission.request_id;
        let generation = pending.admission.generation;
        assert_ne!(request_id, 0);
        assert!(pending.admission.deadline > tokio::time::Instant::now());

        let (provider_provenance, provider_request) =
            tokio::time::timeout(LIVE_EVENT_TIMEOUT, async {
                loop {
                    match provider_events
                        .recv()
                        .await
                        .expect("provider event channel")
                    {
                        PeerEvent::Hip76ProviderRequest {
                            provenance,
                            request,
                        } => break (provenance, request),
                        PeerEvent::Packet { packet, .. } => assert_not_generic_hip76(&packet),
                        _ => {}
                    }
                }
            })
            .await
            .expect("provider f0 admission event");
        assert_eq!(provider_provenance.peer, provider_peer);
        assert_eq!(provider_provenance.direction, PeerDirection::Inbound);
        assert_eq!(provider_provenance.transport, PeerTransportKind::Plaintext);
        assert_eq!(provider_provenance.authenticated_remote_static, None);
        assert_eq!(provider_request.request_id, request_id);
        assert_eq!(provider_request.generation, generation);
        assert_eq!(provider_request.query(), query);
        let (provider_work, provider_query) = provider_request.into_parts();
        assert_eq!(provider_work.request_id(), request_id);
        assert_eq!(provider_work.generation(), generation);
        assert_eq!(provider_query, query);

        let response = correlated_dns_response(&query);
        provider_manager
            .finish_hip76_provider_request(
                provider_peer,
                provider_work,
                DnsRelayStatus::Ok,
                response.clone(),
            )
            .await
            .expect("write correlated provider response");

        let outcome = tokio::time::timeout(LIVE_EVENT_TIMEOUT, pending.outcome())
            .await
            .expect("requester per-admission outcome")
            .expect("requester outcome channel");
        let Hip76RequestOutcome::Response {
            provenance,
            response: requester_response,
        } = outcome
        else {
            panic!("expected correlated HIP-76 response, got {outcome:?}");
        };
        assert_eq!(provenance.peer, requester_peer);
        assert_eq!(provenance.address, provider_address);
        assert_eq!(provenance.direction, PeerDirection::Outbound);
        assert_eq!(provenance.transport, PeerTransportKind::Plaintext);
        assert_eq!(provenance.authenticated_remote_static, None);
        let (response_id, response_generation, status, untrusted_response) =
            requester_response.into_parts();
        assert_eq!(response_id, request_id);
        assert_eq!(response_generation, generation);
        assert_eq!(status, DnsRelayStatus::Ok);
        assert_eq!(untrusted_response.as_bytes(), response);

        requester_manager
            .try_send(
                requester_peer,
                Arc::new(Packet::GetAddr),
                OutboundPriority::Control,
            )
            .await
            .expect("ordinary requester packet");
        await_ordinary_packet(&mut provider_events, provider_peer, Packet::GetAddr).await;
        provider_manager
            .try_send(
                provider_peer,
                Arc::new(Packet::GetAddr),
                OutboundPriority::Control,
            )
            .await
            .expect("ordinary provider packet");
        await_ordinary_packet(&mut requester_events, requester_peer, Packet::GetAddr).await;

        requester_manager
            .replace_peer_hip76_policy(
                requester_peer,
                DnsRelayRequesterPolicy::Disabled,
                Hip76ProviderPolicy::disabled(),
                generation + 1,
            )
            .await
            .expect("apply requester opt-out");
        let opted_out = await_hip76_capability(&mut requester_hip76, false, false).await;
        assert!(!opted_out.requester_enabled);
        let error = requester_manager
            .begin_hip76_request(requester_peer, strict_nonrecursive_dnssec_query(0x77))
            .await
            .expect_err("requester opt-out must reject new work");
        assert!(matches!(
            error,
            P2pError::Hip76 { peer, reason }
                if peer == requester_peer
                    && reason == crate::Hip76FailureReason::RequesterDisabled
        ));
        requester_manager
            .try_send(
                requester_peer,
                Arc::new(Packet::GetAddr),
                OutboundPriority::Control,
            )
            .await
            .expect("ordinary traffic after requester opt-out");
        await_ordinary_packet(&mut provider_events, provider_peer, Packet::GetAddr).await;

        requester_manager.disconnect_all().await;
        provider_manager.disconnect_all().await;
    }

    #[test]
    fn public_networks_reject_plaintext_peer_transport() {
        for network in [Network::Mainnet, Network::Testnet] {
            let mut config = LivePeerConfig::for_network(network);
            config.transport = PeerTransport::Plaintext;
            let error = config
                .validate()
                .expect_err("public network plaintext must fail closed");
            assert!(
                matches!(error, P2pError::Configuration(ref message) if
                    message == "mainnet and testnet peer transport must use authenticated Brontide"),
                "unexpected {network:?} plaintext validation error: {error}"
            );
        }
    }

    #[tokio::test]
    async fn live_manager_completes_authenticated_brontide_and_version_handshakes() {
        let mut server_config = LivePeerConfig::for_network(Network::Testnet);
        server_config.runtime.ping_interval = Duration::from_secs(60);
        let server_key = match &server_config.transport {
            PeerTransport::Brontide(identity) => *identity.public_key(),
            PeerTransport::Plaintext => panic!("public network must use Brontide"),
        };
        let mut client_config = LivePeerConfig::for_network(Network::Testnet);
        client_config.runtime.ping_interval = Duration::from_secs(60);
        let (server_manager, mut server_events) =
            LivePeerManager::new(server_config).expect("server");
        let (client_manager, mut client_events) =
            LivePeerManager::new(client_config).expect("client");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let server = {
            let manager = server_manager.clone();
            tokio::spawn(async move {
                let (stream, peer_address) = listener.accept().await.expect("accept");
                manager
                    .accept_stream(stream, peer_address)
                    .await
                    .expect("register")
            })
        };
        let mut peer_address = NetAddress::from_socket_addr(address, unix_time(), SERVICE_NETWORK);
        peer_address.key = server_key;
        let client_peer = client_manager
            .connect_net_address(&peer_address)
            .await
            .expect("Brontide connect");
        let server_peer = server.await.expect("join");

        let client_ready = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(PeerEvent::Ready { peer, .. }) = client_events.recv().await {
                    break peer;
                }
            }
        })
        .await
        .expect("client ready");
        let server_ready = tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if let Some(PeerEvent::Ready { peer, .. }) = server_events.recv().await {
                    break peer;
                }
            }
        })
        .await
        .expect("server ready");
        assert_eq!(client_ready, client_peer);
        assert_eq!(server_ready, server_peer);
    }

    #[tokio::test]
    async fn ban_admission_is_ip_wide_for_inbound_and_expires() {
        let config = LivePeerConfig::for_network(Network::Regtest);
        let (manager, _events) = LivePeerManager::new(config).expect("manager");
        let address: IpAddr = "127.0.0.1".parse().expect("IP");
        manager
            .replace_bans(vec![(address, unix_time().saturating_add(60))])
            .await;

        let outbound = manager
            .connect("127.0.0.1:1".parse().expect("outbound"))
            .await
            .expect_err("outbound ban");
        assert!(matches!(outbound, P2pError::BannedAddress { .. }));

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let listener_address = listener.local_addr().expect("listener address");
        let client = TcpStream::connect(listener_address).await.expect("connect");
        let (server, peer_address) = listener.accept().await.expect("accept");
        let inbound = manager
            .accept_stream(server, peer_address)
            .await
            .expect_err("inbound ban");
        assert!(matches!(inbound, P2pError::BannedAddress { .. }));
        drop(client);

        manager
            .replace_bans(vec![(address, unix_time().saturating_sub(1))])
            .await;
        assert!(!manager.is_banned(address).await);
    }

    #[tokio::test]
    async fn peer_limits_fail_closed() {
        let mut invalid_ban_time = LivePeerConfig::for_network(Network::Regtest);
        invalid_ban_time.ban_time = Duration::from_nanos(1);
        assert!(matches!(
            LivePeerManager::new(invalid_ban_time),
            Err(P2pError::Configuration(_))
        ));

        let mut config = LivePeerConfig::for_network(Network::Regtest);
        config.maximum_outbound = 0;
        config.maximum_inbound = 1;
        let (manager, _events) = LivePeerManager::new(config).expect("manager");
        let error = manager
            .connect("127.0.0.1:14038".parse().expect("address"))
            .await
            .expect_err("outbound disabled");
        assert!(matches!(error, P2pError::PeerLimit { .. }));
    }
}
