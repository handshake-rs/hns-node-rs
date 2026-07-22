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
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{mpsc, Mutex, RwLock},
    task::JoinSet,
};

use crate::{
    constants::{DEFAULT_USER_AGENT, PROTOCOL_VERSION, SERVICE_NETWORK},
    handshake::{PeerDirection, PeerState},
    runtime::{
        spawn_peer_runtime, OutboundPriority, PeerEvent, PeerHandle, PeerId, PeerRuntimeConfig,
        PeerRuntimeParameters, PeerSnapshot,
    },
    wire::{NetAddress, NetworkMagic, Packet, VersionPacket},
    P2pError,
};

#[derive(Clone, Debug)]
pub struct LivePeerConfig {
    pub network: Network,
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
}

impl LivePeerConfig {
    pub fn for_network(network: Network) -> Self {
        Self {
            network,
            maximum_inbound: 32,
            maximum_outbound: 8,
            event_capacity: 1_024,
            connect_timeout: Duration::from_secs(10),
            critical_broadcast_timeout: Duration::from_millis(250),
            ban_score: 100,
            ban_time: Duration::from_secs(24 * 60 * 60),
            protocol_version: PROTOCOL_VERSION,
            services: SERVICE_NETWORK,
            user_agent: DEFAULT_USER_AGENT.to_owned(),
            no_relay: false,
            runtime: PeerRuntimeConfig::default(),
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
        Ok((
            Self {
                config,
                peers: Arc::new(RwLock::new(HashMap::new())),
                events,
                next_peer_id: Arc::new(AtomicU64::new(1)),
                local_height: Arc::new(AtomicU32::new(0)),
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
        self.ensure_capacity(PeerDirection::Outbound, address)
            .await?;
        let stream = tokio::time::timeout(self.config.connect_timeout, TcpStream::connect(address))
            .await
            .map_err(|_| P2pError::Timeout(format!("connection to {address} timed out")))??;
        stream.set_nodelay(true)?;
        self.register_stream(stream, address, PeerDirection::Outbound)
            .await
    }

    pub async fn accept_stream(
        &self,
        stream: TcpStream,
        address: SocketAddr,
    ) -> Result<PeerId, P2pError> {
        self.ensure_capacity(PeerDirection::Inbound, address)
            .await?;
        stream.set_nodelay(true)?;
        self.register_stream(stream, address, PeerDirection::Inbound)
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
    ) -> Result<PeerId, P2pError> {
        let _registration = self.registration_lock.lock().await;
        self.ensure_capacity(direction, address).await?;
        let id = PeerId(self.next_peer_id.fetch_add(1, Ordering::Relaxed));
        let nonce = self.local_nonce;
        let local_version = VersionPacket {
            version: self.config.protocol_version,
            services: self.config.services,
            time: unix_time(),
            remote: NetAddress::from_socket_addr(address, unix_time(), self.config.services),
            nonce,
            agent: self.config.user_agent.clone(),
            height: self.local_height.load(Ordering::Acquire),
            no_relay: self.config.no_relay,
        };
        let magic = NetworkMagic::from(self.config.network);
        let (reader, writer) = stream.into_split();
        let spawned = spawn_peer_runtime(
            PeerRuntimeParameters {
                id,
                address,
                direction,
                magic,
                local_version,
                config: self.config.runtime.clone(),
                events: self.events.clone(),
            },
            reader,
            writer,
        )?;
        self.peers.write().await.insert(id, spawned.handle.clone());

        let peers = Arc::clone(&self.peers);
        let events = self.events.clone();
        tokio::spawn(async move {
            let reason = match spawned.task.await {
                Ok(Ok(())) => "peer task completed".to_owned(),
                Ok(Err(error)) => error.to_string(),
                Err(error) => format!("peer task join failed: {error}"),
            };
            peers.write().await.remove(&id);
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
    use crate::{handshake::PeerState, wire::Packet};

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
        client_manager.disconnect_all().await;
        server_manager.disconnect_all().await;
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
