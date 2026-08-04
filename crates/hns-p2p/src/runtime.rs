use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    fmt,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use hns_consensus::Network;
use hns_p2p_experimental::{
    ExperimentalPeerState, ExperimentalWireProfile, NegotiatedRegistry, ServiceMask,
    DENUO_V1_REGISTRY_FINGERPRINT,
};
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, oneshot, watch, Mutex, RwLock},
    task::JoinHandle,
    time::{sleep_until, Instant, MissedTickBehavior},
};

use crate::{
    brontide::{AsyncBrontideFrameReader, AsyncBrontideFrameWriter, BrontideSession},
    denuo::{
        extension_packet, is_extension_packet_type, is_registry_hello_packet, DenuoAction,
        DenuoCoordinator, DenuoPeerDiagnostics, DenuoPeerPhase, DenuoRuntimeMetrics,
    },
    experimental::{ExperimentalExchangeError, ExperimentalExchangeRuntime},
    handshake::{PeerDirection, PeerHandshake, PeerState},
    hip76::{
        is_hip76_packet_type, Hip76FailureReason, Hip76Inbound, Hip76ProviderPolicy,
        Hip76ProviderRequest, Hip76ProviderWork, Hip76RequesterResponse, Hip76RevokedWork,
        Hip76Session, Hip76SessionConfig, Hip76SessionDiagnostics, Hip76WriteToken,
    },
    hnsr::{is_hnsr_packet_type, peer_id_from_hnsr, HnsrCoordinator, HnsrIncoming, HnsrPeerAdmission},
    odoh::{
        is_odoh_packet_type, OdohFailureReason, OdohPeerProvenance, OdohRequesterRuntime,
    },
    wire::{
        AsyncFrameReader, AsyncFrameWriter, Frame, NetworkMagic, Packet, PacketType, VersionPacket,
    },
    DnsRelayRequesterPolicy, DnsRelayStatus, P2pError,
};

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
pub struct PeerId(pub u64);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OutboundPriority {
    Critical,
    Control,
    Normal,
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PeerTransportKind {
    #[default]
    Plaintext,
    Brontide,
}

#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct AuthenticatedPeerKey([u8; 33]);

impl AuthenticatedPeerKey {
    pub const fn new(bytes: [u8; 33]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 33] {
        &self.0
    }

    pub const fn into_bytes(self) -> [u8; 33] {
        self.0
    }
}

impl fmt::Debug for AuthenticatedPeerKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&encode_peer_key(self.0))
    }
}

impl Serialize for AuthenticatedPeerKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode_peer_key(self.0))
    }
}

impl<'de> Deserialize<'de> for AuthenticatedPeerKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded.len() != 66 {
            return Err(D::Error::custom(
                "authenticated peer key must contain 66 hexadecimal characters",
            ));
        }
        let mut bytes = [0_u8; 33];
        for (index, byte) in bytes.iter_mut().enumerate() {
            let high = decode_hex(encoded.as_bytes()[index * 2]).ok_or_else(|| {
                D::Error::custom("authenticated peer key contains non-hexadecimal data")
            })?;
            let low = decode_hex(encoded.as_bytes()[index * 2 + 1]).ok_or_else(|| {
                D::Error::custom("authenticated peer key contains non-hexadecimal data")
            })?;
            *byte = high << 4 | low;
        }
        Ok(Self(bytes))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hip76PeerProvenance {
    pub peer: PeerId,
    pub address: SocketAddr,
    pub direction: PeerDirection,
    pub transport: PeerTransportKind,
    pub authenticated_remote_static: Option<AuthenticatedPeerKey>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Hip76RequestAdmission {
    pub request_id: u64,
    pub generation: u64,
    pub deadline: Instant,
}

#[derive(Debug)]
pub struct Hip76PendingRequest {
    pub admission: Hip76RequestAdmission,
    peer: PeerId,
    outcome: oneshot::Receiver<Hip76RequestOutcome>,
}

impl Hip76PendingRequest {
    pub async fn outcome(self) -> Result<Hip76RequestOutcome, P2pError> {
        self.outcome
            .await
            .map_err(|_| P2pError::PeerUnavailable(self.peer))
    }
}

#[derive(Debug)]
pub enum Hip76RequestOutcome {
    Response {
        provenance: Hip76PeerProvenance,
        response: Hip76RequesterResponse,
    },
    Expired,
    Revoked,
    Disconnected,
    LocalSendUnavailable,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PeerSnapshot {
    pub id: PeerId,
    pub address: SocketAddr,
    pub direction: PeerDirection,
    pub transport: PeerTransportKind,
    pub authenticated_remote_static: Option<AuthenticatedPeerKey>,
    pub state: PeerState,
    pub protocol_version: Option<u32>,
    pub services: u64,
    pub advertised_height: Option<u32>,
    pub agent: Option<String>,
    pub no_relay: bool,
    pub score: i32,
    pub connected_at: u64,
    pub last_send: Option<u64>,
    pub last_receive: Option<u64>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub ping_millis: Option<u64>,
    pub denuo: DenuoPeerDiagnostics,
    #[serde(skip)]
    pub(crate) denuo_wire_profile: Option<ExperimentalWireProfile>,
    #[serde(skip)]
    pub(crate) denuo_negotiated_registry: Option<NegotiatedRegistry>,
    pub hip76: Hip76SessionDiagnostics,
}

/// Exact ready Denuo evidence bound to one authenticated live Brontide
/// connection. Browser and mobile adapters can consume this without
/// reconstructing registry state from diagnostics strings.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedExperimentalPeerEvidence {
    pub peer: PeerId,
    pub address: SocketAddr,
    pub direction: PeerDirection,
    pub peer_key: AuthenticatedPeerKey,
    pub services: u64,
    pub state: ExperimentalPeerState,
    pub negotiated: NegotiatedRegistry,
}

impl PeerSnapshot {
    pub fn new(id: PeerId, address: SocketAddr, direction: PeerDirection) -> Self {
        Self {
            id,
            address,
            direction,
            transport: PeerTransportKind::Plaintext,
            authenticated_remote_static: None,
            state: PeerState::Connecting,
            protocol_version: None,
            services: 0,
            advertised_height: None,
            agent: None,
            no_relay: false,
            score: 0,
            connected_at: unix_time(),
            last_send: None,
            last_receive: None,
            bytes_sent: 0,
            bytes_received: 0,
            ping_millis: None,
            denuo: DenuoPeerDiagnostics::default(),
            denuo_wire_profile: None,
            denuo_negotiated_registry: None,
            hip76: Hip76SessionDiagnostics::awaiting_registry(direction),
        }
    }

    pub fn authenticated_experimental_evidence(
        &self,
    ) -> Option<AuthenticatedExperimentalPeerEvidence> {
        if self.state != PeerState::Ready || self.transport != PeerTransportKind::Brontide {
            return None;
        }
        let peer_key = self.authenticated_remote_static?;
        let profile = self.denuo_wire_profile?;
        let negotiated = self.denuo_negotiated_registry.clone()?;
        let mut state = ExperimentalPeerState::new(
            profile,
            negotiated.network,
            negotiated.genesis_hash,
            DENUO_V1_REGISTRY_FINGERPRINT,
            ServiceMask::new(self.services),
        );
        state.mark_established();
        state.install_negotiation(negotiated.clone()).ok()?;
        Some(AuthenticatedExperimentalPeerEvidence {
            peer: self.id,
            address: self.address,
            direction: self.direction,
            peer_key,
            services: self.services,
            state,
            negotiated,
        })
    }
}

fn refresh_denuo_snapshot(snapshot: &mut PeerSnapshot, denuo: &DenuoCoordinator) {
    snapshot.denuo = denuo.diagnostics();
    match denuo.negotiated_evidence() {
        Some((wire_profile, negotiated)) => {
            snapshot.denuo_wire_profile = Some(wire_profile);
            snapshot.denuo_negotiated_registry = Some(negotiated.clone());
        }
        None => {
            snapshot.denuo_wire_profile = None;
            snapshot.denuo_negotiated_registry = None;
        }
    }
}

#[derive(Clone, Debug)]
pub struct PeerRuntimeConfig {
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
    pub ping_interval: Duration,
    pub pong_timeout: Duration,
    pub denuo_negotiation_timeout: Duration,
    pub critical_queue: usize,
    pub control_queue: usize,
    pub normal_queue: usize,
}

impl Default for PeerRuntimeConfig {
    fn default() -> Self {
        Self {
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(180),
            ping_interval: Duration::from_secs(30),
            pong_timeout: Duration::from_secs(90),
            denuo_negotiation_timeout: Duration::from_secs(10),
            critical_queue: 8,
            control_queue: 64,
            normal_queue: 256,
        }
    }
}

impl PeerRuntimeConfig {
    pub fn validate(&self) -> Result<(), P2pError> {
        if self.handshake_timeout.is_zero()
            || self.idle_timeout.is_zero()
            || self.ping_interval.is_zero()
            || self.pong_timeout.is_zero()
            || self.denuo_negotiation_timeout.is_zero()
        {
            return Err(P2pError::Configuration(
                "peer timeouts and intervals must be non-zero".to_owned(),
            ));
        }
        if self.critical_queue == 0 || self.control_queue == 0 || self.normal_queue == 0 {
            return Err(P2pError::Configuration(
                "peer outbound queue capacities must be non-zero".to_owned(),
            ));
        }
        if self.pong_timeout < self.ping_interval {
            return Err(P2pError::Configuration(
                "pong timeout must not be shorter than ping interval".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum PeerEvent {
    Connected {
        peer: PeerId,
        address: SocketAddr,
        direction: PeerDirection,
    },
    Ready {
        peer: PeerId,
        version: VersionPacket,
    },
    Packet {
        peer: PeerId,
        packet: Packet,
    },
    Disconnected {
        peer: PeerId,
        address: SocketAddr,
        direction: PeerDirection,
        reason: String,
    },
    InboundRejected {
        address: SocketAddr,
        reason: String,
    },
    Hip76ProviderRequest {
        provenance: Hip76PeerProvenance,
        request: Hip76ProviderRequest,
    },
    Hip76CapabilityChanged {
        provenance: Hip76PeerProvenance,
        diagnostics: Hip76SessionDiagnostics,
    },
    HnsrRequester {
        event: hns_hnsr_protocol::HnsrRequesterEvent,
    },
}

struct CriticalOutbound {
    packet: Arc<Packet>,
    completion: Option<oneshot::Sender<Result<(), String>>>,
}

enum Hip76Command {
    BeginRequest {
        query: Vec<u8>,
        completion: oneshot::Sender<Result<Hip76PendingRequest, crate::Hip76Error>>,
    },
    FinishProviderRequest {
        work: Hip76ProviderWork,
        status: DnsRelayStatus,
        response: Vec<u8>,
        completion: oneshot::Sender<Result<(), crate::Hip76Error>>,
    },
    ReplacePolicy {
        requester: DnsRelayRequesterPolicy,
        provider: Hip76ProviderPolicy,
        generation: u64,
        completion: oneshot::Sender<Result<Hip76RevokedWork, crate::Hip76Error>>,
    },
    Revoke {
        generation: u64,
        completion: oneshot::Sender<Result<Hip76RevokedWork, crate::Hip76Error>>,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Hip76WireKind {
    Requester { work_token: Hip76WriteToken },
    Provider { work_token: Hip76WriteToken },
    ProviderRejection { work_token: Hip76WriteToken },
}

struct Hip76WireOutbound {
    packet: Arc<Packet>,
    request_id: u64,
    generation: u64,
    deadline: Instant,
    kind: Hip76WireKind,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Hip76WriterState {
    generation: u64,
    connection_active: bool,
    requester_active: bool,
    provider_active: bool,
}

impl Hip76WriterState {
    fn from_diagnostics(diagnostics: &Hip76SessionDiagnostics) -> Self {
        Self {
            generation: diagnostics.policy_generation,
            connection_active: diagnostics.phase == crate::Hip76ConnectionPhase::Active,
            requester_active: diagnostics.requester_eligible,
            provider_active: diagnostics.provider_available,
        }
    }

    fn admits(self, outbound: &Hip76WireOutbound, now: Instant) -> bool {
        if self.generation != outbound.generation || now >= outbound.deadline {
            return false;
        }
        match outbound.kind {
            Hip76WireKind::Requester { .. } => self.requester_active,
            Hip76WireKind::Provider { .. } => self.provider_active,
            Hip76WireKind::ProviderRejection { .. } => self.connection_active,
        }
    }
}

#[derive(Debug)]
enum Hip76WriteDisposition {
    Written,
    DroppedStale,
    Failed,
}

#[derive(Debug)]
struct Hip76WriteResult {
    request_id: u64,
    generation: u64,
    kind: Hip76WireKind,
    disposition: Hip76WriteDisposition,
}

struct PendingRequester {
    generation: u64,
    work_token: Hip76WriteToken,
    completion: oneshot::Sender<Hip76RequestOutcome>,
}

struct PendingProviderWrite {
    request_id: u64,
    generation: u64,
    completion: oneshot::Sender<Result<(), crate::Hip76Error>>,
}

struct Hip76WriterChannels {
    outbound: mpsc::Receiver<Hip76WireOutbound>,
    results: mpsc::Sender<Hip76WriteResult>,
    state: watch::Receiver<Hip76WriterState>,
}

#[derive(Clone, Debug)]
pub struct PeerHandle {
    pub(crate) id: PeerId,
    pub(crate) snapshot: Arc<RwLock<PeerSnapshot>>,
    critical_tx: mpsc::Sender<CriticalOutbound>,
    control_tx: mpsc::Sender<Arc<Packet>>,
    normal_tx: mpsc::Sender<Arc<Packet>>,
    hip76_tx: mpsc::Sender<Hip76Command>,
    hip76_status: watch::Receiver<Hip76SessionDiagnostics>,
    shutdown_tx: watch::Sender<bool>,
}

impl PeerHandle {
    pub fn id(&self) -> PeerId {
        self.id
    }

    pub async fn snapshot(&self) -> PeerSnapshot {
        self.snapshot.read().await.clone()
    }

    pub fn try_send(
        &self,
        packet: Arc<Packet>,
        priority: OutboundPriority,
    ) -> Result<(), P2pError> {
        let map_error = |full: bool| {
            if full {
                P2pError::QueueFull {
                    peer: self.id,
                    priority,
                }
            } else {
                P2pError::PeerUnavailable(self.id)
            }
        };
        match priority {
            OutboundPriority::Critical => self
                .critical_tx
                .try_send(CriticalOutbound {
                    packet,
                    completion: None,
                })
                .map_err(|error| map_error(matches!(error, mpsc::error::TrySendError::Full(_)))),
            OutboundPriority::Control => self
                .control_tx
                .try_send(packet)
                .map_err(|error| map_error(matches!(error, mpsc::error::TrySendError::Full(_)))),
            OutboundPriority::Normal => self
                .normal_tx
                .try_send(packet)
                .map_err(|error| map_error(matches!(error, mpsc::error::TrySendError::Full(_)))),
        }
    }

    pub fn disconnect(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    pub async fn begin_hip76_request(
        &self,
        query: Vec<u8>,
    ) -> Result<Hip76PendingRequest, P2pError> {
        let (completion, result) = oneshot::channel();
        self.hip76_tx
            .try_send(Hip76Command::BeginRequest { query, completion })
            .map_err(|error| {
                if matches!(error, mpsc::error::TrySendError::Full(_)) {
                    P2pError::ExperimentalQueueFull {
                        peer: self.id,
                        protocol: "HIP-76",
                    }
                } else {
                    P2pError::PeerUnavailable(self.id)
                }
            })?;
        result
            .await
            .map_err(|_| P2pError::PeerUnavailable(self.id))?
            .map_err(|error| P2pError::Hip76 {
                peer: self.id,
                reason: error.reason,
            })
    }

    pub async fn finish_hip76_provider_request(
        &self,
        work: Hip76ProviderWork,
        status: DnsRelayStatus,
        response: Vec<u8>,
    ) -> Result<(), P2pError> {
        let (completion, result) = oneshot::channel();
        self.hip76_tx
            .try_send(Hip76Command::FinishProviderRequest {
                work,
                status,
                response,
                completion,
            })
            .map_err(|error| {
                if matches!(error, mpsc::error::TrySendError::Full(_)) {
                    P2pError::ExperimentalQueueFull {
                        peer: self.id,
                        protocol: "HIP-76",
                    }
                } else {
                    P2pError::PeerUnavailable(self.id)
                }
            })?;
        result
            .await
            .map_err(|_| P2pError::PeerUnavailable(self.id))?
            .map_err(|error| P2pError::Hip76 {
                peer: self.id,
                reason: error.reason,
            })
    }

    pub fn subscribe_hip76(&self) -> watch::Receiver<Hip76SessionDiagnostics> {
        self.hip76_status.clone()
    }

    pub(crate) async fn replace_hip76_policy(
        &self,
        requester: DnsRelayRequesterPolicy,
        provider: Hip76ProviderPolicy,
        generation: u64,
    ) -> Result<Hip76RevokedWork, P2pError> {
        let (completion, result) = oneshot::channel();
        self.hip76_tx
            .try_send(Hip76Command::ReplacePolicy {
                requester,
                provider,
                generation,
                completion,
            })
            .map_err(|_| P2pError::PeerUnavailable(self.id))?;
        result
            .await
            .map_err(|_| P2pError::PeerUnavailable(self.id))?
            .map_err(|error| P2pError::Hip76 {
                peer: self.id,
                reason: error.reason,
            })
    }

    pub(crate) async fn revoke_hip76(&self, generation: u64) -> Result<Hip76RevokedWork, P2pError> {
        let (completion, result) = oneshot::channel();
        self.hip76_tx
            .try_send(Hip76Command::Revoke {
                generation,
                completion,
            })
            .map_err(|_| P2pError::PeerUnavailable(self.id))?;
        result
            .await
            .map_err(|_| P2pError::PeerUnavailable(self.id))?
            .map_err(|error| P2pError::Hip76 {
                peer: self.id,
                reason: error.reason,
            })
    }

    /// Send a latency-critical packet and wait until the peer writer has
    /// completed the socket write. Queue admission alone is not sufficient for
    /// solved-block publication durability.
    pub async fn send_critical(
        &self,
        packet: Arc<Packet>,
        maximum_wait: Duration,
    ) -> Result<(), P2pError> {
        let (completion_tx, completion_rx) = oneshot::channel();
        tokio::time::timeout(maximum_wait, async {
            self.critical_tx
                .send(CriticalOutbound {
                    packet,
                    completion: Some(completion_tx),
                })
                .await
                .map_err(|_| P2pError::PeerUnavailable(self.id))?;
            match completion_rx.await {
                Ok(Ok(())) => Ok(()),
                Ok(Err(reason)) => Err(P2pError::Disconnected(reason)),
                Err(_) => Err(P2pError::PeerUnavailable(self.id)),
            }
        })
        .await
        .map_err(|_| P2pError::QueueTimeout {
            peer: self.id,
            priority: OutboundPriority::Critical,
        })?
    }
}

pub(crate) struct SpawnedPeer {
    pub handle: PeerHandle,
    pub task: JoinHandle<Result<(), P2pError>>,
}

pub(crate) struct PeerRuntimeParameters {
    pub id: PeerId,
    pub address: SocketAddr,
    pub direction: PeerDirection,
    pub network: Network,
    pub magic: NetworkMagic,
    pub local_version: VersionPacket,
    pub config: PeerRuntimeConfig,
    pub critical_write_timeout: Duration,
    pub events: mpsc::Sender<PeerEvent>,
    pub denuo_metrics: DenuoRuntimeMetrics,
    pub hip76_config: Hip76SessionConfig,
    pub odoh: Arc<Mutex<OdohRequesterRuntime>>,
    pub experimental: Arc<Mutex<ExperimentalExchangeRuntime>>,
    pub hnsr: Arc<Mutex<HnsrCoordinator>>,
    pub peers: Arc<RwLock<HashMap<PeerId, PeerHandle>>>,
}

pub(crate) fn spawn_peer_runtime<R, W>(
    parameters: PeerRuntimeParameters,
    reader: R,
    writer: W,
) -> Result<SpawnedPeer, P2pError>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let magic = parameters.magic;
    spawn_peer_runtime_with_frames(
        parameters,
        PeerFrameReader::Plaintext(AsyncFrameReader::new(reader, magic)),
        PeerFrameWriter::Plaintext(AsyncFrameWriter::new(writer, magic)),
        PeerTransportKind::Plaintext,
        None,
    )
}

pub(crate) fn spawn_brontide_peer_runtime<R, W>(
    parameters: PeerRuntimeParameters,
    reader: R,
    writer: W,
    session: BrontideSession,
) -> Result<SpawnedPeer, P2pError>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let magic = parameters.magic;
    let authenticated_remote_static = AuthenticatedPeerKey::new(*session.remote_static_key());
    let (send_cipher, receive_cipher) = session.into_ciphers();
    spawn_peer_runtime_with_frames(
        parameters,
        PeerFrameReader::Brontide(AsyncBrontideFrameReader::new(reader, receive_cipher, magic)),
        PeerFrameWriter::Brontide(AsyncBrontideFrameWriter::new(writer, send_cipher, magic)),
        PeerTransportKind::Brontide,
        Some(authenticated_remote_static),
    )
}

fn spawn_peer_runtime_with_frames<R, W>(
    parameters: PeerRuntimeParameters,
    reader: PeerFrameReader<R>,
    writer: PeerFrameWriter<W>,
    transport: PeerTransportKind,
    authenticated_remote_static: Option<AuthenticatedPeerKey>,
) -> Result<SpawnedPeer, P2pError>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let PeerRuntimeParameters {
        id,
        address,
        direction,
        network,
        magic,
        local_version,
        config,
        critical_write_timeout,
        events,
        denuo_metrics,
        mut hip76_config,
        odoh,
        experimental,
        hnsr,
        peers,
    } = parameters;
    config.validate()?;
    // Runtime request IDs are unpredictable per connection. The configurable
    // seed remains available only to direct session tests and embeddings.
    hip76_config.first_request_id = rand::random::<u64>().max(1);
    let denuo = DenuoCoordinator::new(
        direction,
        network,
        local_version.services,
        denuo_request_id(id, local_version.nonce),
        config.denuo_negotiation_timeout,
        denuo_metrics,
    )
    .map_err(|error| {
        P2pError::Configuration(format!(
            "canonical Denuo registry hello is invalid: {error}"
        ))
    })?;
    let hip76 = Hip76Session::new(
        direction,
        local_version.services,
        0,
        false,
        hip76_config.clone(),
    )
    .map_err(|error| P2pError::Configuration(error.to_string()))?;
    let (critical_tx, critical_rx) = mpsc::channel(config.critical_queue);
    let (control_tx, control_rx) = mpsc::channel(config.control_queue);
    let (normal_tx, normal_rx) = mpsc::channel(config.normal_queue);
    let hip76_capacity = usize::from(hip76_config.maximum_live_requests)
        .saturating_mul(2)
        .max(1);
    let (hip76_tx, hip76_rx) = mpsc::channel(hip76_capacity);
    let (hip76_wire_tx, hip76_wire_rx) = mpsc::channel(hip76_capacity);
    let (hip76_write_result_tx, hip76_write_result_rx) = mpsc::channel(hip76_capacity);
    let initial_hip76 = hip76.diagnostics();
    let (hip76_writer_state_tx, hip76_writer_state_rx) =
        watch::channel(Hip76WriterState::from_diagnostics(&initial_hip76));
    let (hip76_status_tx, hip76_status) = watch::channel(initial_hip76.clone());
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let mut initial_snapshot = PeerSnapshot::new(id, address, direction);
    initial_snapshot.transport = transport;
    initial_snapshot.authenticated_remote_static = authenticated_remote_static;
    refresh_denuo_snapshot(&mut initial_snapshot, &denuo);
    initial_snapshot.hip76 = initial_hip76;
    let snapshot = Arc::new(RwLock::new(initial_snapshot));
    let handle = PeerHandle {
        id,
        snapshot: Arc::clone(&snapshot),
        critical_tx: critical_tx.clone(),
        control_tx: control_tx.clone(),
        normal_tx,
        hip76_tx,
        hip76_status,
        shutdown_tx,
    };

    let task = tokio::spawn(run_peer(
        id,
        address,
        direction,
        magic,
        local_version,
        denuo,
        hip76,
        odoh,
        experimental,
        hnsr,
        peers,
        transport,
        authenticated_remote_static,
        reader,
        writer,
        config,
        critical_write_timeout,
        events,
        snapshot,
        critical_rx,
        control_rx,
        normal_rx,
        hip76_rx,
        hip76_wire_tx,
        hip76_wire_rx,
        hip76_write_result_tx,
        hip76_write_result_rx,
        hip76_writer_state_tx,
        hip76_writer_state_rx,
        hip76_status_tx,
        control_tx,
        shutdown_rx,
    ));

    Ok(SpawnedPeer { handle, task })
}

enum PeerFrameReader<R> {
    Plaintext(AsyncFrameReader<R>),
    Brontide(AsyncBrontideFrameReader<R>),
}

impl<R> PeerFrameReader<R>
where
    R: AsyncRead + Unpin,
{
    async fn read_frame(&mut self) -> Result<Frame, P2pError> {
        match self {
            Self::Plaintext(reader) => reader.read_frame().await,
            Self::Brontide(reader) => reader.read_frame().await,
        }
    }
}

enum PeerFrameWriter<W> {
    Plaintext(AsyncFrameWriter<W>),
    Brontide(AsyncBrontideFrameWriter<W>),
}

impl<W> PeerFrameWriter<W>
where
    W: AsyncWrite + Unpin,
{
    async fn write_packet(&mut self, packet: &Packet) -> Result<usize, P2pError> {
        match self {
            Self::Plaintext(writer) => writer.write_packet(packet).await,
            Self::Brontide(writer) => writer.write_frame(&Frame::from_packet(packet)?).await,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_peer<R, W>(
    id: PeerId,
    address: SocketAddr,
    direction: PeerDirection,
    _magic: NetworkMagic,
    local_version: VersionPacket,
    denuo: DenuoCoordinator,
    hip76: Hip76Session,
    odoh: Arc<Mutex<OdohRequesterRuntime>>,
    experimental: Arc<Mutex<ExperimentalExchangeRuntime>>,
    hnsr: Arc<Mutex<HnsrCoordinator>>,
    peers: Arc<RwLock<HashMap<PeerId, PeerHandle>>>,
    transport: PeerTransportKind,
    authenticated_remote_static: Option<AuthenticatedPeerKey>,
    reader: PeerFrameReader<R>,
    writer: PeerFrameWriter<W>,
    config: PeerRuntimeConfig,
    critical_write_timeout: Duration,
    events: mpsc::Sender<PeerEvent>,
    snapshot: Arc<RwLock<PeerSnapshot>>,
    critical_rx: mpsc::Receiver<CriticalOutbound>,
    control_rx: mpsc::Receiver<Arc<Packet>>,
    normal_rx: mpsc::Receiver<Arc<Packet>>,
    hip76_rx: mpsc::Receiver<Hip76Command>,
    hip76_wire_tx: mpsc::Sender<Hip76WireOutbound>,
    hip76_wire_rx: mpsc::Receiver<Hip76WireOutbound>,
    hip76_write_result_tx: mpsc::Sender<Hip76WriteResult>,
    hip76_write_result_rx: mpsc::Receiver<Hip76WriteResult>,
    hip76_writer_state_tx: watch::Sender<Hip76WriterState>,
    hip76_writer_state_rx: watch::Receiver<Hip76WriterState>,
    hip76_status_tx: watch::Sender<Hip76SessionDiagnostics>,
    control_tx: mpsc::Sender<Arc<Packet>>,
    shutdown_rx: watch::Receiver<bool>,
) -> Result<(), P2pError>
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    {
        let mut state = snapshot.write().await;
        state.state = PeerState::Handshaking;
    }
    events
        .send(PeerEvent::Connected {
            peer: id,
            address,
            direction,
        })
        .await
        .map_err(|_| P2pError::EventChannelClosed)?;

    let mut writer_task = tokio::spawn(peer_writer(
        writer,
        Arc::clone(&snapshot),
        critical_rx,
        control_rx,
        normal_rx,
        Hip76WriterChannels {
            outbound: hip76_wire_rx,
            results: hip76_write_result_tx,
            state: hip76_writer_state_rx,
        },
    ));
    if direction == PeerDirection::Outbound {
        control_tx
            .send(Arc::new(Packet::Version(local_version.clone())))
            .await
            .map_err(|_| P2pError::PeerUnavailable(id))?;
    }

    let mut reader_future = Box::pin(peer_reader(
        id,
        direction,
        local_version,
        denuo,
        hip76,
        odoh,
        experimental,
        hnsr,
        peers,
        transport,
        authenticated_remote_static,
        reader,
        config,
        critical_write_timeout,
        events,
        Arc::clone(&snapshot),
        control_tx,
        hip76_rx,
        hip76_wire_tx,
        hip76_write_result_rx,
        hip76_writer_state_tx,
        hip76_status_tx,
        shutdown_rx,
    ));

    let result = tokio::select! {
        result = &mut reader_future => result,
        result = &mut writer_task => {
            match result {
                Ok(result) => result,
                Err(error) => Err(P2pError::Task(format!("peer writer task failed: {error}"))),
            }
        }
    };

    if !writer_task.is_finished() {
        writer_task.abort();
    }
    {
        let mut state = snapshot.write().await;
        state.state = PeerState::Closed;
    }
    result
}

#[allow(clippy::too_many_arguments)]
async fn peer_reader<R>(
    id: PeerId,
    direction: PeerDirection,
    local_version: VersionPacket,
    mut denuo: DenuoCoordinator,
    mut hip76: Hip76Session,
    odoh: Arc<Mutex<OdohRequesterRuntime>>,
    experimental: Arc<Mutex<ExperimentalExchangeRuntime>>,
    hnsr: Arc<Mutex<HnsrCoordinator>>,
    peers: Arc<RwLock<HashMap<PeerId, PeerHandle>>>,
    transport: PeerTransportKind,
    authenticated_remote_static: Option<AuthenticatedPeerKey>,
    mut reader: PeerFrameReader<R>,
    config: PeerRuntimeConfig,
    critical_write_timeout: Duration,
    events: mpsc::Sender<PeerEvent>,
    snapshot: Arc<RwLock<PeerSnapshot>>,
    control_tx: mpsc::Sender<Arc<Packet>>,
    mut hip76_rx: mpsc::Receiver<Hip76Command>,
    hip76_wire_tx: mpsc::Sender<Hip76WireOutbound>,
    mut hip76_write_result_rx: mpsc::Receiver<Hip76WriteResult>,
    hip76_writer_state_tx: watch::Sender<Hip76WriterState>,
    hip76_status_tx: watch::Sender<Hip76SessionDiagnostics>,
    mut shutdown_rx: watch::Receiver<bool>,
) -> Result<(), P2pError>
where
    R: AsyncRead + Unpin,
{
    let started = Instant::now();
    let mut last_receive = Instant::now();
    let mut handshake = PeerHandshake::new(direction, local_version.nonce);
    if direction == PeerDirection::Outbound {
        handshake.local_version(local_version.clone())?;
    }
    let mut ping = tokio::time::interval(config.ping_interval);
    ping.set_missed_tick_behavior(MissedTickBehavior::Delay);
    ping.tick().await;
    let mut challenge: Option<([u8; 8], Instant)> = None;
    let mut nonce_counter = u64::from_le_bytes(handshake_nonce_seed(id));
    let mut hip76_commands_open = true;
    let mut hip76_write_results_open = true;
    let mut pending_requesters = BTreeMap::<u64, PendingRequester>::new();
    let mut pending_provider_writes = BTreeMap::<Hip76WriteToken, PendingProviderWrite>::new();
    let provenance = Hip76PeerProvenance {
        peer: id,
        address: snapshot.read().await.address,
        direction,
        transport,
        authenticated_remote_static,
    };
    let odoh_provenance = OdohPeerProvenance {
        peer: id,
        address: provenance.address,
        direction,
        transport,
        authenticated_remote_static,
    };

    let result = async {
        'peer: loop {
        let idle_deadline = last_receive + config.idle_timeout;
        let handshake_deadline = started + config.handshake_timeout;
        let deadline = if handshake.is_ready() {
            idle_deadline
        } else {
            idle_deadline.min(handshake_deadline)
        };

        // `AsyncReadExt::read_exact` is not cancellation safe. Keep the same
        // frame future alive when maintenance timers fire; recreating it after
        // a partially consumed large payload would interpret payload bytes as
        // the next nine-byte frame header and desynchronize the connection.
        let frame = {
            let mut frame_read = Box::pin(reader.read_frame());
            loop {
                tokio::select! {
                    frame = &mut frame_read => {
                        match frame {
                            Ok(frame) => break frame,
                            Err(P2pError::ScopedPacketLimit {
                                packet_type,
                                actual,
                                ..
                            }) if is_odoh_packet_type(PacketType::Unknown(packet_type)) => {
                                last_receive = Instant::now();
                                let mut state = snapshot.write().await;
                                state.bytes_received = state.bytes_received.saturating_add(
                                    (crate::constants::FRAME_HEADER_SIZE + actual) as u64,
                                );
                                state.last_receive = Some(unix_time());
                                drop(state);
                                odoh
                                    .lock()
                                    .await
                                    .fault_peer(id, OdohFailureReason::PacketTooLarge);
                                experimental.lock().await.cancel(
                                    id,
                                    PacketType::Unknown(packet_type),
                                    ExperimentalExchangeError::ResponseTooLarge,
                                );
                                continue 'peer;
                            }
                            Err(P2pError::ScopedPacketLimit {
                                packet_type,
                                actual,
                                ..
                            }) if is_hnsr_packet_type(PacketType::Unknown(packet_type)) => {
                                last_receive = Instant::now();
                                let mut state = snapshot.write().await;
                                state.bytes_received = state.bytes_received.saturating_add(
                                    (crate::constants::FRAME_HEADER_SIZE + actual) as u64,
                                );
                                state.last_receive = Some(unix_time());
                                drop(state);
                                let routes = hnsr.lock().await.fault_peer(id);
                                dispatch_hnsr_incoming(
                                    &hnsr,
                                    &peers,
                                    &events,
                                    HnsrIncoming {
                                        relay_routes: routes,
                                        ..HnsrIncoming::default()
                                    },
                                    critical_write_timeout,
                                )
                                .await;
                                continue 'peer;
                            }
                            Err(P2pError::ScopedPacketLimit {
                                packet_type,
                                actual,
                                ..
                            })
                                if is_hip76_packet_type(PacketType::Unknown(packet_type)) =>
                            {
                                last_receive = Instant::now();
                                let mut state = snapshot.write().await;
                                state.bytes_received = state.bytes_received.saturating_add(
                                    (crate::constants::FRAME_HEADER_SIZE + actual) as u64,
                                );
                                state.last_receive = Some(unix_time());
                                drop(state);
                                let reason = if packet_type
                                    == hns_p2p_experimental::DNS_RELAY_REQUEST_PACKET.value()
                                {
                                    Hip76FailureReason::RequestTooLarge
                                } else {
                                    Hip76FailureReason::ResponseTooLarge
                                };
                                let revoked = hip76.fault_protocol(reason);
                                complete_revoked_requesters(
                                    &mut pending_requesters,
                                    &revoked,
                                );
                                snapshot.write().await.hip76 = refresh_hip76_state(
                                    &hip76,
                                    provenance,
                                    &events,
                                    &hip76_writer_state_tx,
                                    &hip76_status_tx,
                                );
                                continue 'peer;
                            }
                            Err(error) => return Err(error),
                        }
                    },
                    _ = sleep_until(denuo.pending_deadline().unwrap_or(deadline)), if denuo.pending_deadline().is_some() => {
                        if denuo.expire(Instant::now()) {
                            odoh
                                .lock()
                                .await
                                .fault_peer(id, OdohFailureReason::RegistryNotNegotiated);
                            let hnsr_routes = hnsr.lock().await.fault_peer(id);
                            dispatch_hnsr_incoming(
                                &hnsr,
                                &peers,
                                &events,
                                HnsrIncoming {
                                    relay_routes: hnsr_routes,
                                    ..HnsrIncoming::default()
                                },
                                critical_write_timeout,
                            )
                            .await;
                            let revoked = synchronize_hip76_with_denuo(&denuo, &mut hip76);
                            complete_revoked_requesters(
                                &mut pending_requesters,
                                &revoked,
                            );
                            let mut state = snapshot.write().await;
                            refresh_denuo_snapshot(&mut state, &denuo);
                            state.hip76 = refresh_hip76_state(
                                &hip76,
                                provenance,
                                &events,
                                &hip76_writer_state_tx,
                                &hip76_status_tx,
                            );
                        }
                    }
                    _ = sleep_until(hip76.pending_deadline().unwrap_or(deadline)), if hip76.pending_deadline().is_some() => {
                        let expiration = hip76.expire(Instant::now());
                        if !expiration.is_empty() {
                            complete_requester_ids(
                                &mut pending_requesters,
                                &expiration.requester_request_ids,
                                || Hip76RequestOutcome::Expired,
                            );
                            fail_provider_ids(
                                &mut pending_provider_writes,
                                &expiration.provider_request_ids,
                                Hip76FailureReason::DeadlineExpired,
                            );
                            snapshot.write().await.hip76 = refresh_hip76_state(
                                &hip76,
                                provenance,
                                &events,
                                &hip76_writer_state_tx,
                                &hip76_status_tx,
                            );
                        }
                    }
                    command = hip76_rx.recv(), if hip76_commands_open => {
                        match command {
                            Some(command) => {
                                handle_hip76_command(
                                    id,
                                    &mut hip76,
                                    command,
                                    &hip76_wire_tx,
                                    &mut pending_requesters,
                                    &mut pending_provider_writes,
                                );
                                snapshot.write().await.hip76 = refresh_hip76_state(
                                    &hip76,
                                    provenance,
                                    &events,
                                    &hip76_writer_state_tx,
                                    &hip76_status_tx,
                                );
                            }
                            None => hip76_commands_open = false,
                        }
                    }
                    write_result = hip76_write_result_rx.recv(), if hip76_write_results_open => {
                        match write_result {
                            Some(write_result) => {
                                handle_hip76_write_result(
                                    &mut hip76,
                                    write_result,
                                    &mut pending_requesters,
                                    &mut pending_provider_writes,
                                );
                                snapshot.write().await.hip76 = refresh_hip76_state(
                                    &hip76,
                                    provenance,
                                    &events,
                                    &hip76_writer_state_tx,
                                    &hip76_status_tx,
                                );
                            }
                            None => hip76_write_results_open = false,
                        }
                    }
                    _ = ping.tick(), if handshake.is_ready() => {
                        if let Some((_, sent)) = challenge {
                            if sent.elapsed() >= config.pong_timeout {
                                return Err(P2pError::Timeout("peer did not answer ping".to_owned()));
                            }
                        } else {
                            nonce_counter = nonce_counter.wrapping_add(1);
                            let nonce = nonce_counter.to_le_bytes();
                            challenge = Some((nonce, Instant::now()));
                            control_tx
                                .send(Arc::new(Packet::Ping(nonce)))
                                .await
                                .map_err(|_| P2pError::PeerUnavailable(id))?;
                        }
                    }
                    _ = sleep_until(deadline) => {
                        if !handshake.is_ready() && Instant::now() >= handshake_deadline {
                            return Err(P2pError::Timeout("peer handshake timed out".to_owned()));
                        }
                        return Err(P2pError::Timeout("peer idle timeout expired".to_owned()));
                    }
                    changed = shutdown_rx.changed() => {
                        if changed.is_err() || *shutdown_rx.borrow() {
                            return Err(P2pError::Disconnected("peer was disconnected locally".to_owned()));
                        }
                    }
                }
            }
        };

        last_receive = Instant::now();
        {
            let mut state = snapshot.write().await;
            state.last_receive = Some(unix_time());
            state.bytes_received = state
                .bytes_received
                .saturating_add((crate::constants::FRAME_HEADER_SIZE + frame.payload.len()) as u64);
        }
        if experimental
            .lock()
            .await
            .receive(id, frame.packet_type, &frame.payload)
        {
            continue;
        }
        if is_extension_packet_type(frame.packet_type) {
            denuo.expire(Instant::now());
            let action = denuo.receive_extension(&frame.payload);
            admit_denuo_action(&mut denuo, action, &control_tx);
            let revoked = synchronize_hip76_with_denuo(&denuo, &mut hip76);
            if denuo.diagnostics().phase != DenuoPeerPhase::Negotiated {
                odoh
                    .lock()
                    .await
                    .fault_peer(id, OdohFailureReason::RegistryNotNegotiated);
                let hnsr_routes = hnsr.lock().await.fault_peer(id);
                dispatch_hnsr_incoming(
                    &hnsr,
                    &peers,
                    &events,
                    HnsrIncoming {
                        relay_routes: hnsr_routes,
                        ..HnsrIncoming::default()
                    },
                    critical_write_timeout,
                )
                .await;
            }
            complete_revoked_requesters(
                &mut pending_requesters,
                &revoked,
            );
            let mut state = snapshot.write().await;
            refresh_denuo_snapshot(&mut state, &denuo);
            state.hip76 = refresh_hip76_state(
                &hip76,
                provenance,
                &events,
                &hip76_writer_state_tx,
                &hip76_status_tx,
            );
            continue;
        }
        if is_hip76_packet_type(frame.packet_type) {
            handle_hip76_frame(
                &mut hip76,
                &frame,
                provenance,
                &events,
                &hip76_wire_tx,
                &mut pending_requesters,
            );
            snapshot.write().await.hip76 = refresh_hip76_state(
                &hip76,
                provenance,
                &events,
                &hip76_writer_state_tx,
                &hip76_status_tx,
            );
            continue;
        }
        if is_hnsr_packet_type(frame.packet_type) {
            let Some(admission) = hnsr_peer_admission(
                id,
                provenance.address,
                direction,
                transport,
                authenticated_remote_static,
                &handshake,
                &denuo,
            ) else {
                let routes = hnsr.lock().await.fault_peer(id);
                dispatch_hnsr_incoming(
                    &hnsr,
                    &peers,
                    &events,
                    HnsrIncoming {
                        relay_routes: routes,
                        ..HnsrIncoming::default()
                    },
                    critical_write_timeout,
                )
                .await;
                continue;
            };
            let incoming = hnsr
                .lock()
                .await
                .handle_encoded(&admission, &frame.payload, unix_time());
            match incoming {
                Ok(incoming) => {
                    dispatch_hnsr_incoming(
                        &hnsr,
                        &peers,
                        &events,
                        incoming,
                        critical_write_timeout,
                    )
                    .await;
                }
                Err(_) => {
                    let routes = hnsr.lock().await.fault_peer(id);
                    dispatch_hnsr_incoming(
                        &hnsr,
                        &peers,
                        &events,
                        HnsrIncoming {
                            relay_routes: routes,
                            ..HnsrIncoming::default()
                        },
                        critical_write_timeout,
                    )
                    .await;
                }
            }
            continue;
        }
        if is_odoh_packet_type(frame.packet_type) {
            let remote_services = handshake
                .remote_version()
                .map_or(0, |version| version.services);
            let Some((wire_profile, negotiated)) = denuo
                .negotiated_evidence()
                .filter(|_| handshake.is_ready())
                .map(|(wire_profile, negotiated)| (wire_profile, negotiated.clone()))
            else {
                odoh
                    .lock()
                    .await
                    .fault_peer(id, OdohFailureReason::RegistryNotNegotiated);
                continue;
            };
            odoh.lock().await.receive(
                odoh_provenance,
                remote_services,
                wire_profile,
                negotiated,
                &frame.payload,
                unix_time(),
                Instant::now(),
            );
            continue;
        }
        let packet = frame.decode_packet()?;
        if let Packet::Pong(nonce) = &packet {
            if let Some((expected, sent)) = challenge {
                if *nonce == expected {
                    let elapsed = sent.elapsed().as_millis();
                    snapshot.write().await.ping_millis =
                        Some(elapsed.min(u128::from(u64::MAX)) as u64);
                    challenge = None;
                }
            }
        }

        let update = handshake.receive(&packet)?;
        if let Packet::Version(version) = &packet {
            denuo.observe_remote_services(version.services);
            hip76.observe_remote_services(version.services);
        }
        // HSD's inbound side waits for the remote version before sending
        // its own introduction. Queue local VERSION before VERACK so the
        // peer observes the same handshake ordering.
        if direction == PeerDirection::Inbound
            && matches!(&packet, Packet::Version(_))
            && !handshake.local_version_sent()
        {
            let version = handshake.local_version(local_version.clone())?;
            control_tx
                .send(Arc::new(version))
                .await
                .map_err(|_| P2pError::PeerUnavailable(id))?;
        }
        for response in update.responses {
            control_tx
                .send(Arc::new(response))
                .await
                .map_err(|_| P2pError::PeerUnavailable(id))?;
        }
        if let Some(version) = handshake.remote_version() {
            let mut state = snapshot.write().await;
            state.protocol_version = Some(version.version);
            state.services = version.services;
            state.advertised_height = Some(version.height);
            state.agent = Some(version.agent.clone());
            state.no_relay = version.no_relay;
            refresh_denuo_snapshot(&mut state, &denuo);
        }
        if update.became_ready {
            snapshot.write().await.state = PeerState::Ready;
            control_tx
                .send(Arc::new(Packet::SendHeaders))
                .await
                .map_err(|_| P2pError::PeerUnavailable(id))?;
            let version = handshake.remote_version().cloned().ok_or_else(|| {
                P2pError::Protocol("ready handshake has no remote version".to_owned())
            })?;
            events
                .send(PeerEvent::Ready { peer: id, version })
                .await
                .map_err(|_| P2pError::EventChannelClosed)?;
            let action = denuo.on_ready(Instant::now());
            admit_denuo_action(&mut denuo, action, &control_tx);
            let revoked = synchronize_hip76_with_denuo(&denuo, &mut hip76);
            complete_revoked_requesters(
                &mut pending_requesters,
                &revoked,
            );
            let mut state = snapshot.write().await;
            refresh_denuo_snapshot(&mut state, &denuo);
            state.hip76 = refresh_hip76_state(
                &hip76,
                provenance,
                &events,
                &hip76_writer_state_tx,
                &hip76_status_tx,
            );
        }

        if handshake.is_ready()
            && !matches!(
                &packet,
                Packet::Version(_) | Packet::Verack | Packet::Ping(_) | Packet::Pong(_)
            )
        {
            events
                .send(PeerEvent::Packet { peer: id, packet })
                .await
                .map_err(|_| P2pError::EventChannelClosed)?;
        }
        }
    }
    .await;
    let revoked = hip76.disconnect();
    complete_requester_ids(
        &mut pending_requesters,
        &revoked.requester_request_ids,
        || Hip76RequestOutcome::Disconnected,
    );
    for (_, pending) in pending_requesters {
        let _ = pending.completion.send(Hip76RequestOutcome::Disconnected);
    }
    fail_provider_ids(
        &mut pending_provider_writes,
        &revoked.provider_request_ids,
        Hip76FailureReason::Disconnected,
    );
    for (_, pending) in pending_provider_writes {
        let _ = pending.completion.send(Err(crate::Hip76Error {
            reason: Hip76FailureReason::Disconnected,
        }));
    }
    snapshot.write().await.hip76 = refresh_hip76_state(
        &hip76,
        provenance,
        &events,
        &hip76_writer_state_tx,
        &hip76_status_tx,
    );
    odoh.lock().await.disconnect(id);
    experimental.lock().await.disconnect(id);
    let routes = hnsr.lock().await.disconnect(id);
    dispatch_hnsr_incoming(
        &hnsr,
        &peers,
        &events,
        HnsrIncoming {
            relay_routes: routes,
            ..HnsrIncoming::default()
        },
        critical_write_timeout,
    )
    .await;
    result
}

fn synchronize_hip76_with_denuo(
    denuo: &DenuoCoordinator,
    hip76: &mut Hip76Session,
) -> Hip76RevokedWork {
    let diagnostics = denuo.diagnostics();
    if diagnostics.phase == DenuoPeerPhase::Negotiated {
        if let Some(negotiated) = diagnostics.negotiated {
            let mut revoked = match hip76.set_negotiated_resource_limits(
                negotiated.maximum_send_size,
                negotiated.maximum_live_requests,
            ) {
                Ok(revoked) => revoked,
                Err(error) => return hip76.disable_protocol(error.reason),
            };
            merge_revoked(&mut revoked, hip76.set_registry_negotiated(true));
            return revoked;
        }
    }
    hip76.set_registry_negotiated(false)
}

fn hnsr_peer_admission(
    peer: PeerId,
    address: SocketAddr,
    direction: PeerDirection,
    transport: PeerTransportKind,
    authenticated_remote_static: Option<AuthenticatedPeerKey>,
    handshake: &PeerHandshake,
    denuo: &DenuoCoordinator,
) -> Option<HnsrPeerAdmission> {
    let remote_services = handshake.remote_version()?.services;
    let (wire_profile, negotiated) = denuo.negotiated_evidence()?;
    handshake.is_ready().then(|| HnsrPeerAdmission {
        peer,
        address,
        direction,
        transport,
        authenticated_remote_static,
        remote_services,
        wire_profile,
        negotiated: negotiated.clone(),
    })
}

async fn dispatch_hnsr_incoming(
    coordinator: &Arc<Mutex<HnsrCoordinator>>,
    peers: &Arc<RwLock<HashMap<PeerId, PeerHandle>>>,
    events: &mpsc::Sender<PeerEvent>,
    incoming: HnsrIncoming,
    maximum_wait: Duration,
) {
    if let Some(event) = incoming.requester_event {
        let _ = events.try_send(PeerEvent::HnsrRequester { event });
    }
    let mut relay_routes = VecDeque::from(incoming.relay_routes);
    for route in incoming.direct_routes {
        let Ok(destination) = peer_id_from_hnsr(&route.destination) else {
            continue;
        };
        let handle = peers.read().await.get(&destination).cloned();
        let delivered = match (handle.as_ref(), crate::hnsr_packet(route.packet)) {
            (Some(handle), Ok(packet)) => handle
                .send_critical(Arc::new(packet), maximum_wait)
                .await
                .is_ok(),
            _ => false,
        };
        if !delivered {
            if let Some(handle) = handle {
                handle.disconnect();
            }
            relay_routes.extend(coordinator.lock().await.fault_peer(destination));
        }
    }
    let mut dispatched = 0usize;
    while let Some(queued) = relay_routes.pop_front() {
        dispatched = dispatched.saturating_add(1);
        if dispatched > 65_536 {
            break;
        }
        let destination = peer_id_from_hnsr(&queued.route.destination);
        let handle = match destination {
            Ok(destination) => peers.read().await.get(&destination).cloned(),
            Err(_) => None,
        };
        let delivered = match (handle.as_ref(), crate::hnsr_packet(queued.route.packet)) {
            (Some(handle), Ok(packet)) => handle
                .send_critical(Arc::new(packet), maximum_wait)
                .await
                .is_ok(),
            _ => false,
        };
        if !delivered {
            if let Some(handle) = handle {
                handle.disconnect();
            }
        }
        if let Ok(cleanup) = coordinator
            .lock()
            .await
            .acknowledge_relay_action(queued.action_id, delivered)
        {
            relay_routes.extend(cleanup);
        }
    }
}

fn handle_hip76_command(
    peer: PeerId,
    hip76: &mut Hip76Session,
    command: Hip76Command,
    wire_tx: &mpsc::Sender<Hip76WireOutbound>,
    pending_requesters: &mut BTreeMap<u64, PendingRequester>,
    pending_provider_writes: &mut BTreeMap<Hip76WriteToken, PendingProviderWrite>,
) {
    match command {
        Hip76Command::BeginRequest { query, completion } => {
            let result = hip76
                .begin_request(query, Instant::now())
                .and_then(|outbound| {
                    let work_token = outbound.work_token();
                    let admission = Hip76RequestAdmission {
                        request_id: outbound.request_id,
                        generation: outbound.generation,
                        deadline: outbound.deadline,
                    };
                    let wire = Hip76WireOutbound {
                        packet: Arc::new(outbound.packet),
                        request_id: admission.request_id,
                        generation: admission.generation,
                        deadline: admission.deadline,
                        kind: Hip76WireKind::Requester { work_token },
                    };
                    if wire_tx.try_send(wire).is_err() {
                        let _ = hip76.cancel_outbound_request(work_token);
                        return Err(hip76.reject(Hip76FailureReason::LocalSendUnavailable));
                    }
                    hip76.outbound_request_queue_admitted(work_token)?;
                    let (outcome, outcome_rx) = oneshot::channel();
                    pending_requesters.insert(
                        admission.request_id,
                        PendingRequester {
                            generation: admission.generation,
                            work_token,
                            completion: outcome,
                        },
                    );
                    Ok(Hip76PendingRequest {
                        admission,
                        peer,
                        outcome: outcome_rx,
                    })
                });
            let _ = completion.send(result);
        }
        Hip76Command::FinishProviderRequest {
            work,
            status,
            response,
            completion,
        } => {
            if let Err((completion, error)) = queue_provider_response(
                hip76,
                work,
                status,
                response,
                wire_tx,
                Some(completion),
                pending_provider_writes,
            ) {
                let _ = completion.send(Err(error));
            }
        }
        Hip76Command::ReplacePolicy {
            requester,
            provider,
            generation,
            completion,
        } => {
            let result = hip76.replace_policy(requester, provider, generation);
            if let Ok(revoked) = &result {
                complete_revoked_requesters(pending_requesters, revoked);
                fail_provider_ids(
                    pending_provider_writes,
                    &revoked.provider_request_ids,
                    Hip76FailureReason::StaleGeneration,
                );
            }
            let _ = completion.send(result);
        }
        Hip76Command::Revoke {
            generation,
            completion,
        } => {
            let result = hip76.revoke(generation);
            if let Ok(revoked) = &result {
                complete_revoked_requesters(pending_requesters, revoked);
                fail_provider_ids(
                    pending_provider_writes,
                    &revoked.provider_request_ids,
                    Hip76FailureReason::Revoked,
                );
            }
            let _ = completion.send(result);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn queue_provider_response(
    hip76: &mut Hip76Session,
    work: Hip76ProviderWork,
    status: DnsRelayStatus,
    response: Vec<u8>,
    wire_tx: &mpsc::Sender<Hip76WireOutbound>,
    completion: Option<oneshot::Sender<Result<(), crate::Hip76Error>>>,
    pending_provider_writes: &mut BTreeMap<Hip76WriteToken, PendingProviderWrite>,
) -> Result<
    (),
    (
        oneshot::Sender<Result<(), crate::Hip76Error>>,
        crate::Hip76Error,
    ),
> {
    let request_id = work.request_id();
    let generation = work.generation();
    let work_token = work.work_token();
    let now = Instant::now();
    let outbound = match hip76.prepare_provider_response(&work, status, response, now) {
        Ok(outbound) => outbound,
        Err(error) => {
            return match completion {
                Some(completion) => Err((completion, error)),
                None => {
                    if severe_hip76_failure(error.reason) {
                        hip76.disable_protocol(error.reason);
                    }
                    Ok(())
                }
            };
        }
    };
    let wire = Hip76WireOutbound {
        packet: Arc::new(outbound.packet),
        request_id,
        generation,
        deadline: outbound.deadline,
        kind: Hip76WireKind::Provider { work_token },
    };
    if wire_tx.try_send(wire).is_err() {
        let _ = hip76.outbound_queue_rejected(work_token);
        let error = hip76.reject(Hip76FailureReason::LocalSendUnavailable);
        return match completion {
            Some(completion) => Err((completion, error)),
            None => Ok(()),
        };
    }
    if let Err(error) = hip76.commit_provider_response(work, now) {
        return match completion {
            Some(completion) => Err((completion, error)),
            None => {
                hip76.disable_protocol(error.reason);
                Ok(())
            }
        };
    }
    if let Some(completion) = completion {
        pending_provider_writes.insert(
            work_token,
            PendingProviderWrite {
                request_id,
                generation,
                completion,
            },
        );
    }
    Ok(())
}

fn handle_hip76_frame(
    hip76: &mut Hip76Session,
    frame: &Frame,
    provenance: Hip76PeerProvenance,
    events: &mpsc::Sender<PeerEvent>,
    wire_tx: &mpsc::Sender<Hip76WireOutbound>,
    pending_requesters: &mut BTreeMap<u64, PendingRequester>,
) {
    match hip76.receive_frame(frame, Instant::now()) {
        Ok(Hip76Inbound::ProviderRequest(request)) => {
            if let Err(error) = events.try_send(PeerEvent::Hip76ProviderRequest {
                provenance,
                request,
            }) {
                let PeerEvent::Hip76ProviderRequest { request, .. } = error.into_inner() else {
                    unreachable!("failed event preserves provider request")
                };
                let (work, _) = request.into_parts();
                let _ = queue_provider_response(
                    hip76,
                    work,
                    DnsRelayStatus::Busy,
                    Vec::new(),
                    wire_tx,
                    None,
                    &mut BTreeMap::new(),
                );
            }
        }
        Ok(Hip76Inbound::ProviderRejection(response)) => {
            let request_id = response.request_id;
            let generation = response.generation;
            let deadline = response.deadline;
            let (packet, work_token) = response.into_parts();
            let wire = Hip76WireOutbound {
                request_id,
                generation,
                deadline,
                kind: Hip76WireKind::ProviderRejection { work_token },
                packet: Arc::new(packet),
            };
            if wire_tx.try_send(wire).is_err() {
                let _ = hip76.outbound_queue_rejected(work_token);
                let _ = hip76.reject(Hip76FailureReason::LocalSendUnavailable);
            } else {
                let _ = hip76.provider_rejection_queue_admitted(work_token);
            }
        }
        Ok(Hip76Inbound::RequesterResponse(response)) => {
            if let Some(pending) = pending_requesters.remove(&response.request_id) {
                let _ = pending.completion.send(Hip76RequestOutcome::Response {
                    provenance,
                    response,
                });
            }
        }
        Err(error) => {
            if severe_hip76_failure(error.reason) {
                let revoked = hip76.disable_protocol(error.reason);
                complete_revoked_requesters(pending_requesters, &revoked);
            }
        }
    }
}

fn handle_hip76_write_result(
    hip76: &mut Hip76Session,
    result: Hip76WriteResult,
    pending_requesters: &mut BTreeMap<u64, PendingRequester>,
    pending_provider_writes: &mut BTreeMap<Hip76WriteToken, PendingProviderWrite>,
) {
    match result.kind {
        Hip76WireKind::Requester { work_token } => {
            let unavailable = match result.disposition {
                Hip76WriteDisposition::Written => {
                    let _ = hip76.outbound_socket_written(work_token);
                    false
                }
                Hip76WriteDisposition::DroppedStale => {
                    let _ = hip76.cancel_outbound_request(work_token);
                    let _ = hip76.outbound_write_dropped(work_token);
                    true
                }
                Hip76WriteDisposition::Failed => {
                    let _ = hip76.cancel_outbound_request(work_token);
                    let _ = hip76.outbound_socket_failed(work_token);
                    true
                }
            };
            let matching_pending = unavailable
                && pending_requesters
                    .get(&result.request_id)
                    .is_some_and(|pending| {
                        pending.generation == result.generation && pending.work_token == work_token
                    });
            if matching_pending {
                let pending = pending_requesters
                    .remove(&result.request_id)
                    .expect("matching requester admission remains pending");
                let _ = pending
                    .completion
                    .send(Hip76RequestOutcome::LocalSendUnavailable);
            }
        }
        Hip76WireKind::Provider { work_token } => {
            match result.disposition {
                Hip76WriteDisposition::Written => {
                    let _ = hip76.outbound_socket_written(work_token);
                }
                Hip76WriteDisposition::DroppedStale => {
                    let _ = hip76.outbound_write_dropped(work_token);
                }
                Hip76WriteDisposition::Failed => {
                    let _ = hip76.outbound_socket_failed(work_token);
                }
            }
            if pending_provider_writes
                .get(&work_token)
                .is_some_and(|pending| {
                    pending.request_id == result.request_id
                        && pending.generation == result.generation
                })
            {
                if let Some(pending) = pending_provider_writes.remove(&work_token) {
                    let completion = match result.disposition {
                        Hip76WriteDisposition::Written => Ok(()),
                        Hip76WriteDisposition::DroppedStale | Hip76WriteDisposition::Failed => {
                            Err(crate::Hip76Error {
                                reason: Hip76FailureReason::LocalSendUnavailable,
                            })
                        }
                    };
                    let _ = pending.completion.send(completion);
                }
            }
        }
        Hip76WireKind::ProviderRejection { work_token } => match result.disposition {
            Hip76WriteDisposition::Written => {
                let _ = hip76.outbound_socket_written(work_token);
            }
            Hip76WriteDisposition::DroppedStale => {
                let _ = hip76.outbound_write_dropped(work_token);
            }
            Hip76WriteDisposition::Failed => {
                let _ = hip76.outbound_socket_failed(work_token);
            }
        },
    }
}

fn refresh_hip76_state(
    hip76: &Hip76Session,
    provenance: Hip76PeerProvenance,
    events: &mpsc::Sender<PeerEvent>,
    writer_state: &watch::Sender<Hip76WriterState>,
    status: &watch::Sender<Hip76SessionDiagnostics>,
) -> Hip76SessionDiagnostics {
    let diagnostics = hip76.diagnostics();
    let previous = status.borrow().clone();
    let capability_changed = previous.phase != diagnostics.phase
        || previous.requester_eligible != diagnostics.requester_eligible
        || previous.provider_available != diagnostics.provider_available
        || previous.maximum_live_requests != diagnostics.maximum_live_requests
        || previous.maximum_send_size != diagnostics.maximum_send_size;
    let _ = writer_state.send(Hip76WriterState::from_diagnostics(&diagnostics));
    let _ = status.send(diagnostics.clone());
    if capability_changed {
        let _ = events.try_send(PeerEvent::Hip76CapabilityChanged {
            provenance,
            diagnostics: diagnostics.clone(),
        });
    }
    diagnostics
}

fn complete_revoked_requesters(
    pending: &mut BTreeMap<u64, PendingRequester>,
    revoked: &Hip76RevokedWork,
) {
    complete_requester_ids(pending, &revoked.requester_request_ids, || {
        Hip76RequestOutcome::Revoked
    });
}

fn complete_requester_ids(
    pending: &mut BTreeMap<u64, PendingRequester>,
    request_ids: &[u64],
    outcome: impl Fn() -> Hip76RequestOutcome,
) {
    for request_id in request_ids {
        if let Some(pending) = pending.remove(request_id) {
            let _ = pending.completion.send(outcome());
        }
    }
}

fn fail_provider_ids(
    pending: &mut BTreeMap<Hip76WriteToken, PendingProviderWrite>,
    request_ids: &[u64],
    reason: Hip76FailureReason,
) {
    let tokens = pending
        .iter()
        .filter_map(|(token, work)| request_ids.contains(&work.request_id).then_some(*token))
        .collect::<Vec<_>>();
    for token in tokens {
        if let Some(pending) = pending.remove(&token) {
            let _ = pending.completion.send(Err(crate::Hip76Error { reason }));
        }
    }
}

fn merge_revoked(target: &mut Hip76RevokedWork, mut other: Hip76RevokedWork) {
    target
        .requester_request_ids
        .append(&mut other.requester_request_ids);
    target
        .provider_request_ids
        .append(&mut other.provider_request_ids);
}

const fn severe_hip76_failure(reason: Hip76FailureReason) -> bool {
    matches!(
        reason,
        Hip76FailureReason::ProviderNotOptedIn
            | Hip76FailureReason::LocalProviderNotAdvertised
            | Hip76FailureReason::RemoteProviderNotAdvertised
            | Hip76FailureReason::RegistryNotNegotiated
            | Hip76FailureReason::PeerFaulted
            | Hip76FailureReason::RequestTooLarge
            | Hip76FailureReason::ResponseTooLarge
            | Hip76FailureReason::MalformedRequest
            | Hip76FailureReason::MalformedResponse
            | Hip76FailureReason::InvalidDnsResponse
            | Hip76FailureReason::DnsCorrelationMismatch
            | Hip76FailureReason::DuplicateOrReplay
            | Hip76FailureReason::UncorrelatedResponse
            | Hip76FailureReason::UnexpectedPacket
    )
}

fn admit_denuo_action(
    denuo: &mut DenuoCoordinator,
    action: DenuoAction,
    control_tx: &mpsc::Sender<Arc<Packet>>,
) {
    match (action.response_payload, action.outbound_message) {
        (Some(payload), Some(message)) => {
            if control_tx
                .try_send(Arc::new(extension_packet(payload)))
                .is_ok()
            {
                denuo.outbound_admitted(message, Instant::now());
            } else {
                // Queue pressure or a closed writer is scoped to Denuo. The
                // ordinary peer reader remains available and never blocks on
                // experimental response admission.
                denuo.outbound_rejected();
            }
        }
        (None, None) => {}
        _ => {
            debug_assert!(false, "Denuo action payload/message mismatch");
            denuo.outbound_rejected();
        }
    }
}

enum PeerWriterOutbound {
    Ordinary {
        packet: Arc<Packet>,
        completion: Option<oneshot::Sender<Result<(), String>>>,
    },
    Hip76(Hip76WireOutbound),
}

async fn peer_writer<W>(
    mut writer: PeerFrameWriter<W>,
    snapshot: Arc<RwLock<PeerSnapshot>>,
    mut critical_rx: mpsc::Receiver<CriticalOutbound>,
    mut control_rx: mpsc::Receiver<Arc<Packet>>,
    mut normal_rx: mpsc::Receiver<Arc<Packet>>,
    hip76: Hip76WriterChannels,
) -> Result<(), P2pError>
where
    W: AsyncWrite + Unpin,
{
    let Hip76WriterChannels {
        outbound: mut hip76_rx,
        results: hip76_write_results,
        state: hip76_writer_state,
    } = hip76;
    let mut critical_open = true;
    let mut control_open = true;
    let mut normal_open = true;
    let mut hip76_open = true;

    while critical_open || control_open || normal_open || hip76_open {
        let outgoing = tokio::select! {
            biased;
            item = critical_rx.recv(), if critical_open => {
                match item {
                    Some(item) => Some(PeerWriterOutbound::Ordinary {
                        packet: item.packet,
                        completion: item.completion,
                    }),
                    None => { critical_open = false; None }
                }
            }
            packet = control_rx.recv(), if control_open => {
                match packet {
                    Some(packet) => Some(PeerWriterOutbound::Ordinary {
                        packet,
                        completion: None,
                    }),
                    None => { control_open = false; None }
                }
            }
            outbound = hip76_rx.recv(), if hip76_open => {
                match outbound {
                    Some(outbound) => Some(PeerWriterOutbound::Hip76(outbound)),
                    None => { hip76_open = false; None }
                }
            }
            packet = normal_rx.recv(), if normal_open => {
                match packet {
                    Some(packet) => Some(PeerWriterOutbound::Ordinary {
                        packet,
                        completion: None,
                    }),
                    None => { normal_open = false; None }
                }
            }
        };

        let Some(outgoing) = outgoing else {
            continue;
        };
        let (packet, completion, hip76_metadata) = match outgoing {
            PeerWriterOutbound::Ordinary { packet, completion } => {
                if completion
                    .as_ref()
                    .is_some_and(tokio::sync::oneshot::Sender::is_closed)
                {
                    // The bounded caller stopped waiting before this item
                    // reached the writer. Do not put abandoned critical work
                    // on the wire.
                    continue;
                }
                if is_registry_hello_packet(&packet)
                    && snapshot.read().await.denuo.phase != DenuoPeerPhase::HelloAdmitted
                {
                    // HELLO admission starts the negotiation deadline. If it
                    // expires while queued, never put the stale request on wire.
                    if let Some(completion) = completion {
                        let _ = completion.send(Err(
                            "stale Denuo registry HELLO was dropped before socket write".to_owned(),
                        ));
                    }
                    continue;
                }
                (packet, completion, None)
            }
            PeerWriterOutbound::Hip76(outbound) => {
                if !hip76_writer_state
                    .borrow()
                    .admits(&outbound, Instant::now())
                {
                    let _ = hip76_write_results
                        .send(Hip76WriteResult {
                            request_id: outbound.request_id,
                            generation: outbound.generation,
                            kind: outbound.kind,
                            disposition: Hip76WriteDisposition::DroppedStale,
                        })
                        .await;
                    continue;
                }
                (Arc::clone(&outbound.packet), None, Some(outbound))
            }
        };
        let bytes = match writer.write_packet(&packet).await {
            Ok(bytes) => bytes,
            Err(error) => {
                if let Some(outbound) = hip76_metadata {
                    let _ = hip76_write_results
                        .send(Hip76WriteResult {
                            request_id: outbound.request_id,
                            generation: outbound.generation,
                            kind: outbound.kind,
                            disposition: Hip76WriteDisposition::Failed,
                        })
                        .await;
                }
                if let Some(completion) = completion {
                    let _ = completion.send(Err(error.to_string()));
                }
                return Err(error);
            }
        };
        {
            let mut state = snapshot.write().await;
            state.last_send = Some(unix_time());
            state.bytes_sent = state.bytes_sent.saturating_add(bytes as u64);
        }
        if let Some(outbound) = hip76_metadata {
            let _ = hip76_write_results
                .send(Hip76WriteResult {
                    request_id: outbound.request_id,
                    generation: outbound.generation,
                    kind: outbound.kind,
                    disposition: Hip76WriteDisposition::Written,
                })
                .await;
        }
        if let Some(completion) = completion {
            let _ = completion.send(Ok(()));
        }
    }
    Ok(())
}

fn handshake_nonce_seed(peer: PeerId) -> [u8; 8] {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    now.rotate_left(17).wrapping_add(peer.0).to_le_bytes()
}

fn denuo_request_id(peer: PeerId, local_nonce: [u8; 8]) -> u64 {
    let request_id = u64::from_le_bytes(local_nonce) ^ peer.0.rotate_left(29);
    request_id.max(1)
}

fn encode_peer_key(bytes: [u8; 33]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(66);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

const fn decode_hex(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        denuo::DenuoDisableReason,
        wire::{encode_frame, Frame, NetAddress, PacketType},
        PROTOCOL_VERSION, SERVICE_NETWORK,
    };
    use hns_p2p_experimental::{
        DENUO_EXTENSION_MAX_PACKET_PAYLOAD, DENUO_EXTENSION_PACKET, DENUO_EXTENSION_SERVICE,
    };
    use tokio::io::{duplex, AsyncWriteExt};

    fn test_version(nonce: [u8; 8]) -> VersionPacket {
        test_version_with_services(nonce, SERVICE_NETWORK)
    }

    fn test_version_with_services(nonce: [u8; 8], services: u64) -> VersionPacket {
        VersionPacket {
            version: PROTOCOL_VERSION,
            services,
            time: 1_700_000_000,
            remote: NetAddress::default(),
            nonce,
            agent: "/hsrd-runtime-test/".to_owned(),
            height: 10,
            no_relay: false,
        }
    }

    fn test_hip76(direction: PeerDirection, local_services: u64) -> Hip76Session {
        Hip76Session::new(
            direction,
            local_services,
            0,
            false,
            Hip76SessionConfig::default(),
        )
        .expect("HIP-76 test session")
    }

    fn test_writer_channels(direction: PeerDirection) -> Hip76WriterChannels {
        let (_wire_tx, wire_rx) = mpsc::channel(1);
        let (result_tx, _result_rx) = mpsc::channel(1);
        let diagnostics = Hip76SessionDiagnostics::awaiting_registry(direction);
        let (_state_tx, state_rx) =
            watch::channel(Hip76WriterState::from_diagnostics(&diagnostics));
        Hip76WriterChannels {
            outbound: wire_rx,
            results: result_tx,
            state: state_rx,
        }
    }

    struct TestHip76ReaderChannels {
        commands: mpsc::Receiver<Hip76Command>,
        wire: mpsc::Sender<Hip76WireOutbound>,
        write_results: mpsc::Receiver<Hip76WriteResult>,
        writer_state: watch::Sender<Hip76WriterState>,
        status: watch::Sender<Hip76SessionDiagnostics>,
    }

    fn test_reader_channels(direction: PeerDirection) -> TestHip76ReaderChannels {
        let (_command_tx, command_rx) = mpsc::channel(1);
        let (wire_tx, _wire_rx) = mpsc::channel(1);
        let (_result_tx, result_rx) = mpsc::channel(1);
        let diagnostics = Hip76SessionDiagnostics::awaiting_registry(direction);
        let (writer_state_tx, _writer_state_rx) =
            watch::channel(Hip76WriterState::from_diagnostics(&diagnostics));
        let (status_tx, _status_rx) = watch::channel(diagnostics);
        TestHip76ReaderChannels {
            commands: command_rx,
            wire: wire_tx,
            write_results: result_rx,
            writer_state: writer_state_tx,
            status: status_tx,
        }
    }

    #[test]
    fn full_control_queue_disables_only_denuo_admission() {
        let services = SERVICE_NETWORK | DENUO_EXTENSION_SERVICE.value();
        let mut denuo = DenuoCoordinator::new(
            PeerDirection::Outbound,
            Network::Regtest,
            services,
            7,
            Duration::from_secs(1),
            DenuoRuntimeMetrics::default(),
        )
        .expect("Denuo coordinator");
        denuo.observe_remote_services(services);
        let action = denuo.on_ready(Instant::now());
        let (control_tx, _control_rx) = mpsc::channel(1);
        control_tx
            .try_send(Arc::new(Packet::SendHeaders))
            .expect("fill ordinary control queue");

        admit_denuo_action(&mut denuo, action, &control_tx);

        assert_eq!(denuo.diagnostics().phase, DenuoPeerPhase::Disabled);
        assert_eq!(
            denuo.diagnostics().disable_reason,
            Some(DenuoDisableReason::LocalSendUnavailable)
        );
    }

    #[tokio::test]
    async fn timed_out_queued_hello_is_dropped_but_ack_still_drains() {
        let services = SERVICE_NETWORK | DENUO_EXTENSION_SERVICE.value();
        let now = Instant::now();
        let mut outbound = DenuoCoordinator::new(
            PeerDirection::Outbound,
            Network::Regtest,
            services,
            7,
            Duration::from_millis(1),
            DenuoRuntimeMetrics::default(),
        )
        .expect("outbound coordinator");
        outbound.observe_remote_services(services);
        let hello_action = outbound.on_ready(now);
        let hello_payload = hello_action
            .response_payload
            .clone()
            .expect("registry hello");
        outbound.outbound_admitted(
            hello_action.outbound_message.expect("hello message kind"),
            now,
        );

        let mut inbound = DenuoCoordinator::new(
            PeerDirection::Inbound,
            Network::Regtest,
            services,
            8,
            Duration::from_secs(1),
            DenuoRuntimeMetrics::default(),
        )
        .expect("inbound coordinator");
        inbound.observe_remote_services(services);
        inbound.on_ready(now);
        let ack_payload = inbound
            .receive_extension(&hello_payload)
            .response_payload
            .expect("registry hello ack");
        let hello = Arc::new(extension_packet(hello_payload));
        let ack = Arc::new(extension_packet(ack_payload));
        assert!(is_registry_hello_packet(&hello));
        assert!(!is_registry_hello_packet(&ack));

        let deadline = outbound.pending_deadline().expect("admitted deadline");
        assert!(outbound.expire(deadline));
        let mut initial_snapshot = PeerSnapshot::new(
            PeerId(4),
            "127.0.0.1:12041".parse().expect("peer address"),
            PeerDirection::Outbound,
        );
        refresh_denuo_snapshot(&mut initial_snapshot, &outbound);
        let snapshot = Arc::new(RwLock::new(initial_snapshot));
        let (writer_io, reader_io) = duplex(64 * 1024);
        let (critical_tx, critical_rx) = mpsc::channel::<CriticalOutbound>(1);
        let (control_tx, control_rx) = mpsc::channel::<Arc<Packet>>(2);
        let (normal_tx, normal_rx) = mpsc::channel::<Arc<Packet>>(1);
        let writer = tokio::spawn(peer_writer(
            PeerFrameWriter::Plaintext(AsyncFrameWriter::new(writer_io, NetworkMagic::Regtest)),
            Arc::clone(&snapshot),
            critical_rx,
            control_rx,
            normal_rx,
            test_writer_channels(PeerDirection::Outbound),
        ));
        control_tx.send(hello).await.expect("queue stale hello");
        control_tx
            .send(Arc::clone(&ack))
            .await
            .expect("queue mismatch ack");
        drop(critical_tx);
        drop(control_tx);
        drop(normal_tx);

        let mut reader = AsyncFrameReader::new(reader_io, NetworkMagic::Regtest);
        assert_eq!(reader.read_packet().await.expect("written ack"), *ack);
        writer.await.expect("writer join").expect("writer result");
        assert!(snapshot.read().await.bytes_sent > 0);
    }

    #[tokio::test]
    async fn critical_completion_waits_for_peer_writer_socket_write() {
        let (writer_io, reader_io) = duplex(4_096);
        let (critical_tx, critical_rx) = mpsc::channel::<CriticalOutbound>(1);
        let (control_tx, control_rx) = mpsc::channel::<Arc<Packet>>(1);
        let (normal_tx, normal_rx) = mpsc::channel::<Arc<Packet>>(1);
        let snapshot = Arc::new(RwLock::new(PeerSnapshot::new(
            PeerId(1),
            "127.0.0.1:12038".parse().expect("peer address"),
            PeerDirection::Outbound,
        )));
        let writer = tokio::spawn(peer_writer(
            PeerFrameWriter::Plaintext(AsyncFrameWriter::new(writer_io, NetworkMagic::Regtest)),
            Arc::clone(&snapshot),
            critical_rx,
            control_rx,
            normal_rx,
            test_writer_channels(PeerDirection::Outbound),
        ));

        let packet = Arc::new(Packet::Ping([7; 8]));
        let (completion_tx, completion_rx) = oneshot::channel();
        critical_tx
            .send(CriticalOutbound {
                packet: Arc::clone(&packet),
                completion: Some(completion_tx),
            })
            .await
            .expect("critical item");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(1), completion_rx)
                .await
                .expect("completion timeout")
                .expect("completion channel"),
            Ok(())
        );

        let mut reader = AsyncFrameReader::new(reader_io, NetworkMagic::Regtest);
        assert_eq!(reader.read_packet().await.expect("packet"), *packet);
        assert!(snapshot.read().await.bytes_sent > 0);

        drop(critical_tx);
        drop(control_tx);
        drop(normal_tx);
        writer.await.expect("writer join").expect("writer result");
    }

    #[tokio::test]
    async fn maintenance_tick_does_not_cancel_a_partial_frame_read() {
        let (peer_io, mut remote_io) = duplex(256 * 1024);
        let (events_tx, mut events_rx) = mpsc::channel(8);
        let (control_tx, mut control_rx) = mpsc::channel(8);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let peer = PeerId(1);
        let snapshot = Arc::new(RwLock::new(PeerSnapshot::new(
            peer,
            "127.0.0.1:12038".parse().expect("peer address"),
            PeerDirection::Inbound,
        )));
        let config = PeerRuntimeConfig {
            handshake_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(1),
            ping_interval: Duration::from_millis(20),
            pong_timeout: Duration::from_millis(200),
            ..PeerRuntimeConfig::default()
        };
        let denuo = DenuoCoordinator::new(
            PeerDirection::Inbound,
            Network::Regtest,
            SERVICE_NETWORK,
            7,
            config.denuo_negotiation_timeout,
            DenuoRuntimeMetrics::default(),
        )
        .expect("Denuo coordinator");
        let TestHip76ReaderChannels {
            commands: hip76_rx,
            wire: hip76_wire_tx,
            write_results: hip76_write_result_rx,
            writer_state: hip76_writer_state_tx,
            status: hip76_status_tx,
        } = test_reader_channels(PeerDirection::Inbound);
        let reader = tokio::spawn(peer_reader(
            peer,
            PeerDirection::Inbound,
            test_version([1; 8]),
            denuo,
            test_hip76(PeerDirection::Inbound, SERVICE_NETWORK),
            PeerTransportKind::Plaintext,
            None,
            PeerFrameReader::Plaintext(AsyncFrameReader::new(peer_io, NetworkMagic::Regtest)),
            config,
            events_tx,
            Arc::clone(&snapshot),
            control_tx,
            hip76_rx,
            hip76_wire_tx,
            hip76_write_result_rx,
            hip76_writer_state_tx,
            hip76_status_tx,
            shutdown_rx,
        ));

        for packet in [Packet::Version(test_version([2; 8])), Packet::Verack] {
            let frame = Frame::from_packet(&packet).expect("handshake frame");
            remote_io
                .write_all(&encode_frame(NetworkMagic::Regtest, &frame).expect("handshake bytes"))
                .await
                .expect("write handshake");
        }
        let ready = tokio::time::timeout(Duration::from_secs(1), events_rx.recv())
            .await
            .expect("ready timeout")
            .expect("ready event");
        assert!(matches!(ready, PeerEvent::Ready { peer: target, .. } if target == peer));

        let packet = Packet::Unknown {
            packet_type: PacketType::Unknown(250),
            payload: vec![0x5a; 128 * 1024],
        };
        let frame = Frame::from_packet(&packet).expect("large frame");
        let encoded = encode_frame(NetworkMagic::Regtest, &frame).expect("large frame bytes");
        let split = crate::constants::FRAME_HEADER_SIZE + 64;
        remote_io
            .write_all(&encoded[..split])
            .await
            .expect("write partial frame");
        tokio::time::sleep(Duration::from_millis(30)).await;
        remote_io
            .write_all(&encoded[split..])
            .await
            .expect("finish partial frame");

        let received = tokio::time::timeout(Duration::from_secs(1), events_rx.recv())
            .await
            .expect("packet timeout")
            .expect("packet event");
        assert!(matches!(
            received,
            PeerEvent::Packet {
                peer: target,
                packet: received,
            } if target == peer && received == packet
        ));
        assert!((0..4).any(
            |_| matches!(control_rx.try_recv(), Ok(packet) if matches!(&*packet, Packet::Ping(_)))
        ));

        shutdown_tx.send(true).expect("shutdown reader");
        assert!(matches!(
            reader.await.expect("reader join"),
            Err(P2pError::Disconnected(_))
        ));
    }

    #[tokio::test]
    async fn early_denuo_packet_is_scoped_and_handshake_remains_available() {
        let (peer_io, mut remote_io) = duplex(64 * 1024);
        let (events_tx, mut events_rx) = mpsc::channel(8);
        let (control_tx, _control_rx) = mpsc::channel(8);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let peer = PeerId(2);
        let services = SERVICE_NETWORK | DENUO_EXTENSION_SERVICE.value();
        let snapshot = Arc::new(RwLock::new(PeerSnapshot::new(
            peer,
            "127.0.0.1:12039".parse().expect("peer address"),
            PeerDirection::Inbound,
        )));
        let config = PeerRuntimeConfig {
            handshake_timeout: Duration::from_secs(1),
            idle_timeout: Duration::from_secs(1),
            ping_interval: Duration::from_secs(1),
            pong_timeout: Duration::from_secs(1),
            ..PeerRuntimeConfig::default()
        };
        let denuo = DenuoCoordinator::new(
            PeerDirection::Inbound,
            Network::Regtest,
            services,
            9,
            config.denuo_negotiation_timeout,
            DenuoRuntimeMetrics::default(),
        )
        .expect("Denuo coordinator");
        let TestHip76ReaderChannels {
            commands: hip76_rx,
            wire: hip76_wire_tx,
            write_results: hip76_write_result_rx,
            writer_state: hip76_writer_state_tx,
            status: hip76_status_tx,
        } = test_reader_channels(PeerDirection::Inbound);
        let reader = tokio::spawn(peer_reader(
            peer,
            PeerDirection::Inbound,
            test_version_with_services([3; 8], services),
            denuo,
            test_hip76(PeerDirection::Inbound, services),
            PeerTransportKind::Plaintext,
            None,
            PeerFrameReader::Plaintext(AsyncFrameReader::new(peer_io, NetworkMagic::Regtest)),
            config,
            events_tx,
            Arc::clone(&snapshot),
            control_tx,
            hip76_rx,
            hip76_wire_tx,
            hip76_write_result_rx,
            hip76_writer_state_tx,
            hip76_status_tx,
            shutdown_rx,
        ));

        for packet in [
            extension_packet(vec![0xde, 0xad]),
            Packet::Version(test_version_with_services([4; 8], services)),
            Packet::Verack,
        ] {
            let frame = Frame::from_packet(&packet).expect("frame");
            remote_io
                .write_all(&encode_frame(NetworkMagic::Regtest, &frame).expect("frame bytes"))
                .await
                .expect("write frame");
        }

        let ready = tokio::time::timeout(Duration::from_secs(1), events_rx.recv())
            .await
            .expect("ready timeout")
            .expect("ready event");
        assert!(matches!(ready, PeerEvent::Ready { peer: target, .. } if target == peer));
        let state = snapshot.read().await.clone();
        assert_eq!(state.state, PeerState::Ready);
        assert_eq!(state.denuo.phase, DenuoPeerPhase::Disabled);
        assert_eq!(
            state.denuo.disable_reason,
            Some(DenuoDisableReason::UnexpectedMessage)
        );

        let ordinary = Packet::GetAddr;
        let frame = Frame::from_packet(&ordinary).expect("ordinary frame");
        remote_io
            .write_all(&encode_frame(NetworkMagic::Regtest, &frame).expect("ordinary bytes"))
            .await
            .expect("write ordinary frame");
        let received = tokio::time::timeout(Duration::from_secs(1), events_rx.recv())
            .await
            .expect("ordinary packet timeout")
            .expect("ordinary packet event");
        assert!(matches!(
            received,
            PeerEvent::Packet {
                peer: target,
                packet,
            } if target == peer && packet == ordinary
        ));

        shutdown_tx.send(true).expect("shutdown reader");
        assert!(matches!(
            reader.await.expect("reader join"),
            Err(P2pError::Disconnected(_))
        ));
    }

    #[tokio::test]
    async fn repeated_oversized_denuo_frames_do_not_close_a_ready_peer() {
        let (peer_io, mut remote_io) = duplex(128 * 1024);
        let (events_tx, mut events_rx) = mpsc::channel(8);
        let (control_tx, _control_rx) = mpsc::channel(8);
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let peer = PeerId(3);
        let services = SERVICE_NETWORK | DENUO_EXTENSION_SERVICE.value();
        let snapshot = Arc::new(RwLock::new(PeerSnapshot::new(
            peer,
            "127.0.0.1:12040".parse().expect("peer address"),
            PeerDirection::Inbound,
        )));
        let config = PeerRuntimeConfig {
            handshake_timeout: Duration::from_secs(2),
            idle_timeout: Duration::from_secs(5),
            ping_interval: Duration::from_secs(5),
            pong_timeout: Duration::from_secs(5),
            ..PeerRuntimeConfig::default()
        };
        let metrics = DenuoRuntimeMetrics::default();
        let denuo = DenuoCoordinator::new(
            PeerDirection::Inbound,
            Network::Regtest,
            services,
            10,
            config.denuo_negotiation_timeout,
            metrics.clone(),
        )
        .expect("Denuo coordinator");
        let TestHip76ReaderChannels {
            commands: hip76_rx,
            wire: hip76_wire_tx,
            write_results: hip76_write_result_rx,
            writer_state: hip76_writer_state_tx,
            status: hip76_status_tx,
        } = test_reader_channels(PeerDirection::Inbound);
        let reader = tokio::spawn(peer_reader(
            peer,
            PeerDirection::Inbound,
            test_version_with_services([5; 8], services),
            denuo,
            test_hip76(PeerDirection::Inbound, services),
            PeerTransportKind::Plaintext,
            None,
            PeerFrameReader::Plaintext(AsyncFrameReader::new(peer_io, NetworkMagic::Regtest)),
            config,
            events_tx,
            Arc::clone(&snapshot),
            control_tx,
            hip76_rx,
            hip76_wire_tx,
            hip76_write_result_rx,
            hip76_writer_state_tx,
            hip76_status_tx,
            shutdown_rx,
        ));

        for packet in [
            Packet::Version(test_version_with_services([6; 8], services)),
            Packet::Verack,
        ] {
            let frame = Frame::from_packet(&packet).expect("handshake frame");
            remote_io
                .write_all(&encode_frame(NetworkMagic::Regtest, &frame).expect("handshake bytes"))
                .await
                .expect("write handshake");
        }
        let ready = tokio::time::timeout(Duration::from_secs(2), events_rx.recv())
            .await
            .expect("ready timeout")
            .expect("ready event");
        assert!(matches!(ready, PeerEvent::Ready { peer: target, .. } if target == peer));

        let oversized = Frame::new(
            PacketType::Unknown(DENUO_EXTENSION_PACKET.value()),
            vec![0; DENUO_EXTENSION_MAX_PACKET_PAYLOAD + 1],
        )
        .expect("globally bounded extension frame");
        let oversized =
            encode_frame(NetworkMagic::Regtest, &oversized).expect("oversized extension bytes");
        remote_io
            .write_all(&oversized)
            .await
            .expect("write first oversized extension");
        remote_io
            .write_all(&oversized)
            .await
            .expect("write repeated oversized extension");

        let ordinary = Packet::GetAddr;
        let frame = Frame::from_packet(&ordinary).expect("ordinary frame");
        remote_io
            .write_all(&encode_frame(NetworkMagic::Regtest, &frame).expect("ordinary bytes"))
            .await
            .expect("write ordinary frame");
        let received = tokio::time::timeout(Duration::from_secs(3), events_rx.recv())
            .await
            .expect("ordinary packet timeout")
            .expect("ordinary packet event");
        assert!(matches!(
            received,
            PeerEvent::Packet {
                peer: target,
                packet,
            } if target == peer && packet == ordinary
        ));

        let state = snapshot.read().await.clone();
        assert_eq!(state.state, PeerState::Ready);
        assert_eq!(state.denuo.phase, DenuoPeerPhase::Disabled);
        assert_eq!(
            state.denuo.disable_reason,
            Some(DenuoDisableReason::PacketTooLarge)
        );
        let summary = metrics.summary(services, &[state.denuo]);
        assert_eq!(summary.process.disabled, 1);
        assert_eq!(summary.process.rejected, 2);
        assert_eq!(
            summary.rejection_reasons[DenuoDisableReason::PacketTooLarge.index()].count,
            2
        );

        shutdown_tx.send(true).expect("shutdown reader");
        assert!(matches!(
            reader.await.expect("reader join"),
            Err(P2pError::Disconnected(_))
        ));
    }
}
