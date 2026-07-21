use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{mpsc, oneshot, watch, RwLock},
    task::JoinHandle,
    time::{sleep_until, Instant, MissedTickBehavior},
};

use crate::{
    handshake::{PeerDirection, PeerHandshake, PeerState},
    wire::{AsyncFrameReader, AsyncFrameWriter, NetworkMagic, Packet, VersionPacket},
    P2pError,
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

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PeerSnapshot {
    pub id: PeerId,
    pub address: SocketAddr,
    pub direction: PeerDirection,
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
}

impl PeerSnapshot {
    pub fn new(id: PeerId, address: SocketAddr, direction: PeerDirection) -> Self {
        Self {
            id,
            address,
            direction,
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
        }
    }
}

#[derive(Clone, Debug)]
pub struct PeerRuntimeConfig {
    pub handshake_timeout: Duration,
    pub idle_timeout: Duration,
    pub ping_interval: Duration,
    pub pong_timeout: Duration,
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

#[derive(Clone, Debug)]
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
}

struct CriticalOutbound {
    packet: Arc<Packet>,
    completion: Option<oneshot::Sender<Result<(), String>>>,
}

#[derive(Clone, Debug)]
pub struct PeerHandle {
    pub(crate) id: PeerId,
    pub(crate) snapshot: Arc<RwLock<PeerSnapshot>>,
    critical_tx: mpsc::Sender<CriticalOutbound>,
    control_tx: mpsc::Sender<Arc<Packet>>,
    normal_tx: mpsc::Sender<Arc<Packet>>,
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
    pub magic: NetworkMagic,
    pub local_version: VersionPacket,
    pub config: PeerRuntimeConfig,
    pub events: mpsc::Sender<PeerEvent>,
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
    let PeerRuntimeParameters {
        id,
        address,
        direction,
        magic,
        local_version,
        config,
        events,
    } = parameters;
    config.validate()?;
    let (critical_tx, critical_rx) = mpsc::channel(config.critical_queue);
    let (control_tx, control_rx) = mpsc::channel(config.control_queue);
    let (normal_tx, normal_rx) = mpsc::channel(config.normal_queue);
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let snapshot = Arc::new(RwLock::new(PeerSnapshot::new(id, address, direction)));
    let handle = PeerHandle {
        id,
        snapshot: Arc::clone(&snapshot),
        critical_tx: critical_tx.clone(),
        control_tx: control_tx.clone(),
        normal_tx,
        shutdown_tx,
    };

    let task = tokio::spawn(run_peer(
        id,
        address,
        direction,
        magic,
        local_version,
        reader,
        writer,
        config,
        events,
        snapshot,
        critical_rx,
        control_rx,
        normal_rx,
        control_tx,
        shutdown_rx,
    ));

    Ok(SpawnedPeer { handle, task })
}

#[allow(clippy::too_many_arguments)]
async fn run_peer<R, W>(
    id: PeerId,
    address: SocketAddr,
    direction: PeerDirection,
    magic: NetworkMagic,
    local_version: VersionPacket,
    reader: R,
    writer: W,
    config: PeerRuntimeConfig,
    events: mpsc::Sender<PeerEvent>,
    snapshot: Arc<RwLock<PeerSnapshot>>,
    critical_rx: mpsc::Receiver<CriticalOutbound>,
    control_rx: mpsc::Receiver<Arc<Packet>>,
    normal_rx: mpsc::Receiver<Arc<Packet>>,
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
        AsyncFrameWriter::new(writer, magic),
        Arc::clone(&snapshot),
        critical_rx,
        control_rx,
        normal_rx,
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
        AsyncFrameReader::new(reader, magic),
        config,
        events,
        Arc::clone(&snapshot),
        control_tx,
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
    mut reader: AsyncFrameReader<R>,
    config: PeerRuntimeConfig,
    events: mpsc::Sender<PeerEvent>,
    snapshot: Arc<RwLock<PeerSnapshot>>,
    control_tx: mpsc::Sender<Arc<Packet>>,
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

    loop {
        let idle_deadline = last_receive + config.idle_timeout;
        let handshake_deadline = started + config.handshake_timeout;
        let deadline = if handshake.is_ready() {
            idle_deadline
        } else {
            idle_deadline.min(handshake_deadline)
        };

        tokio::select! {
            frame = reader.read_frame() => {
                let frame = frame?;
                last_receive = Instant::now();
                {
                    let mut state = snapshot.write().await;
                    state.last_receive = Some(unix_time());
                    state.bytes_received = state.bytes_received.saturating_add(
                        (crate::constants::FRAME_HEADER_SIZE + frame.payload.len()) as u64,
                    );
                }
                let packet = frame.decode_packet()?;
                if let Packet::Pong(nonce) = &packet {
                    if let Some((expected, sent)) = challenge {
                        if *nonce == expected {
                            let elapsed = sent.elapsed().as_millis();
                            snapshot.write().await.ping_millis = Some(elapsed.min(u128::from(u64::MAX)) as u64);
                            challenge = None;
                        }
                    }
                }

                let update = handshake.receive(&packet)?;
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
                }
                if update.became_ready {
                    snapshot.write().await.state = PeerState::Ready;
                    control_tx
                        .send(Arc::new(Packet::SendHeaders))
                        .await
                        .map_err(|_| P2pError::PeerUnavailable(id))?;
                    let version = handshake
                        .remote_version()
                        .cloned()
                        .ok_or_else(|| P2pError::Protocol("ready handshake has no remote version".to_owned()))?;
                    events
                        .send(PeerEvent::Ready { peer: id, version })
                        .await
                        .map_err(|_| P2pError::EventChannelClosed)?;
                }

                if handshake.is_ready()
                    && !matches!(&packet, Packet::Version(_) | Packet::Verack | Packet::Ping(_) | Packet::Pong(_))
                {
                    events
                        .send(PeerEvent::Packet { peer: id, packet })
                        .await
                        .map_err(|_| P2pError::EventChannelClosed)?;
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
}

async fn peer_writer<W>(
    mut writer: AsyncFrameWriter<W>,
    snapshot: Arc<RwLock<PeerSnapshot>>,
    mut critical_rx: mpsc::Receiver<CriticalOutbound>,
    mut control_rx: mpsc::Receiver<Arc<Packet>>,
    mut normal_rx: mpsc::Receiver<Arc<Packet>>,
) -> Result<(), P2pError>
where
    W: AsyncWrite + Unpin,
{
    let mut critical_open = true;
    let mut control_open = true;
    let mut normal_open = true;

    while critical_open || control_open || normal_open {
        let outgoing = tokio::select! {
            biased;
            item = critical_rx.recv(), if critical_open => {
                match item {
                    Some(item) => Some((item.packet, item.completion)),
                    None => { critical_open = false; None }
                }
            }
            packet = control_rx.recv(), if control_open => {
                match packet {
                    Some(packet) => Some((packet, None)),
                    None => { control_open = false; None }
                }
            }
            packet = normal_rx.recv(), if normal_open => {
                match packet {
                    Some(packet) => Some((packet, None)),
                    None => { normal_open = false; None }
                }
            }
        };

        let Some((packet, completion)) = outgoing else {
            continue;
        };
        let bytes = match writer.write_packet(&packet).await {
            Ok(bytes) => bytes,
            Err(error) => {
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

pub(crate) fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

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
            AsyncFrameWriter::new(writer_io, NetworkMagic::Regtest),
            Arc::clone(&snapshot),
            critical_rx,
            control_rx,
            normal_rx,
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
}
