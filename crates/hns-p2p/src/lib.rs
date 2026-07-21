#![forbid(unsafe_code)]

//! Bounded Handshake P2P codecs, peer sessions, and peer management.

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use hns_primitives::BlockHash;

pub mod constants;
pub mod handshake;
pub mod manager;
pub mod runtime;
pub mod wire;

pub use constants::*;
pub use handshake::{HandshakeUpdate, PeerDirection, PeerHandshake, PeerState};
pub use manager::{BroadcastReport, LivePeerConfig, LivePeerManager};
pub use runtime::{
    OutboundPriority, PeerEvent, PeerHandle, PeerId, PeerRuntimeConfig, PeerSnapshot,
};
pub use wire::{
    decode_frame, encode_frame, AddressHost, AsyncFrameReader, AsyncFrameWriter,
    AsyncPeerTransport, Frame, Inventory, InventoryKind, LocatorPacket, NetAddress, NetworkMagic,
    Packet, PacketType, RejectPacket, VersionPacket,
};

pub trait PeerManager {
    fn peers(&self) -> Result<Vec<PeerSnapshot>, P2pError>;

    fn broadcast_inventory(&self, inventory: Inventory) -> Result<(), P2pError>;

    fn request_block(&self, peer: PeerId, hash: BlockHash) -> Result<(), P2pError>;
}

/// Deterministic in-memory peer manager retained for tests and higher-level
/// composition. Live network behavior is implemented by [`LivePeerManager`].
#[derive(Clone, Debug, Default)]
pub struct MemoryPeerManager {
    inner: Arc<RwLock<MemoryPeerState>>,
}

impl MemoryPeerManager {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add_peer(&self, peer: PeerSnapshot) -> Result<(), P2pError> {
        self.inner
            .write()
            .map_err(|_| P2pError::State("peer manager write lock poisoned".to_owned()))?
            .peers
            .insert(peer.id, peer);
        Ok(())
    }

    pub fn announced_inventory(&self) -> Result<Vec<Inventory>, P2pError> {
        Ok(self
            .inner
            .read()
            .map_err(|_| P2pError::State("peer manager read lock poisoned".to_owned()))?
            .announced
            .clone())
    }

    pub fn block_requests(&self) -> Result<Vec<(PeerId, BlockHash)>, P2pError> {
        Ok(self
            .inner
            .read()
            .map_err(|_| P2pError::State("peer manager read lock poisoned".to_owned()))?
            .block_requests
            .clone())
    }
}

impl PeerManager for MemoryPeerManager {
    fn peers(&self) -> Result<Vec<PeerSnapshot>, P2pError> {
        let mut peers = self
            .inner
            .read()
            .map_err(|_| P2pError::State("peer manager read lock poisoned".to_owned()))?
            .peers
            .values()
            .cloned()
            .collect::<Vec<_>>();
        peers.sort_by_key(|peer| peer.id.0);
        Ok(peers)
    }

    fn broadcast_inventory(&self, inventory: Inventory) -> Result<(), P2pError> {
        self.inner
            .write()
            .map_err(|_| P2pError::State("peer manager write lock poisoned".to_owned()))?
            .announced
            .push(inventory);
        Ok(())
    }

    fn request_block(&self, peer: PeerId, hash: BlockHash) -> Result<(), P2pError> {
        let mut state = self
            .inner
            .write()
            .map_err(|_| P2pError::State("peer manager write lock poisoned".to_owned()))?;
        if !state.peers.contains_key(&peer) {
            return Err(P2pError::PeerUnavailable(peer));
        }
        state.block_requests.push((peer, hash));
        Ok(())
    }
}

#[derive(Clone, Debug, Default)]
struct MemoryPeerState {
    peers: HashMap<PeerId, PeerSnapshot>,
    announced: Vec<Inventory>,
    block_requests: Vec<(PeerId, BlockHash)>,
}

#[derive(Debug, thiserror::Error)]
pub enum P2pError {
    #[error("p2p configuration failed: {0}")]
    Configuration(String),
    #[error("p2p connection closed: {0}")]
    Disconnected(String),
    #[error("peer address {0} is already registered")]
    DuplicatePeer(SocketAddr),
    #[error("peer event channel is closed")]
    EventChannelClosed,
    #[error("{context} limit exceeded: limit {limit}, actual {actual}")]
    LimitExceeded {
        context: &'static str,
        limit: usize,
        actual: usize,
    },
    #[error("malformed frame: {0}")]
    MalformedFrame(String),
    #[error("malformed packet: {0}")]
    MalformedPacket(String),
    #[error("{direction:?} peer limit {limit} reached")]
    PeerLimit {
        direction: PeerDirection,
        limit: usize,
    },
    #[error("peer {0:?} is unavailable")]
    PeerUnavailable(PeerId),
    #[error("p2p protocol violation: {0}")]
    Protocol(String),
    #[error("peer {peer:?} {priority:?} queue is full")]
    QueueFull {
        peer: PeerId,
        priority: OutboundPriority,
    },
    #[error("peer {peer:?} {priority:?} queue timed out")]
    QueueTimeout {
        peer: PeerId,
        priority: OutboundPriority,
    },
    #[error("p2p state failed: {0}")]
    State(String),
    #[error("p2p task failed: {0}")]
    Task(String),
    #[error("p2p timeout: {0}")]
    Timeout(String),
    #[error("p2p io failed: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_primitives::Txid;

    #[test]
    fn memory_peer_manager_tracks_peers_and_requests() {
        let manager = MemoryPeerManager::new();
        let mut peer = PeerSnapshot::new(
            PeerId(1),
            "127.0.0.1:12038".parse().expect("address"),
            PeerDirection::Outbound,
        );
        peer.advertised_height = Some(10);
        manager.add_peer(peer).expect("add peer");
        manager
            .request_block(PeerId(1), BlockHash::new([3; 32]))
            .expect("request");
        manager
            .broadcast_inventory(Inventory::transaction(Txid::new([4; 32])))
            .expect("inventory");

        assert_eq!(manager.peers().expect("peers").len(), 1);
        assert_eq!(manager.block_requests().expect("requests").len(), 1);
        assert_eq!(manager.announced_inventory().expect("announced").len(), 1);
    }
}
