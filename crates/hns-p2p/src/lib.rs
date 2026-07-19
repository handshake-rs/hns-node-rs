#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, RwLock},
};

use hns_consensus::Network;
use hns_primitives::{BlockHash, Reader, Txid, Writer};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const FRAME_HEADER_SIZE: usize = 9;
pub const MAX_FRAME_PAYLOAD_SIZE: usize = 8_000_000;
pub const MAX_INVENTORY_ITEMS: usize = 50_000;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct PeerId(pub u64);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PeerSnapshot {
    pub id: PeerId,
    pub address: SocketAddr,
    pub advertised_height: Option<u32>,
    pub score: i32,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum NetworkMagic {
    Mainnet,
    Testnet,
    Regtest,
    Simnet,
}

impl NetworkMagic {
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Mainnet => 0x5b6e_f2d3,
            Self::Testnet => 0xb152_0dd2,
            Self::Regtest => 0xae38_95cf,
            Self::Simnet => 0x0e64_8edc,
        }
    }
}

impl From<Network> for NetworkMagic {
    fn from(network: Network) -> Self {
        match network {
            Network::Mainnet => Self::Mainnet,
            Network::Testnet => Self::Testnet,
            Network::Regtest => Self::Regtest,
            Network::Simnet => Self::Simnet,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum PacketType {
    Version,
    Verack,
    Ping,
    Pong,
    GetAddr,
    Addr,
    Inv,
    GetData,
    NotFound,
    GetBlocks,
    GetHeaders,
    Headers,
    SendHeaders,
    Block,
    Tx,
    Reject,
    Mempool,
    FilterLoad,
    FilterAdd,
    FilterClear,
    MerkleBlock,
    FeeFilter,
    SendCmpct,
    CmpctBlock,
    GetBlockTxn,
    BlockTxn,
    GetProof,
    Proof,
    Claim,
    Airdrop,
    Unknown(u8),
}

impl PacketType {
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Version => 0,
            Self::Verack => 1,
            Self::Ping => 2,
            Self::Pong => 3,
            Self::GetAddr => 4,
            Self::Addr => 5,
            Self::Inv => 6,
            Self::GetData => 7,
            Self::NotFound => 8,
            Self::GetBlocks => 9,
            Self::GetHeaders => 10,
            Self::Headers => 11,
            Self::SendHeaders => 12,
            Self::Block => 13,
            Self::Tx => 14,
            Self::Reject => 15,
            Self::Mempool => 16,
            Self::FilterLoad => 17,
            Self::FilterAdd => 18,
            Self::FilterClear => 19,
            Self::MerkleBlock => 20,
            Self::FeeFilter => 21,
            Self::SendCmpct => 22,
            Self::CmpctBlock => 23,
            Self::GetBlockTxn => 24,
            Self::BlockTxn => 25,
            Self::GetProof => 26,
            Self::Proof => 27,
            Self::Claim => 28,
            Self::Airdrop => 29,
            Self::Unknown(value) => value,
        }
    }

    pub const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Version,
            1 => Self::Verack,
            2 => Self::Ping,
            3 => Self::Pong,
            4 => Self::GetAddr,
            5 => Self::Addr,
            6 => Self::Inv,
            7 => Self::GetData,
            8 => Self::NotFound,
            9 => Self::GetBlocks,
            10 => Self::GetHeaders,
            11 => Self::Headers,
            12 => Self::SendHeaders,
            13 => Self::Block,
            14 => Self::Tx,
            15 => Self::Reject,
            16 => Self::Mempool,
            17 => Self::FilterLoad,
            18 => Self::FilterAdd,
            19 => Self::FilterClear,
            20 => Self::MerkleBlock,
            21 => Self::FeeFilter,
            22 => Self::SendCmpct,
            23 => Self::CmpctBlock,
            24 => Self::GetBlockTxn,
            25 => Self::BlockTxn,
            26 => Self::GetProof,
            27 => Self::Proof,
            28 => Self::Claim,
            29 => Self::Airdrop,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum InventoryKind {
    Transaction,
    Block,
    FilteredBlock,
    CompactBlock,
    Claim,
    Airdrop,
    Unknown(u32),
}

impl InventoryKind {
    pub const fn as_u32(self) -> u32 {
        match self {
            Self::Transaction => 1,
            Self::Block => 2,
            Self::FilteredBlock => 3,
            Self::CompactBlock => 4,
            Self::Claim => 5,
            Self::Airdrop => 6,
            Self::Unknown(value) => value,
        }
    }

    pub const fn from_u32(value: u32) -> Self {
        match value {
            1 => Self::Transaction,
            2 => Self::Block,
            3 => Self::FilteredBlock,
            4 => Self::CompactBlock,
            5 => Self::Claim,
            6 => Self::Airdrop,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Inventory {
    Block(BlockHash),
    Transaction(Txid),
    Unknown { kind: u32, hash: [u8; 32] },
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Frame {
    pub packet_type: PacketType,
    pub payload: Vec<u8>,
}

impl Frame {
    pub fn new(packet_type: PacketType, payload: Vec<u8>) -> Result<Self, P2pError> {
        if payload.len() > MAX_FRAME_PAYLOAD_SIZE {
            return Err(P2pError::MalformedFrame(format!(
                "payload exceeds {MAX_FRAME_PAYLOAD_SIZE} bytes"
            )));
        }

        Ok(Self {
            packet_type,
            payload,
        })
    }
}

pub trait PeerManager {
    fn peers(&self) -> Result<Vec<PeerSnapshot>, P2pError>;

    fn broadcast_inventory(&self, inventory: Inventory) -> Result<(), P2pError>;

    fn request_block(&self, peer: PeerId, hash: BlockHash) -> Result<(), P2pError>;
}

pub fn encode_frame(magic: NetworkMagic, frame: &Frame) -> Result<Vec<u8>, P2pError> {
    if frame.payload.len() > MAX_FRAME_PAYLOAD_SIZE {
        return Err(P2pError::MalformedFrame(format!(
            "payload exceeds {MAX_FRAME_PAYLOAD_SIZE} bytes"
        )));
    }

    let payload_len = u32::try_from(frame.payload.len())
        .map_err(|_| P2pError::MalformedFrame("payload length exceeds u32".to_owned()))?;
    let mut writer = Writer::with_capacity(FRAME_HEADER_SIZE + frame.payload.len());
    writer.write_u32(magic.as_u32());
    writer.write_u8(frame.packet_type.as_u8());
    writer.write_u32(payload_len);
    writer.write_bytes(&frame.payload);
    Ok(writer.finish())
}

pub fn decode_frame(magic: NetworkMagic, bytes: &[u8]) -> Result<Frame, P2pError> {
    let mut reader = Reader::new(bytes, FRAME_HEADER_SIZE + MAX_FRAME_PAYLOAD_SIZE)
        .map_err(|error| P2pError::MalformedFrame(error.to_string()))?;
    let actual_magic = reader
        .read_u32()
        .map_err(|error| P2pError::MalformedFrame(error.to_string()))?;

    if actual_magic != magic.as_u32() {
        return Err(P2pError::MalformedFrame(
            "network magic mismatch".to_owned(),
        ));
    }

    let packet_type = PacketType::from_u8(
        reader
            .read_u8()
            .map_err(|error| P2pError::MalformedFrame(error.to_string()))?,
    );
    let payload_len = reader
        .read_u32()
        .map_err(|error| P2pError::MalformedFrame(error.to_string()))?
        as usize;

    if payload_len > MAX_FRAME_PAYLOAD_SIZE {
        return Err(P2pError::MalformedFrame(format!(
            "payload exceeds {MAX_FRAME_PAYLOAD_SIZE} bytes"
        )));
    }

    let payload = reader
        .read_vec(payload_len)
        .map_err(|error| P2pError::MalformedFrame(error.to_string()))?;
    reader
        .ensure_finished()
        .map_err(|error| P2pError::MalformedFrame(error.to_string()))?;

    Frame::new(packet_type, payload)
}

#[derive(Debug)]
pub struct AsyncPeerTransport<T> {
    io: T,
    magic: NetworkMagic,
}

impl<T> AsyncPeerTransport<T>
where
    T: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(io: T, magic: NetworkMagic) -> Self {
        Self { io, magic }
    }

    pub fn into_inner(self) -> T {
        self.io
    }

    pub async fn read_frame(&mut self) -> Result<Frame, P2pError> {
        let mut header = [0u8; FRAME_HEADER_SIZE];
        self.io.read_exact(&mut header).await?;
        let (packet_type, payload_len) = decode_frame_header(self.magic, &header)?;
        let mut payload = vec![0; payload_len];
        self.io.read_exact(&mut payload).await?;
        Frame::new(packet_type, payload)
    }

    pub async fn write_frame(&mut self, frame: &Frame) -> Result<(), P2pError> {
        let encoded = encode_frame(self.magic, frame)?;
        self.io.write_all(&encoded).await?;
        self.io.flush().await?;
        Ok(())
    }
}

fn decode_frame_header(
    magic: NetworkMagic,
    header: &[u8; FRAME_HEADER_SIZE],
) -> Result<(PacketType, usize), P2pError> {
    let mut reader = Reader::new(header, FRAME_HEADER_SIZE)
        .map_err(|error| P2pError::MalformedFrame(error.to_string()))?;
    let actual_magic = reader
        .read_u32()
        .map_err(|error| P2pError::MalformedFrame(error.to_string()))?;

    if actual_magic != magic.as_u32() {
        return Err(P2pError::MalformedFrame(
            "network magic mismatch".to_owned(),
        ));
    }

    let packet_type = PacketType::from_u8(
        reader
            .read_u8()
            .map_err(|error| P2pError::MalformedFrame(error.to_string()))?,
    );
    let payload_len = reader
        .read_u32()
        .map_err(|error| P2pError::MalformedFrame(error.to_string()))?
        as usize;

    if payload_len > MAX_FRAME_PAYLOAD_SIZE {
        return Err(P2pError::MalformedFrame(format!(
            "payload exceeds {MAX_FRAME_PAYLOAD_SIZE} bytes"
        )));
    }

    reader
        .ensure_finished()
        .map_err(|error| P2pError::MalformedFrame(error.to_string()))?;
    Ok((packet_type, payload_len))
}

pub fn encode_inventory_payload(inventory: &[Inventory]) -> Result<Vec<u8>, P2pError> {
    if inventory.len() > MAX_INVENTORY_ITEMS {
        return Err(P2pError::MalformedFrame(format!(
            "inventory exceeds {MAX_INVENTORY_ITEMS} items"
        )));
    }

    let mut writer = Writer::new();
    writer.write_varint(inventory.len() as u64);

    for item in inventory {
        writer.write_u32(item.kind().as_u32());
        writer.write_bytes(&item.hash_bytes());
    }

    Ok(writer.finish())
}

pub fn decode_inventory_payload(payload: &[u8]) -> Result<Vec<Inventory>, P2pError> {
    let mut reader = Reader::new(payload, MAX_FRAME_PAYLOAD_SIZE)
        .map_err(|error| P2pError::MalformedFrame(error.to_string()))?;
    let count = reader
        .read_varint_usize("inventory")
        .map_err(|error| P2pError::MalformedFrame(error.to_string()))?;

    if count > MAX_INVENTORY_ITEMS {
        return Err(P2pError::MalformedFrame(format!(
            "inventory exceeds {MAX_INVENTORY_ITEMS} items"
        )));
    }

    let mut inventory = Vec::with_capacity(count);

    for _ in 0..count {
        let kind = InventoryKind::from_u32(
            reader
                .read_u32()
                .map_err(|error| P2pError::MalformedFrame(error.to_string()))?,
        );
        let hash = reader
            .read_hash()
            .map_err(|error| P2pError::MalformedFrame(error.to_string()))?;
        inventory.push(Inventory::from_kind_hash(kind, hash));
    }

    reader
        .ensure_finished()
        .map_err(|error| P2pError::MalformedFrame(error.to_string()))?;
    Ok(inventory)
}

impl Inventory {
    pub fn kind(&self) -> InventoryKind {
        match self {
            Self::Transaction(_) => InventoryKind::Transaction,
            Self::Block(_) => InventoryKind::Block,
            Self::Unknown { kind, .. } => InventoryKind::Unknown(*kind),
        }
    }

    pub fn hash_bytes(&self) -> [u8; 32] {
        match self {
            Self::Transaction(txid) => *txid.as_bytes(),
            Self::Block(hash) => *hash.as_bytes(),
            Self::Unknown { hash, .. } => *hash,
        }
    }

    pub fn from_kind_hash(kind: InventoryKind, hash: [u8; 32]) -> Self {
        match kind {
            InventoryKind::Transaction => Self::Transaction(Txid::new(hash)),
            InventoryKind::Block => Self::Block(BlockHash::new(hash)),
            InventoryKind::FilteredBlock
            | InventoryKind::CompactBlock
            | InventoryKind::Claim
            | InventoryKind::Airdrop => Self::Unknown {
                kind: kind.as_u32(),
                hash,
            },
            InventoryKind::Unknown(kind) => Self::Unknown { kind, hash },
        }
    }
}

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
        let mut peers: Vec<_> = self
            .inner
            .read()
            .map_err(|_| P2pError::State("peer manager read lock poisoned".to_owned()))?
            .peers
            .values()
            .cloned()
            .collect();
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
    #[error("p2p service is not implemented in the scaffold")]
    Unimplemented,
    #[error("peer {0:?} is unavailable")]
    PeerUnavailable(PeerId),
    #[error("malformed frame: {0}")]
    MalformedFrame(String),
    #[error("p2p io failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("p2p state failed: {0}")]
    State(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[test]
    fn memory_peer_manager_tracks_peers_and_requests() {
        let manager = MemoryPeerManager::new();
        let peer = PeerSnapshot {
            id: PeerId(1),
            address: "127.0.0.1:12038".parse().expect("addr"),
            advertised_height: Some(10),
            score: 0,
        };
        manager.add_peer(peer).expect("add peer");
        manager
            .request_block(PeerId(1), BlockHash::new([3; 32]))
            .expect("request");

        assert_eq!(manager.peers().expect("peers").len(), 1);
        assert_eq!(manager.block_requests().expect("requests").len(), 1);
    }

    #[test]
    fn frame_codec_round_trips_hsd_header_layout() {
        let frame = Frame::new(PacketType::Ping, vec![1, 2, 3, 4, 5, 6, 7, 8]).expect("frame");
        let encoded = encode_frame(NetworkMagic::Regtest, &frame).expect("encode");

        assert_eq!(
            &encoded[0..4],
            &NetworkMagic::Regtest.as_u32().to_le_bytes()
        );
        assert_eq!(encoded[4], PacketType::Ping.as_u8());
        assert_eq!(&encoded[5..9], &(8u32).to_le_bytes());
        assert_eq!(
            decode_frame(NetworkMagic::Regtest, &encoded).expect("decode"),
            frame
        );
    }

    #[test]
    fn network_magic_matches_pinned_hsd_genesis_prefixes() {
        assert_eq!(NetworkMagic::Mainnet.as_u32(), 1_533_997_779);
        assert_eq!(NetworkMagic::Testnet.as_u32(), 2_974_944_722);
        assert_eq!(NetworkMagic::Regtest.as_u32(), 2_922_943_951);
        assert_eq!(NetworkMagic::Simnet.as_u32(), 241_471_196);
        for network in [
            Network::Mainnet,
            Network::Testnet,
            Network::Regtest,
            Network::Simnet,
        ] {
            assert_eq!(
                NetworkMagic::from(network).as_u32(),
                network.params().packet_magic
            );
        }
    }

    #[test]
    fn frame_codec_rejects_wrong_network_magic() {
        let frame = Frame::new(PacketType::Pong, vec![0; 8]).expect("frame");
        let encoded = encode_frame(NetworkMagic::Regtest, &frame).expect("encode");
        let error = decode_frame(NetworkMagic::Mainnet, &encoded).expect_err("wrong magic");

        assert!(
            matches!(error, P2pError::MalformedFrame(message) if message == "network magic mismatch")
        );
    }

    #[test]
    fn inventory_payload_round_trips_known_and_unknown_items() {
        let inventory = vec![
            Inventory::Block(BlockHash::new([1; 32])),
            Inventory::Transaction(Txid::new([2; 32])),
            Inventory::Unknown {
                kind: 99,
                hash: [3; 32],
            },
        ];
        let encoded = encode_inventory_payload(&inventory).expect("encode");

        assert_eq!(
            decode_inventory_payload(&encoded).expect("decode"),
            inventory
        );
    }

    #[tokio::test]
    async fn async_transport_exchanges_frames() {
        let (client_io, server_io) = tokio::io::duplex(1024);
        let mut client = AsyncPeerTransport::new(client_io, NetworkMagic::Regtest);
        let mut server = AsyncPeerTransport::new(server_io, NetworkMagic::Regtest);
        let frame = Frame::new(PacketType::Ping, vec![1, 2, 3, 4, 5, 6, 7, 8]).expect("frame");
        let expected = frame.clone();

        let writer = tokio::spawn(async move {
            client.write_frame(&frame).await.expect("write frame");
        });

        assert_eq!(server.read_frame().await.expect("read frame"), expected);
        writer.await.expect("writer join");
    }

    #[tokio::test]
    async fn async_transport_rejects_wrong_magic() {
        let (mut writer, reader) = tokio::io::duplex(1024);
        let mut transport = AsyncPeerTransport::new(reader, NetworkMagic::Regtest);
        let frame = Frame::new(PacketType::Pong, vec![0; 8]).expect("frame");
        let encoded = encode_frame(NetworkMagic::Mainnet, &frame).expect("encode");

        writer.write_all(&encoded).await.expect("write frame");
        drop(writer);

        let error = transport.read_frame().await.expect_err("wrong magic");
        assert!(
            matches!(error, P2pError::MalformedFrame(message) if message == "network magic mismatch")
        );
    }

    #[tokio::test]
    async fn async_transport_rejects_oversized_payload_before_allocation() {
        let (mut writer, reader) = tokio::io::duplex(1024);
        let mut transport = AsyncPeerTransport::new(reader, NetworkMagic::Regtest);
        let mut header = Writer::with_capacity(FRAME_HEADER_SIZE);
        header.write_u32(NetworkMagic::Regtest.as_u32());
        header.write_u8(PacketType::Block.as_u8());
        header.write_u32((MAX_FRAME_PAYLOAD_SIZE as u32) + 1);

        writer
            .write_all(&header.finish())
            .await
            .expect("write header");
        drop(writer);

        let error = transport.read_frame().await.expect_err("oversized frame");
        assert!(
            matches!(error, P2pError::MalformedFrame(message) if message == format!("payload exceeds {MAX_FRAME_PAYLOAD_SIZE} bytes"))
        );
    }
}
