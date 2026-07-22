use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
};

use hns_consensus::Network;
use hns_primitives::{
    blake2b_256_many, AirdropProof, Block, BlockHash, Claim, Header, Reader, Transaction, Txid,
    Writer,
};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    constants::{
        FRAME_HEADER_SIZE, MAX_ADDR_ITEMS, MAX_COMPACT_BLOCK_TRANSACTIONS, MAX_FRAME_PAYLOAD_SIZE,
        MAX_HEADERS, MAX_INVENTORY_ITEMS, MAX_LOCATOR_HASHES, MAX_REJECT_REASON_SIZE,
        MAX_USER_AGENT_SIZE, NET_ADDRESS_SIZE,
    },
    P2pError,
};

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

    pub const fn carries_reject_hash(self) -> bool {
        matches!(self, Self::Block | Self::Tx | Self::Claim | Self::Airdrop)
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

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Inventory {
    pub kind: InventoryKind,
    pub hash: [u8; 32],
}

impl Inventory {
    pub fn block(hash: BlockHash) -> Self {
        Self {
            kind: InventoryKind::Block,
            hash: hash.into_inner(),
        }
    }

    pub fn transaction(txid: Txid) -> Self {
        Self {
            kind: InventoryKind::Transaction,
            hash: txid.into_inner(),
        }
    }

    pub const fn claim(hash: [u8; 32]) -> Self {
        Self {
            kind: InventoryKind::Claim,
            hash,
        }
    }

    pub const fn airdrop(hash: [u8; 32]) -> Self {
        Self {
            kind: InventoryKind::Airdrop,
            hash,
        }
    }

    pub fn block_hash(&self) -> Option<BlockHash> {
        matches!(
            self.kind,
            InventoryKind::Block | InventoryKind::FilteredBlock | InventoryKind::CompactBlock
        )
        .then(|| BlockHash::new(self.hash))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AddressHost {
    Ip([u8; 16]),
    Opaque { kind: u8, bytes: [u8; 36] },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NetAddress {
    pub time: u64,
    pub services: u64,
    pub host: AddressHost,
    pub port: u16,
    pub key: [u8; 33],
}

/// Canonical HSD outbound-peer network group.
///
/// HSD groups IPv4 peers by /16 and ordinary IPv6 peers by /32, with
/// special handling for transition and tunnel address ranges. The encoded
/// bytes intentionally match `NetAddress#getGroup()` so callers can use this
/// value as a stable set key without retaining a full peer address.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PeerAddressGroup {
    bytes: [u8; 6],
    length: u8,
}

impl PeerAddressGroup {
    fn from_prefix(prefix: &[u8]) -> Self {
        debug_assert!(prefix.len() <= 6);
        let mut bytes = [0; 6];
        bytes[..prefix.len()].copy_from_slice(prefix);
        Self {
            bytes,
            length: prefix.len() as u8,
        }
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.length)]
    }
}

/// Return the exact HSD address-group key for an IP address.
pub fn peer_address_group(address: IpAddr) -> PeerAddressGroup {
    const NETWORK_NONE: u8 = 0;
    const NETWORK_IPV4: u8 = 1;
    const NETWORK_IPV6: u8 = 2;
    const NETWORK_ONION: u8 = 3;
    const NETWORK_LOCAL: u8 = 255;

    let raw = match address {
        IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
        IpAddr::V6(ip) => ip.octets(),
    };

    if is_hsd_local_ip(&raw) {
        return PeerAddressGroup::from_prefix(&[NETWORK_LOCAL]);
    }
    if !is_hsd_routable_ip(&raw) {
        return PeerAddressGroup::from_prefix(&[NETWORK_NONE]);
    }
    if is_ipv4_mapped(&raw) || is_rfc6145(&raw) || is_rfc6052(&raw) {
        return PeerAddressGroup::from_prefix(&[NETWORK_IPV4, raw[12], raw[13]]);
    }
    if raw[0..2] == [0x20, 0x02] {
        return PeerAddressGroup::from_prefix(&[NETWORK_IPV4, raw[2], raw[3]]);
    }
    if raw[0..4] == [0x20, 0x01, 0x00, 0x00] {
        return PeerAddressGroup::from_prefix(&[NETWORK_IPV4, raw[12] ^ 0xff, raw[13] ^ 0xff]);
    }
    if is_onion_ip(&raw) {
        return PeerAddressGroup::from_prefix(&[NETWORK_ONION, raw[6] | 0x0f]);
    }
    if raw[0..4] == [0x20, 0x01, 0x04, 0x70] {
        return PeerAddressGroup::from_prefix(&[
            NETWORK_IPV6,
            raw[0],
            raw[1],
            raw[2],
            raw[3],
            raw[4] | 0x0f,
        ]);
    }
    PeerAddressGroup::from_prefix(&[NETWORK_IPV6, raw[0], raw[1], raw[2], raw[3]])
}

fn is_ipv4_mapped(raw: &[u8; 16]) -> bool {
    raw[..10] == [0; 10] && raw[10..12] == [0xff, 0xff]
}

fn is_rfc6052(raw: &[u8; 16]) -> bool {
    raw[..12] == [0x00, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0]
}

fn is_rfc6145(raw: &[u8; 16]) -> bool {
    raw[..12] == [0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0, 0]
}

fn is_onion_ip(raw: &[u8; 16]) -> bool {
    raw[..6] == [0xfd, 0x87, 0xd8, 0x7e, 0xeb, 0x43]
}

fn is_hsd_local_ip(raw: &[u8; 16]) -> bool {
    if is_ipv4_mapped(raw) {
        return raw[12] == 0 || raw[12] == 127;
    }
    *raw == Ipv6Addr::LOCALHOST.octets()
}

fn is_hsd_routable_ip(raw: &[u8; 16]) -> bool {
    if is_ipv4_mapped(raw) {
        let [a, b, c, d] = [raw[12], raw[13], raw[14], raw[15]];
        return !(a == 0
            || a == 10
            || a == 127
            || (a == 100 && (64..=127).contains(&b))
            || (a == 169 && b == 254)
            || (a == 172 && (16..=31).contains(&b))
            || (a == 192 && b == 0 && c == 2)
            || (a == 192 && b == 168)
            || (a == 198 && (b == 18 || b == 19))
            || (a == 198 && b == 51 && c == 100)
            || (a == 203 && b == 0 && c == 113)
            || (a == 255 && b == 255 && c == 255 && d == 255));
    }

    if raw.iter().all(|byte| *byte == 0)
        || is_hsd_local_ip(raw)
        || raw[..9] == [0, 0, 0, 0, 0, 0, 0, 0xff, 0xff]
        || raw[..8] == [0xfe, 0x80, 0, 0, 0, 0, 0, 0]
        || raw[..4] == [0x20, 0x01, 0x0d, 0xb8]
        || (raw[0] & 0xfe == 0xfc && !is_onion_ip(raw))
        || (raw[0..3] == [0x20, 0x01, 0x00] && raw[3] & 0xf0 == 0x10)
        || (raw[0..3] == [0x20, 0x01, 0x00] && raw[3] & 0xf0 == 0x20)
    {
        return false;
    }
    true
}

impl NetAddress {
    pub fn from_socket_addr(address: SocketAddr, time: u64, services: u64) -> Self {
        let ip = match address.ip() {
            IpAddr::V4(ip) => ip.to_ipv6_mapped().octets(),
            IpAddr::V6(ip) => ip.octets(),
        };
        Self {
            time,
            services,
            host: AddressHost::Ip(ip),
            port: address.port(),
            key: [0; 33],
        }
    }

    pub fn socket_addr(&self) -> Option<SocketAddr> {
        let AddressHost::Ip(bytes) = &self.host else {
            return None;
        };
        let ip = Ipv6Addr::from(*bytes);
        let address = ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip));
        Some(SocketAddr::new(address, self.port))
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(NET_ADDRESS_SIZE);
        writer.write_u64(self.time);
        // HSD currently serializes only the low 32 service bits and writes a
        // reserved zero high word. Keep the public field wide for diagnostics,
        // but match the wire layout byte-for-byte.
        writer.write_u32(self.services as u32);
        writer.write_u32(0);
        match &self.host {
            AddressHost::Ip(bytes) => {
                writer.write_u8(0);
                writer.write_bytes(bytes);
                writer.write_bytes(&[0; 20]);
            }
            // HSD normalizes unsupported address kinds to the all-zero IP
            // representation when it decodes and later re-encodes them. Do not
            // preserve opaque bytes on the wire because doing so would diverge
            // from the pinned implementation.
            AddressHost::Opaque { .. } => {
                writer.write_u8(0);
                writer.write_bytes(&[0; 36]);
            }
        }
        writer.write_u16(self.port);
        writer.write_bytes(&self.key);
        writer.finish()
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, P2pError> {
        if bytes.len() != NET_ADDRESS_SIZE {
            return Err(P2pError::MalformedPacket(format!(
                "network address must be {NET_ADDRESS_SIZE} bytes, got {}",
                bytes.len()
            )));
        }
        let mut reader = packet_reader(bytes)?;
        let address = Self::read_from(&mut reader)?;
        finish_reader(reader)?;
        Ok(address)
    }

    fn read_from(reader: &mut Reader<'_>) -> Result<Self, P2pError> {
        let time = primitive(reader.read_u64())?;
        let services = u64::from(primitive(reader.read_u32())?);
        // HSD reads and discards the reserved high service word.
        let _reserved_services_high = primitive(reader.read_u32())?;
        let kind = primitive(reader.read_u8())?;
        let raw = read_array::<36>(reader)?;
        let host = if kind == 0 {
            let mut ip = [0; 16];
            ip.copy_from_slice(&raw[..16]);
            AddressHost::Ip(ip)
        } else {
            // HSD discards unsupported host encodings and leaves the raw IP at
            // its zero value. Matching that behavior is important because a
            // decode/re-encode cycle must produce HSD's canonical bytes.
            let _ = raw;
            AddressHost::Ip([0; 16])
        };
        let port = primitive(reader.read_u16())?;
        let key = read_array::<33>(reader)?;
        Ok(Self {
            time,
            services,
            host,
            port,
            key,
        })
    }
}

impl Default for NetAddress {
    fn default() -> Self {
        Self::from_socket_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0), 0, 0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VersionPacket {
    pub version: u32,
    pub services: u64,
    pub time: u64,
    pub remote: NetAddress,
    pub nonce: [u8; 8],
    pub agent: String,
    pub height: u32,
    pub no_relay: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LocatorPacket {
    pub locator: Vec<BlockHash>,
    pub stop: BlockHash,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RejectPacket {
    pub message: PacketType,
    pub code: u8,
    pub reason: String,
    pub hash: Option<[u8; 32]>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrefilledTransaction {
    /// Differential index, matching HSD/BIP152 wire encoding.
    pub index: usize,
    pub transaction: Transaction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactBlock {
    pub header: Header,
    pub key_nonce: [u8; 8],
    pub short_ids: Vec<u64>,
    pub prefilled: Vec<PrefilledTransaction>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactBlockRequest {
    pub block_hash: BlockHash,
    /// Absolute transaction indexes. The wire codec converts them to and from
    /// BIP152 differential indexes.
    pub indexes: Vec<usize>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactBlockResponse {
    pub block_hash: BlockHash,
    pub transactions: Vec<Transaction>,
}

#[derive(Clone, Debug)]
pub struct CompactBlockReconstruction {
    header: Header,
    available: Vec<Option<usize>>,
    transactions: Vec<Option<Transaction>>,
    short_id_indexes: HashMap<u64, usize>,
    filled: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CompactBlockError {
    #[error("malformed compact block: {0}")]
    Malformed(String),
    #[error("compact block short-id collision: {0:#014x}")]
    ShortIdCollision(u64),
    #[error("compact block response hash does not match the pending block")]
    ResponseHashMismatch,
    #[error("compact block response has {actual} transactions; expected {expected}")]
    ResponseCountMismatch { expected: usize, actual: usize },
    #[error("compact block reconstruction is incomplete")]
    Incomplete,
}

impl CompactBlock {
    pub fn from_block(block: &Block) -> Self {
        Self::from_block_with_nonce(block, rand::random())
    }

    pub fn from_block_with_nonce(block: &Block, key_nonce: [u8; 8]) -> Self {
        let mut compact = Self {
            header: block.header.clone(),
            key_nonce,
            short_ids: Vec::with_capacity(block.transactions.len().saturating_sub(1)),
            prefilled: Vec::with_capacity(usize::from(!block.transactions.is_empty())),
        };
        let siphash_key = compact.siphash_key();
        compact.short_ids = block
            .transactions
            .iter()
            .skip(1)
            .map(|transaction| Self::short_id_with_key(&transaction.witness_hash(), &siphash_key))
            .collect();
        if let Some(coinbase) = block.transactions.first() {
            compact.prefilled.push(PrefilledTransaction {
                index: 0,
                transaction: coinbase.clone(),
            });
        }
        compact
    }

    pub fn hash(&self) -> BlockHash {
        self.header.hash()
    }

    pub fn total_transactions(&self) -> usize {
        self.short_ids.len().saturating_add(self.prefilled.len())
    }

    pub fn short_id(&self, witness_hash: &[u8; 32]) -> u64 {
        Self::short_id_with_key(witness_hash, &self.siphash_key())
    }

    fn siphash_key(&self) -> [u8; 16] {
        let header = self.header.encode();
        let hash = blake2b_256_many([header.as_slice(), self.key_nonce.as_slice()]);
        let mut key = [0u8; 16];
        key.copy_from_slice(&hash[..16]);
        key
    }

    fn short_id_with_key(witness_hash: &[u8; 32], key: &[u8; 16]) -> u64 {
        siphash24(witness_hash, key) & 0x0000_ffff_ffff_ffff
    }

    pub fn reconstruct(
        &self,
        mempool: &[Transaction],
    ) -> Result<CompactBlockReconstruction, CompactBlockError> {
        let total = self.validate_layout()?;
        let mut reconstruction = CompactBlockReconstruction {
            header: self.header.clone(),
            available: vec![None; total],
            transactions: Vec::with_capacity(total),
            short_id_indexes: HashMap::with_capacity(self.short_ids.len()),
            filled: 0,
        };

        let mut previous = None;
        for prefilled in &self.prefilled {
            let index = absolute_prefilled_index(previous, prefilled.index)?;
            if index >= total {
                return Err(CompactBlockError::Malformed(format!(
                    "prefilled index {index} exceeds transaction count {total}"
                )));
            }
            previous = Some(index);
            reconstruction.insert(index, prefilled.transaction.clone())?;
        }

        let mut offset = 0usize;
        for (relative, short_id) in self.short_ids.iter().copied().enumerate() {
            while reconstruction
                .available
                .get(relative.saturating_add(offset))
                .is_some_and(Option::is_some)
            {
                offset = offset.saturating_add(1);
            }
            let index = relative.checked_add(offset).ok_or_else(|| {
                CompactBlockError::Malformed("short-id index overflow".to_owned())
            })?;
            if index >= total {
                return Err(CompactBlockError::Malformed(
                    "short-id layout exceeds transaction count".to_owned(),
                ));
            }
            if reconstruction
                .short_id_indexes
                .insert(short_id, index)
                .is_some()
            {
                return Err(CompactBlockError::ShortIdCollision(short_id));
            }
        }
        reconstruction.fill_mempool(self, mempool);
        Ok(reconstruction)
    }

    fn validate_layout(&self) -> Result<usize, CompactBlockError> {
        let total = self.total_transactions();
        if total == 0 {
            return Err(CompactBlockError::Malformed(
                "empty short-id and prefilled vectors".to_owned(),
            ));
        }
        if total > MAX_COMPACT_BLOCK_TRANSACTIONS {
            return Err(CompactBlockError::Malformed(format!(
                "transaction count {total} exceeds {MAX_COMPACT_BLOCK_TRANSACTIONS}"
            )));
        }
        if self
            .short_ids
            .iter()
            .any(|short_id| *short_id > 0x0000_ffff_ffff_ffff)
        {
            return Err(CompactBlockError::Malformed(
                "short ID exceeds 48 bits".to_owned(),
            ));
        }

        let mut previous = None;
        for prefilled in &self.prefilled {
            let index = absolute_prefilled_index(previous, prefilled.index)?;
            if index >= total {
                return Err(CompactBlockError::Malformed(format!(
                    "prefilled index {index} exceeds transaction count {total}"
                )));
            }
            previous = Some(index);
        }
        Ok(total)
    }

    fn write_to(&self, writer: &mut Writer) -> Result<(), P2pError> {
        self.validate_layout()
            .map_err(|error| P2pError::MalformedPacket(error.to_string()))?;
        self.header.write_to(writer);
        writer.write_bytes(&self.key_nonce);
        writer.write_varint(self.short_ids.len() as u64);
        for short_id in &self.short_ids {
            writer.write_u32(*short_id as u32);
            writer.write_u16((*short_id >> 32) as u16);
        }
        writer.write_varint(self.prefilled.len() as u64);
        for prefilled in &self.prefilled {
            writer.write_varint(prefilled.index as u64);
            prefilled.transaction.write_to(writer);
        }
        Ok(())
    }

    fn read_from(reader: &mut Reader<'_>) -> Result<Self, P2pError> {
        let header = primitive(Header::read_from(reader))?;
        let key_nonce = read_array::<8>(reader)?;
        let short_id_count = read_count(
            reader,
            "compact-block short IDs",
            MAX_COMPACT_BLOCK_TRANSACTIONS,
        )?;
        let mut short_ids = Vec::with_capacity(short_id_count);
        for _ in 0..short_id_count {
            let low = u64::from(primitive(reader.read_u32())?);
            let high = u64::from(primitive(reader.read_u16())?);
            short_ids.push((high << 32) | low);
        }
        let maximum_prefilled = MAX_COMPACT_BLOCK_TRANSACTIONS.saturating_sub(short_id_count);
        let prefilled_count = read_count(
            reader,
            "compact-block prefilled transactions",
            maximum_prefilled,
        )?;
        let total = short_id_count.saturating_add(prefilled_count);
        let mut prefilled = Vec::with_capacity(prefilled_count);
        let mut previous = None;
        for _ in 0..prefilled_count {
            let index = read_bounded_index(reader, "compact-block prefilled index")?;
            let absolute = absolute_prefilled_index(previous, index)
                .map_err(|error| P2pError::MalformedPacket(error.to_string()))?;
            if absolute >= total {
                return Err(P2pError::MalformedPacket(format!(
                    "compact-block prefilled index {absolute} exceeds transaction count {total}"
                )));
            }
            previous = Some(absolute);
            prefilled.push(PrefilledTransaction {
                index,
                transaction: primitive(Transaction::read_from(reader))?,
            });
        }
        let compact = Self {
            header,
            key_nonce,
            short_ids,
            prefilled,
        };
        compact
            .validate_layout()
            .map_err(|error| P2pError::MalformedPacket(error.to_string()))?;
        Ok(compact)
    }
}

impl CompactBlockReconstruction {
    pub fn is_complete(&self) -> bool {
        self.filled == self.available.len()
    }

    pub fn missing_request(&self) -> CompactBlockRequest {
        CompactBlockRequest {
            block_hash: self.header.hash(),
            indexes: self
                .available
                .iter()
                .enumerate()
                .filter_map(|(index, transaction)| transaction.is_none().then_some(index))
                .collect(),
        }
    }

    pub fn fill_missing(
        &mut self,
        response: CompactBlockResponse,
    ) -> Result<(), CompactBlockError> {
        if response.block_hash != self.header.hash() {
            return Err(CompactBlockError::ResponseHashMismatch);
        }
        let missing = self.available.iter().filter(|item| item.is_none()).count();
        if response.transactions.len() != missing {
            return Err(CompactBlockError::ResponseCountMismatch {
                expected: missing,
                actual: response.transactions.len(),
            });
        }
        for (index, transaction) in self
            .available
            .iter()
            .enumerate()
            .filter_map(|(index, item)| item.is_none().then_some(index))
            .zip(response.transactions)
            .collect::<Vec<_>>()
        {
            self.insert(index, transaction)?;
        }
        Ok(())
    }

    pub fn into_block(self) -> Result<Block, CompactBlockError> {
        if !self.is_complete() {
            return Err(CompactBlockError::Incomplete);
        }
        let mut resolved = self.transactions;
        let mut transactions = Vec::with_capacity(self.available.len());
        for item in self.available {
            let index = item.ok_or(CompactBlockError::Incomplete)?;
            let transaction = resolved
                .get_mut(index)
                .and_then(Option::take)
                .ok_or_else(|| {
                    CompactBlockError::Malformed(
                        "multiple compact-block slots reference one transaction".to_owned(),
                    )
                })?;
            transactions.push(transaction);
        }
        Ok(Block {
            header: self.header,
            transactions,
        })
    }

    fn fill_mempool(&mut self, compact: &CompactBlock, mempool: &[Transaction]) {
        if self.is_complete() {
            return;
        }
        let mut matched = HashSet::new();
        let siphash_key = compact.siphash_key();
        for transaction in mempool {
            let short_id =
                CompactBlock::short_id_with_key(&transaction.witness_hash(), &siphash_key);
            let Some(index) = self.short_id_indexes.get(&short_id).copied() else {
                continue;
            };
            if !matched.insert(index) {
                if self.available[index].take().is_some() {
                    self.filled = self.filled.saturating_sub(1);
                }
                continue;
            }
            if self.available[index].is_none() && self.insert(index, transaction.clone()).is_err() {
                return;
            }
            if self.is_complete() {
                return;
            }
        }
    }

    fn insert(&mut self, index: usize, transaction: Transaction) -> Result<(), CompactBlockError> {
        let slot = self.available.get_mut(index).ok_or_else(|| {
            CompactBlockError::Malformed(format!("transaction index {index} is out of bounds"))
        })?;
        if slot.is_some() {
            return Err(CompactBlockError::Malformed(format!(
                "transaction index {index} is filled more than once"
            )));
        }
        let resolved = self.transactions.len();
        self.transactions.push(Some(transaction));
        *slot = Some(resolved);
        self.filled = self.filled.saturating_add(1);
        Ok(())
    }
}

impl CompactBlockRequest {
    pub fn from_block(block: &Block, indexes: Vec<usize>) -> Self {
        Self {
            block_hash: block.hash(),
            indexes,
        }
    }

    fn write_to(&self, writer: &mut Writer) -> Result<(), P2pError> {
        validate_absolute_indexes(&self.indexes)?;
        writer.write_bytes(self.block_hash.as_bytes());
        writer.write_varint(self.indexes.len() as u64);
        for (position, index) in self.indexes.iter().copied().enumerate() {
            let differential = if position == 0 {
                index
            } else {
                index - self.indexes[position - 1] - 1
            };
            writer.write_varint(differential as u64);
        }
        Ok(())
    }

    fn read_from(reader: &mut Reader<'_>) -> Result<Self, P2pError> {
        let block_hash = BlockHash::new(primitive(reader.read_hash())?);
        let count = read_count(
            reader,
            "compact-block requested indexes",
            MAX_COMPACT_BLOCK_TRANSACTIONS,
        )?;
        let mut indexes = Vec::with_capacity(count);
        let mut previous = None;
        for _ in 0..count {
            let differential = read_bounded_index(reader, "compact-block requested index")?;
            let absolute = absolute_prefilled_index(previous, differential)
                .map_err(|error| P2pError::MalformedPacket(error.to_string()))?;
            indexes.push(absolute);
            previous = Some(absolute);
        }
        Ok(Self {
            block_hash,
            indexes,
        })
    }
}

impl CompactBlockResponse {
    pub fn from_block(block: &Block, request: &CompactBlockRequest) -> Self {
        let transactions = request
            .indexes
            .iter()
            .map_while(|index| block.transactions.get(*index).cloned())
            .collect();
        Self {
            block_hash: request.block_hash,
            transactions,
        }
    }

    fn write_to(&self, writer: &mut Writer) -> Result<(), P2pError> {
        check_count(
            "compact-block response transactions",
            self.transactions.len(),
            MAX_COMPACT_BLOCK_TRANSACTIONS,
        )?;
        writer.write_bytes(self.block_hash.as_bytes());
        writer.write_varint(self.transactions.len() as u64);
        for transaction in &self.transactions {
            transaction.write_to(writer);
        }
        Ok(())
    }

    fn read_from(reader: &mut Reader<'_>) -> Result<Self, P2pError> {
        let block_hash = BlockHash::new(primitive(reader.read_hash())?);
        let count = read_count(
            reader,
            "compact-block response transactions",
            MAX_COMPACT_BLOCK_TRANSACTIONS,
        )?;
        let mut transactions = Vec::with_capacity(count);
        for _ in 0..count {
            transactions.push(primitive(Transaction::read_from(reader))?);
        }
        Ok(Self {
            block_hash,
            transactions,
        })
    }
}

fn absolute_prefilled_index(
    previous: Option<usize>,
    differential: usize,
) -> Result<usize, CompactBlockError> {
    let index = match previous {
        Some(previous) => previous
            .checked_add(1)
            .and_then(|value| value.checked_add(differential))
            .ok_or_else(|| {
                CompactBlockError::Malformed("differential index overflow".to_owned())
            })?,
        None => differential,
    };
    if index > u16::MAX as usize {
        return Err(CompactBlockError::Malformed(format!(
            "transaction index {index} exceeds 65535"
        )));
    }
    Ok(index)
}

fn read_bounded_index(reader: &mut Reader<'_>, context: &'static str) -> Result<usize, P2pError> {
    let index = primitive(reader.read_varint())?;
    if index > u64::from(u16::MAX) {
        return Err(P2pError::LimitExceeded {
            context,
            limit: usize::from(u16::MAX),
            actual: usize::try_from(index).unwrap_or(usize::MAX),
        });
    }
    Ok(index as usize)
}

fn validate_absolute_indexes(indexes: &[usize]) -> Result<(), P2pError> {
    check_count(
        "compact-block requested indexes",
        indexes.len(),
        MAX_COMPACT_BLOCK_TRANSACTIONS,
    )?;
    let mut previous = None;
    for index in indexes {
        if *index > usize::from(u16::MAX) {
            return Err(P2pError::LimitExceeded {
                context: "compact-block requested index",
                limit: usize::from(u16::MAX),
                actual: *index,
            });
        }
        if previous.is_some_and(|previous| *index <= previous) {
            return Err(P2pError::MalformedPacket(
                "compact-block requested indexes must be strictly increasing".to_owned(),
            ));
        }
        previous = Some(*index);
    }
    Ok(())
}

fn siphash24(message: &[u8], key: &[u8]) -> u64 {
    debug_assert_eq!(key.len(), 16);
    let k0 = u64::from_le_bytes(key[..8].try_into().expect("eight-byte SipHash key half"));
    let k1 = u64::from_le_bytes(key[8..].try_into().expect("eight-byte SipHash key half"));
    let mut v0 = 0x736f_6d65_7073_6575 ^ k0;
    let mut v1 = 0x646f_7261_6e64_6f6d ^ k1;
    let mut v2 = 0x6c79_6765_6e65_7261 ^ k0;
    let mut v3 = 0x7465_6462_7974_6573 ^ k1;

    let mut chunks = message.chunks_exact(8);
    for chunk in &mut chunks {
        let value = u64::from_le_bytes(chunk.try_into().expect("eight-byte SipHash message chunk"));
        v3 ^= value;
        for _ in 0..2 {
            siphash_round(&mut v0, &mut v1, &mut v2, &mut v3);
        }
        v0 ^= value;
    }
    let mut tail = (message.len() as u64) << 56;
    for (offset, byte) in chunks.remainder().iter().enumerate() {
        tail |= u64::from(*byte) << (offset * 8);
    }
    v3 ^= tail;
    for _ in 0..2 {
        siphash_round(&mut v0, &mut v1, &mut v2, &mut v3);
    }
    v0 ^= tail;
    v2 ^= 0xff;
    for _ in 0..4 {
        siphash_round(&mut v0, &mut v1, &mut v2, &mut v3);
    }
    v0 ^ v1 ^ v2 ^ v3
}

fn siphash_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);
    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;
    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;
    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Packet {
    Version(VersionPacket),
    Verack,
    Ping([u8; 8]),
    Pong([u8; 8]),
    GetAddr,
    Addr(Vec<NetAddress>),
    Inv(Vec<Inventory>),
    GetData(Vec<Inventory>),
    NotFound(Vec<Inventory>),
    GetBlocks(LocatorPacket),
    GetHeaders(LocatorPacket),
    Headers(Vec<Header>),
    SendHeaders,
    Block(Block),
    Tx(Transaction),
    Claim(Claim),
    Airdrop(AirdropProof),
    Reject(RejectPacket),
    Mempool,
    FeeFilter(i64),
    SendCmpct {
        mode: u8,
        version: u64,
    },
    CmpctBlock(CompactBlock),
    GetBlockTxn(CompactBlockRequest),
    BlockTxn(CompactBlockResponse),
    Unknown {
        packet_type: PacketType,
        payload: Vec<u8>,
    },
}

impl Packet {
    pub const fn packet_type(&self) -> PacketType {
        match self {
            Self::Version(_) => PacketType::Version,
            Self::Verack => PacketType::Verack,
            Self::Ping(_) => PacketType::Ping,
            Self::Pong(_) => PacketType::Pong,
            Self::GetAddr => PacketType::GetAddr,
            Self::Addr(_) => PacketType::Addr,
            Self::Inv(_) => PacketType::Inv,
            Self::GetData(_) => PacketType::GetData,
            Self::NotFound(_) => PacketType::NotFound,
            Self::GetBlocks(_) => PacketType::GetBlocks,
            Self::GetHeaders(_) => PacketType::GetHeaders,
            Self::Headers(_) => PacketType::Headers,
            Self::SendHeaders => PacketType::SendHeaders,
            Self::Block(_) => PacketType::Block,
            Self::Tx(_) => PacketType::Tx,
            Self::Claim(_) => PacketType::Claim,
            Self::Airdrop(_) => PacketType::Airdrop,
            Self::Reject(_) => PacketType::Reject,
            Self::Mempool => PacketType::Mempool,
            Self::FeeFilter(_) => PacketType::FeeFilter,
            Self::SendCmpct { .. } => PacketType::SendCmpct,
            Self::CmpctBlock(_) => PacketType::CmpctBlock,
            Self::GetBlockTxn(_) => PacketType::GetBlockTxn,
            Self::BlockTxn(_) => PacketType::BlockTxn,
            Self::Unknown { packet_type, .. } => *packet_type,
        }
    }

    pub fn encode_payload(&self) -> Result<Vec<u8>, P2pError> {
        let mut writer = Writer::new();
        match self {
            Self::Version(packet) => {
                if packet.agent.len() > MAX_USER_AGENT_SIZE || !packet.agent.is_ascii() {
                    return Err(P2pError::MalformedPacket(
                        "version user agent must be ASCII and fit in one byte".to_owned(),
                    ));
                }
                writer.write_u32(packet.version);
                writer.write_u32(packet.services as u32);
                writer.write_u32(0);
                writer.write_u64(packet.time);
                writer.write_bytes(&packet.remote.encode());
                writer.write_bytes(&packet.nonce);
                writer.write_u8(packet.agent.len() as u8);
                writer.write_bytes(packet.agent.as_bytes());
                writer.write_u32(packet.height);
                writer.write_u8(u8::from(packet.no_relay));
            }
            Self::Verack | Self::GetAddr | Self::SendHeaders | Self::Mempool => {}
            Self::Ping(nonce) | Self::Pong(nonce) => writer.write_bytes(nonce),
            Self::Addr(items) => {
                check_count("addresses", items.len(), MAX_ADDR_ITEMS)?;
                writer.write_varint(items.len() as u64);
                for item in items {
                    writer.write_bytes(&item.encode());
                }
            }
            Self::Inv(items) | Self::GetData(items) | Self::NotFound(items) => {
                encode_inventory(&mut writer, items)?;
            }
            Self::GetBlocks(packet) | Self::GetHeaders(packet) => {
                check_count("locator hashes", packet.locator.len(), MAX_LOCATOR_HASHES)?;
                writer.write_varint(packet.locator.len() as u64);
                for hash in &packet.locator {
                    writer.write_bytes(hash.as_bytes());
                }
                writer.write_bytes(packet.stop.as_bytes());
            }
            Self::Headers(headers) => {
                check_count("headers", headers.len(), MAX_HEADERS)?;
                writer.write_varint(headers.len() as u64);
                for header in headers {
                    header.write_to(&mut writer);
                }
            }
            Self::Block(block) => writer.write_bytes(&block.encode()),
            Self::Tx(transaction) => writer.write_bytes(&transaction.encode()),
            Self::Claim(claim) => writer.write_bytes(
                &claim
                    .encode()
                    .map_err(|error| P2pError::MalformedPacket(error.to_string()))?,
            ),
            Self::Airdrop(proof) => writer.write_bytes(
                &proof
                    .encode()
                    .map_err(|error| P2pError::MalformedPacket(error.to_string()))?,
            ),
            Self::Reject(packet) => {
                if packet.reason.len() > MAX_REJECT_REASON_SIZE || !packet.reason.is_ascii() {
                    return Err(P2pError::MalformedPacket(
                        "reject reason must be ASCII and fit in one byte".to_owned(),
                    ));
                }
                if packet.message.carries_reject_hash() != packet.hash.is_some() {
                    return Err(P2pError::MalformedPacket(
                        "reject hash presence does not match message type".to_owned(),
                    ));
                }
                writer.write_u8(packet.message.as_u8());
                writer.write_u8(packet.code);
                writer.write_u8(packet.reason.len() as u8);
                writer.write_bytes(packet.reason.as_bytes());
                if let Some(hash) = packet.hash {
                    writer.write_bytes(&hash);
                }
            }
            Self::FeeFilter(rate) => writer.write_u64(*rate as u64),
            Self::SendCmpct { mode, version } => {
                writer.write_u8(*mode);
                writer.write_u64(*version);
            }
            Self::CmpctBlock(block) => block.write_to(&mut writer)?,
            Self::GetBlockTxn(request) => request.write_to(&mut writer)?,
            Self::BlockTxn(response) => response.write_to(&mut writer)?,
            Self::Unknown { payload, .. } => writer.write_bytes(payload),
        }
        let payload = writer.finish();
        if payload.len() > MAX_FRAME_PAYLOAD_SIZE {
            return Err(P2pError::MalformedPacket(format!(
                "payload exceeds {MAX_FRAME_PAYLOAD_SIZE} bytes"
            )));
        }
        Ok(payload)
    }

    pub fn decode(packet_type: PacketType, payload: &[u8]) -> Result<Self, P2pError> {
        if payload.len() > MAX_FRAME_PAYLOAD_SIZE {
            return Err(P2pError::MalformedPacket(format!(
                "payload exceeds {MAX_FRAME_PAYLOAD_SIZE} bytes"
            )));
        }
        if matches!(packet_type, PacketType::Unknown(_)) {
            return Ok(Self::Unknown {
                packet_type,
                payload: payload.to_vec(),
            });
        }
        let mut reader = packet_reader(payload)?;
        let packet = match packet_type {
            PacketType::Version => {
                let version = primitive(reader.read_u32())?;
                let services = u64::from(primitive(reader.read_u32())?);
                // HSD currently discards the reserved high service word.
                let _reserved_services_high = primitive(reader.read_u32())?;
                let time = primitive(reader.read_u64())?;
                let remote = NetAddress::read_from(&mut reader)?;
                let nonce = read_array::<8>(&mut reader)?;
                let agent_len = usize::from(primitive(reader.read_u8())?);
                let agent_bytes = primitive(reader.read_vec(agent_len))?;
                let agent = decode_hsd_ascii(&agent_bytes);
                let height = primitive(reader.read_u32())?;
                // HSD treats exactly one as true and every other byte as false.
                let no_relay = primitive(reader.read_u8())? == 1;
                Self::Version(VersionPacket {
                    version,
                    services,
                    time,
                    remote,
                    nonce,
                    agent,
                    height,
                    no_relay,
                })
            }
            PacketType::Verack => Self::Verack,
            PacketType::Ping => Self::Ping(read_array::<8>(&mut reader)?),
            PacketType::Pong => Self::Pong(read_array::<8>(&mut reader)?),
            PacketType::GetAddr => Self::GetAddr,
            PacketType::Addr => {
                let count = read_count(&mut reader, "addresses", MAX_ADDR_ITEMS)?;
                let mut items = Vec::with_capacity(count);
                for _ in 0..count {
                    items.push(NetAddress::read_from(&mut reader)?);
                }
                Self::Addr(items)
            }
            PacketType::Inv => Self::Inv(decode_inventory(&mut reader)?),
            PacketType::GetData => Self::GetData(decode_inventory(&mut reader)?),
            PacketType::NotFound => Self::NotFound(decode_inventory(&mut reader)?),
            PacketType::GetBlocks | PacketType::GetHeaders => {
                let count = read_count(&mut reader, "locator hashes", MAX_LOCATOR_HASHES)?;
                let mut locator = Vec::with_capacity(count);
                for _ in 0..count {
                    locator.push(BlockHash::new(primitive(reader.read_hash())?));
                }
                let stop = BlockHash::new(primitive(reader.read_hash())?);
                let locator = LocatorPacket { locator, stop };
                if packet_type == PacketType::GetBlocks {
                    Self::GetBlocks(locator)
                } else {
                    Self::GetHeaders(locator)
                }
            }
            PacketType::Headers => {
                let count = read_count(&mut reader, "headers", MAX_HEADERS)?;
                let mut headers = Vec::with_capacity(count);
                for _ in 0..count {
                    headers.push(primitive(Header::read_from(&mut reader))?);
                }
                Self::Headers(headers)
            }
            PacketType::SendHeaders => Self::SendHeaders,
            PacketType::Block => {
                return Block::decode(payload)
                    .map(Self::Block)
                    .map_err(|error| P2pError::MalformedPacket(error.to_string()));
            }
            PacketType::Tx => {
                return Transaction::decode(payload)
                    .map(Self::Tx)
                    .map_err(|error| P2pError::MalformedPacket(error.to_string()));
            }
            PacketType::Claim => {
                return Claim::decode(payload)
                    .map(Self::Claim)
                    .map_err(|error| P2pError::MalformedPacket(error.to_string()));
            }
            PacketType::Airdrop => {
                return AirdropProof::decode(payload)
                    .map(Self::Airdrop)
                    .map_err(|error| P2pError::MalformedPacket(error.to_string()));
            }
            PacketType::Reject => {
                let message = PacketType::from_u8(primitive(reader.read_u8())?);
                let code = primitive(reader.read_u8())?;
                let reason_len = usize::from(primitive(reader.read_u8())?);
                let reason_bytes = primitive(reader.read_vec(reason_len))?;
                let reason = decode_hsd_ascii(&reason_bytes);
                let hash = if message.carries_reject_hash() {
                    Some(primitive(reader.read_hash())?)
                } else {
                    None
                };
                Self::Reject(RejectPacket {
                    message,
                    code,
                    reason,
                    hash,
                })
            }
            PacketType::Mempool => Self::Mempool,
            PacketType::FeeFilter => Self::FeeFilter(primitive(reader.read_u64())? as i64),
            PacketType::SendCmpct => Self::SendCmpct {
                mode: primitive(reader.read_u8())?,
                version: primitive(reader.read_u64())?,
            },
            PacketType::CmpctBlock => Self::CmpctBlock(CompactBlock::read_from(&mut reader)?),
            PacketType::GetBlockTxn => {
                Self::GetBlockTxn(CompactBlockRequest::read_from(&mut reader)?)
            }
            PacketType::BlockTxn => Self::BlockTxn(CompactBlockResponse::read_from(&mut reader)?),
            PacketType::FilterLoad
            | PacketType::FilterAdd
            | PacketType::FilterClear
            | PacketType::MerkleBlock
            | PacketType::GetProof
            | PacketType::Proof
            | PacketType::Unknown(_) => {
                return Ok(Self::Unknown {
                    packet_type,
                    payload: payload.to_vec(),
                });
            }
        };
        finish_reader(reader)?;
        Ok(packet)
    }
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

    pub fn from_packet(packet: &Packet) -> Result<Self, P2pError> {
        Self::new(packet.packet_type(), packet.encode_payload()?)
    }

    pub fn decode_packet(&self) -> Result<Packet, P2pError> {
        Packet::decode(self.packet_type, &self.payload)
    }
}

pub fn encode_frame(magic: NetworkMagic, frame: &Frame) -> Result<Vec<u8>, P2pError> {
    let payload_len = u32::try_from(frame.payload.len())
        .map_err(|_| P2pError::MalformedFrame("payload length exceeds u32".to_owned()))?;
    if frame.payload.len() > MAX_FRAME_PAYLOAD_SIZE {
        return Err(P2pError::MalformedFrame(format!(
            "payload exceeds {MAX_FRAME_PAYLOAD_SIZE} bytes"
        )));
    }
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
    let actual_magic = primitive(reader.read_u32())?;
    if actual_magic != magic.as_u32() {
        return Err(P2pError::MalformedFrame(
            "network magic mismatch".to_owned(),
        ));
    }
    let packet_type = PacketType::from_u8(primitive(reader.read_u8())?);
    let payload_len = primitive(reader.read_u32())? as usize;
    if payload_len > MAX_FRAME_PAYLOAD_SIZE {
        return Err(P2pError::MalformedFrame(format!(
            "payload exceeds {MAX_FRAME_PAYLOAD_SIZE} bytes"
        )));
    }
    let payload = primitive(reader.read_vec(payload_len))?;
    finish_reader(reader)?;
    Frame::new(packet_type, payload)
}

pub struct AsyncFrameReader<R> {
    io: R,
    magic: NetworkMagic,
}

impl<R> AsyncFrameReader<R>
where
    R: AsyncRead + Unpin,
{
    pub fn new(io: R, magic: NetworkMagic) -> Self {
        Self { io, magic }
    }

    pub async fn read_frame(&mut self) -> Result<Frame, P2pError> {
        let mut header = [0u8; FRAME_HEADER_SIZE];
        self.io.read_exact(&mut header).await?;
        let (packet_type, payload_len) = decode_frame_header(self.magic, &header)?;
        let mut payload = vec![0; payload_len];
        self.io.read_exact(&mut payload).await?;
        Frame::new(packet_type, payload)
    }

    pub async fn read_packet(&mut self) -> Result<Packet, P2pError> {
        self.read_frame().await?.decode_packet()
    }
}

pub struct AsyncFrameWriter<W> {
    io: W,
    magic: NetworkMagic,
}

impl<W> AsyncFrameWriter<W>
where
    W: AsyncWrite + Unpin,
{
    pub fn new(io: W, magic: NetworkMagic) -> Self {
        Self { io, magic }
    }

    pub async fn write_frame(&mut self, frame: &Frame) -> Result<usize, P2pError> {
        let encoded = encode_frame(self.magic, frame)?;
        let len = encoded.len();
        self.io.write_all(&encoded).await?;
        self.io.flush().await?;
        Ok(len)
    }

    pub async fn write_packet(&mut self, packet: &Packet) -> Result<usize, P2pError> {
        self.write_frame(&Frame::from_packet(packet)?).await
    }
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
    let mut reader = packet_reader(header)?;
    let actual_magic = primitive(reader.read_u32())?;
    if actual_magic != magic.as_u32() {
        return Err(P2pError::MalformedFrame(
            "network magic mismatch".to_owned(),
        ));
    }
    let packet_type = PacketType::from_u8(primitive(reader.read_u8())?);
    let payload_len = primitive(reader.read_u32())? as usize;
    if payload_len > MAX_FRAME_PAYLOAD_SIZE {
        return Err(P2pError::MalformedFrame(format!(
            "payload exceeds {MAX_FRAME_PAYLOAD_SIZE} bytes"
        )));
    }
    finish_reader(reader)?;
    Ok((packet_type, payload_len))
}

fn encode_inventory(writer: &mut Writer, items: &[Inventory]) -> Result<(), P2pError> {
    check_count("inventory", items.len(), MAX_INVENTORY_ITEMS)?;
    writer.write_varint(items.len() as u64);
    for item in items {
        writer.write_u32(item.kind.as_u32());
        writer.write_bytes(&item.hash);
    }
    Ok(())
}

fn decode_inventory(reader: &mut Reader<'_>) -> Result<Vec<Inventory>, P2pError> {
    let count = read_count(reader, "inventory", MAX_INVENTORY_ITEMS)?;
    let mut items = Vec::with_capacity(count);
    for _ in 0..count {
        let kind = InventoryKind::from_u32(primitive(reader.read_u32())?);
        let hash = primitive(reader.read_hash())?;
        items.push(Inventory { kind, hash });
    }
    Ok(items)
}

fn read_count(
    reader: &mut Reader<'_>,
    context: &'static str,
    maximum: usize,
) -> Result<usize, P2pError> {
    let count = primitive(reader.read_varint_usize(context))?;
    check_count(context, count, maximum)?;
    Ok(count)
}

fn check_count(context: &'static str, count: usize, maximum: usize) -> Result<(), P2pError> {
    if count > maximum {
        return Err(P2pError::LimitExceeded {
            context,
            limit: maximum,
            actual: count,
        });
    }
    Ok(())
}

fn packet_reader(bytes: &[u8]) -> Result<Reader<'_>, P2pError> {
    Reader::new(bytes, MAX_FRAME_PAYLOAD_SIZE)
        .map_err(|error| P2pError::MalformedPacket(error.to_string()))
}

fn finish_reader(reader: Reader<'_>) -> Result<(), P2pError> {
    reader
        .ensure_finished()
        .map_err(|error| P2pError::MalformedPacket(error.to_string()))
}

fn primitive<T>(result: Result<T, hns_primitives::PrimitiveError>) -> Result<T, P2pError> {
    result.map_err(|error| P2pError::MalformedPacket(error.to_string()))
}

/// Match Node.js/HSD's `ascii` decoder, which clears the high bit of each
/// input byte rather than rejecting non-ASCII octets.
fn decode_hsd_ascii(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| char::from(byte & 0x7f)).collect()
}

fn read_array<const N: usize>(reader: &mut Reader<'_>) -> Result<[u8; N], P2pError> {
    let bytes = primitive(reader.read_vec(N))?;
    bytes
        .try_into()
        .map_err(|_| P2pError::MalformedPacket(format!("expected fixed-width field of {N} bytes")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::{MIN_PROTOCOL_VERSION, PROTOCOL_VERSION, SERVICE_NETWORK};
    use hns_primitives::{Address, Covenant, CovenantKind, Input, Outpoint, Output, Witness};
    use tokio::io::AsyncWriteExt;

    #[test]
    fn frame_codec_round_trips_hsd_layout() {
        let packet = Packet::Ping([1, 2, 3, 4, 5, 6, 7, 8]);
        let frame = Frame::from_packet(&packet).expect("frame");
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
        assert_eq!(frame.decode_packet().expect("packet"), packet);
    }

    #[test]
    fn network_magic_matches_consensus_params() {
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
        assert_eq!(PROTOCOL_VERSION, 3);
        assert_eq!(MIN_PROTOCOL_VERSION, 1);
        assert_eq!(SERVICE_NETWORK, 1);
    }

    #[test]
    fn packet_round_trips_core_sync_messages() {
        let address = NetAddress::from_socket_addr(
            "127.0.0.1:14038".parse().expect("address"),
            1_700_000_000,
            SERVICE_NETWORK,
        );
        let packets = vec![
            Packet::Version(VersionPacket {
                version: PROTOCOL_VERSION,
                services: SERVICE_NETWORK,
                time: 1_700_000_001,
                remote: address.clone(),
                nonce: [7; 8],
                agent: "/hsrd-test/".to_owned(),
                height: 100,
                no_relay: false,
            }),
            Packet::Verack,
            Packet::Pong([3; 8]),
            Packet::Addr(vec![address]),
            Packet::Inv(vec![Inventory::block(BlockHash::new([1; 32]))]),
            Packet::GetHeaders(LocatorPacket {
                locator: vec![BlockHash::new([2; 32])],
                stop: BlockHash::ZERO,
            }),
            Packet::Headers(vec![Header::default()]),
            Packet::Reject(RejectPacket {
                message: PacketType::Block,
                code: 0x10,
                reason: "bad-block".to_owned(),
                hash: Some([4; 32]),
            }),
            Packet::FeeFilter(12345),
            Packet::SendCmpct {
                mode: 1,
                version: 1,
            },
        ];
        for packet in packets {
            let payload = packet.encode_payload().expect("encode");
            let decoded = Packet::decode(packet.packet_type(), &payload).expect("decode");
            assert_eq!(decoded, packet);
        }
    }

    #[test]
    fn net_address_matches_hsd_normalization_rules() {
        let mut writer = Writer::with_capacity(NET_ADDRESS_SIZE);
        writer.write_u64(123);
        writer.write_u32(7);
        writer.write_u32(0xaabb_ccdd);
        writer.write_u8(9);
        writer.write_bytes(&[0x55; 36]);
        writer.write_u16(14_038);
        writer.write_bytes(&[0x22; 33]);
        let raw = writer.finish();

        let decoded = NetAddress::decode(&raw).expect("decode");
        assert_eq!(decoded.services, 7);
        assert_eq!(decoded.host, AddressHost::Ip([0; 16]));

        let canonical = decoded.encode();
        assert_eq!(&canonical[12..16], &[0; 4]);
        assert_eq!(canonical[16], 0);
        assert_eq!(&canonical[17..53], &[0; 36]);
    }

    #[test]
    fn peer_address_groups_match_hsd_network_prefix_rules() {
        let vectors = [
            ("8.8.4.4", &[0x01, 0x08, 0x08][..]),
            ("8.8.200.1", &[0x01, 0x08, 0x08][..]),
            ("9.9.9.9", &[0x01, 0x09, 0x09][..]),
            ("2001:4860:4860::8888", &[0x02, 0x20, 0x01, 0x48, 0x60][..]),
            ("2001:4860:abcd::1", &[0x02, 0x20, 0x01, 0x48, 0x60][..]),
            (
                "2001:470:1234::1",
                &[0x02, 0x20, 0x01, 0x04, 0x70, 0x1f][..],
            ),
            (
                "2001:470:1fff::1",
                &[0x02, 0x20, 0x01, 0x04, 0x70, 0x1f][..],
            ),
            ("2002:0808:0404::1", &[0x01, 0x08, 0x08][..]),
            (
                "2001:0000:4136:e378:8000:63bf:f7f7:fbfb",
                &[0x01, 0x08, 0x08][..],
            ),
            ("64:ff9b::808:404", &[0x01, 0x08, 0x08][..]),
            ("::ffff:0:808:404", &[0x01, 0x08, 0x08][..]),
            ("127.0.0.1", &[0xff][..]),
            ("10.0.0.1", &[0x00][..]),
        ];

        for (address, expected) in vectors {
            let address = address.parse::<IpAddr>().expect("IP address");
            assert_eq!(
                peer_address_group(address).as_bytes(),
                expected,
                "unexpected HSD group for {address}"
            );
        }
    }

    #[test]
    fn version_no_relay_accepts_only_exact_byte_one() {
        let packet = Packet::Version(VersionPacket {
            version: PROTOCOL_VERSION,
            services: SERVICE_NETWORK,
            time: 1,
            remote: NetAddress::default(),
            nonce: [7; 8],
            agent: "/hsrd-test/".to_owned(),
            height: 2,
            no_relay: false,
        });
        let mut payload = packet.encode_payload().expect("payload");
        let last = payload.last_mut().expect("no-relay byte");
        *last = 2;
        let decoded = Packet::decode(PacketType::Version, &payload).expect("decode");
        let Packet::Version(version) = decoded else {
            panic!("expected version packet");
        };
        assert!(!version.no_relay);
    }

    #[tokio::test]
    async fn split_async_transport_exchanges_packets() {
        let (client_io, server_io) = tokio::io::duplex(1024);
        let (client_read, client_write) = tokio::io::split(client_io);
        let (server_read, _server_write) = tokio::io::split(server_io);
        drop(client_read);
        let mut writer = AsyncFrameWriter::new(client_write, NetworkMagic::Regtest);
        let mut reader = AsyncFrameReader::new(server_read, NetworkMagic::Regtest);
        let packet = Packet::Ping([1; 8]);
        writer.write_packet(&packet).await.expect("write");
        assert_eq!(reader.read_packet().await.expect("read"), packet);
    }

    #[tokio::test]
    async fn async_reader_rejects_oversized_payload_before_allocation() {
        let (mut writer, reader) = tokio::io::duplex(1024);
        let mut transport = AsyncFrameReader::new(reader, NetworkMagic::Regtest);
        let mut header = Writer::with_capacity(FRAME_HEADER_SIZE);
        header.write_u32(NetworkMagic::Regtest.as_u32());
        header.write_u8(PacketType::Block.as_u8());
        header.write_u32((MAX_FRAME_PAYLOAD_SIZE as u32) + 1);
        writer
            .write_all(&header.finish())
            .await
            .expect("write header");
        drop(writer);
        assert!(matches!(
            transport.read_frame().await.expect_err("oversized"),
            P2pError::MalformedFrame(_)
        ));
    }

    #[test]
    fn hsd_header_payload_has_exact_fixed_width() {
        let payload = Packet::Headers(vec![Header::default()])
            .encode_payload()
            .expect("payload");
        assert_eq!(payload.len(), 1 + hns_primitives::HEADER_SIZE);
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0, "hex must have an even length");
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = char::from(pair[0]).to_digit(16).expect("hex high nibble");
                let low = char::from(pair[1]).to_digit(16).expect("hex low nibble");
                ((high << 4) | low) as u8
            })
            .collect()
    }

    fn oracle_address_with_ipv4(ipv4: [u8; 4]) -> NetAddress {
        let mut ip = [0u8; 16];
        ip[10] = 0xff;
        ip[11] = 0xff;
        ip[12..].copy_from_slice(&ipv4);
        let mut key = [0x11; 33];
        key[0] = 0x02;
        NetAddress {
            time: 0x0102_0304,
            services: 0x89ab_cdef,
            host: AddressHost::Ip(ip),
            port: 14_038,
            key,
        }
    }

    fn oracle_address() -> NetAddress {
        oracle_address_with_ipv4([127, 0, 0, 1])
    }

    fn oracle_header() -> Header {
        Header {
            nonce: 0x1234_5678,
            time: 0x0102_0304_0506,
            prev_block: BlockHash::new([0x01; 32]),
            tree_root: [0x04; 32],
            extra_nonce: [0x06; hns_primitives::NONCE_SIZE],
            reserved_root: [0x05; 32],
            witness_root: [0x03; 32],
            merkle_root: [0x02; 32],
            version: 7,
            bits: 0x1d00_ffff,
            mask: [0x07; 32],
        }
    }

    fn oracle_transaction(tag: u8) -> Transaction {
        Transaction {
            version: u32::from(tag),
            inputs: vec![Input {
                previous_output: Outpoint {
                    txid: Txid::new([tag; 32]),
                    index: u32::from(tag),
                },
                sequence: 0xffff_ff00 + u32::from(tag),
                witness: Witness {
                    items: vec![vec![tag, tag + 1]],
                },
            }],
            outputs: vec![Output {
                value: 1_000 + u64::from(tag),
                address: Address {
                    version: 0,
                    hash: vec![0; 20],
                },
                covenant: Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            }],
            locktime: u32::from(tag),
        }
    }

    fn oracle_compact_source() -> Block {
        Block {
            header: oracle_header(),
            transactions: (1..=3).map(oracle_transaction).collect(),
        }
    }

    fn oracle_packet(id: &str) -> Packet {
        match id {
            "version-main" => Packet::Version(VersionPacket {
                version: 3,
                services: SERVICE_NETWORK,
                time: 0x0102_0304_0506,
                // HSD's VersionPacket clones `remote` through its host field.
                // The oracle deliberately leaves that field at 0.0.0.0 while
                // exercising a separately assigned raw address.
                remote: oracle_address_with_ipv4([0; 4]),
                nonce: [1, 2, 3, 4, 5, 6, 7, 8],
                agent: "/hsrd-oracle:0.1.0/".to_owned(),
                height: 123_456,
                no_relay: true,
            }),
            "ping-main" => Packet::Ping([1, 2, 3, 4, 5, 6, 7, 8]),
            "ping-testnet" => Packet::Ping([0x42; 8]),
            "ping-regtest" => Packet::Ping([0x43; 8]),
            "ping-simnet" => Packet::Ping([0x44; 8]),
            "addr-regtest" => Packet::Addr(vec![oracle_address()]),
            "inv-regtest" => Packet::Inv(vec![
                Inventory {
                    kind: InventoryKind::Block,
                    hash: [0x21; 32],
                },
                Inventory {
                    kind: InventoryKind::Unknown(0xfeed_beef),
                    hash: [0x22; 32],
                },
            ]),
            "getheaders-regtest" => Packet::GetHeaders(LocatorPacket {
                locator: vec![BlockHash::new([0x31; 32]), BlockHash::new([0x32; 32])],
                stop: BlockHash::new([0x33; 32]),
            }),
            "headers-regtest" => Packet::Headers(vec![oracle_header()]),
            "block-regtest" => Packet::Block(Block {
                header: Header::default(),
                transactions: Vec::new(),
            }),
            "reject-block-regtest" => Packet::Reject(RejectPacket {
                message: PacketType::Block,
                code: 0x10,
                reason: "bad-block".to_owned(),
                hash: Some([0x51; 32]),
            }),
            "reject-version-regtest" => Packet::Reject(RejectPacket {
                message: PacketType::Version,
                code: 0x11,
                reason: "obsolete".to_owned(),
                hash: None,
            }),
            "feefilter-positive-regtest" => Packet::FeeFilter(1_234_567),
            "feefilter-negative-regtest" => Packet::FeeFilter(-1_234_567),
            "sendcmpct-regtest" => Packet::SendCmpct {
                mode: 1,
                version: 2,
            },
            "cmpctblock-regtest" => Packet::CmpctBlock(CompactBlock::from_block_with_nonce(
                &oracle_compact_source(),
                [1, 2, 3, 4, 5, 6, 7, 8],
            )),
            "getblocktxn-regtest" => {
                let block = oracle_compact_source();
                Packet::GetBlockTxn(CompactBlockRequest::from_block(&block, vec![1, 2]))
            }
            "blocktxn-regtest" => {
                let block = oracle_compact_source();
                let request = CompactBlockRequest::from_block(&block, vec![1, 2]);
                Packet::BlockTxn(CompactBlockResponse::from_block(&block, &request))
            }
            "airdrop-regtest" => {
                let fixture: serde_json::Value = serde_json::from_str(include_str!(
                    "../../../fixtures/hsd/airdrops/codec-v1.json"
                ))
                .expect("airdrop fixture");
                let raw = decode_hex(fixture["faucet"]["raw"].as_str().expect("faucet raw"));
                Packet::Airdrop(AirdropProof::decode(&raw).expect("faucet proof"))
            }
            "claim-main" => {
                let fixture: serde_json::Value = serde_json::from_str(include_str!(
                    "../../../fixtures/hsd/claims/mainnet-history-v1.json"
                ))
                .expect("claim fixture");
                Packet::Claim(Claim {
                    blob: decode_hex(
                        fixture["block"]["claims"][0]["proofRaw"]
                            .as_str()
                            .expect("claim proof"),
                    ),
                })
            }
            other => panic!("unhandled oracle packet {other}"),
        }
    }

    fn oracle_network(name: &str) -> NetworkMagic {
        match name {
            "main" => NetworkMagic::Mainnet,
            "testnet" => NetworkMagic::Testnet,
            "regtest" => NetworkMagic::Regtest,
            "simnet" => NetworkMagic::Simnet,
            other => panic!("unknown oracle network {other}"),
        }
    }

    #[test]
    fn airdrop_packet_uses_the_exact_hsd_proof_payload() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/hsd/airdrops/codec-v1.json"))
                .expect("airdrop fixture");
        let raw = decode_hex(fixture["faucet"]["raw"].as_str().expect("faucet raw"));
        let proof = AirdropProof::decode(&raw).expect("faucet proof");
        let packet = Packet::Airdrop(proof.clone());
        assert_eq!(packet.packet_type(), PacketType::Airdrop);
        assert_eq!(packet.encode_payload().expect("airdrop payload"), raw);
        assert_eq!(
            Packet::decode(PacketType::Airdrop, &raw).expect("airdrop packet"),
            Packet::Airdrop(proof.clone())
        );
        let inventory = Inventory::airdrop(proof.hash().expect("airdrop hash"));
        assert_eq!(inventory.kind, InventoryKind::Airdrop);
        assert_eq!(inventory.hash, proof.hash().expect("airdrop hash"));

        let mut trailing = raw;
        trailing.push(0);
        assert!(Packet::decode(PacketType::Airdrop, &trailing).is_err());
    }

    #[test]
    fn claim_packet_uses_the_exact_hsd_envelope_payload() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/hsd/claims/mainnet-history-v1.json"
        ))
        .expect("claim fixture");
        let claim = Claim {
            blob: decode_hex(
                fixture["block"]["claims"][0]["proofRaw"]
                    .as_str()
                    .expect("claim proof"),
            ),
        };
        let payload = claim.encode().expect("claim payload");
        assert_eq!(
            Packet::Claim(claim.clone()).packet_type(),
            PacketType::Claim
        );
        assert_eq!(
            Packet::Claim(claim.clone())
                .encode_payload()
                .expect("claim payload"),
            payload
        );
        assert_eq!(
            Packet::decode(PacketType::Claim, &payload).expect("claim packet"),
            Packet::Claim(claim.clone())
        );
        assert_eq!(Inventory::claim(claim.hash()).kind, InventoryKind::Claim);

        let mut trailing = payload;
        trailing.push(0);
        assert!(Packet::decode(PacketType::Claim, &trailing).is_err());
    }

    #[test]
    fn compact_block_reconstruction_fills_mempool_and_requested_transactions() {
        let block = oracle_compact_source();
        let compact = CompactBlock::from_block_with_nonce(&block, [1, 2, 3, 4, 5, 6, 7, 8]);
        let mut reconstruction = compact
            .reconstruct(&[block.transactions[1].clone()])
            .expect("initialize compact block");
        assert!(!reconstruction.is_complete());
        let request = reconstruction.missing_request();
        assert_eq!(request.block_hash, block.hash());
        assert_eq!(request.indexes, vec![2]);
        let encoded = Packet::GetBlockTxn(request.clone())
            .encode_payload()
            .expect("encode request");
        assert_eq!(
            Packet::decode(PacketType::GetBlockTxn, &encoded).expect("decode request"),
            Packet::GetBlockTxn(request.clone())
        );

        reconstruction
            .fill_missing(CompactBlockResponse::from_block(&block, &request))
            .expect("fill response");
        assert_eq!(reconstruction.into_block().expect("full block"), block);

        let mut collision = compact.clone();
        collision.short_ids[1] = collision.short_ids[0];
        assert!(matches!(
            collision.reconstruct(&[]),
            Err(CompactBlockError::ShortIdCollision(_))
        ));

        let malformed = CompactBlockRequest {
            block_hash: block.hash(),
            indexes: vec![2, 2],
        };
        assert!(Packet::GetBlockTxn(malformed).encode_payload().is_err());
    }

    #[test]
    fn hsd_oracle_wire_frames_match_byte_for_byte() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/hsd/p2p/wire-v1.json"))
                .expect("hsrd p2p wire fixture");
        assert_eq!(fixture["schema"], 4);
        for case in fixture["frames"].as_array().expect("frame cases") {
            let id = case["id"].as_str().expect("frame id");
            let network = oracle_network(case["network"].as_str().expect("network"));
            let expected_payload = decode_hex(case["payload"].as_str().expect("payload"));
            let expected_frame = decode_hex(case["frame"].as_str().expect("frame"));
            let packet = oracle_packet(id);
            assert_eq!(
                packet.packet_type().as_u8(),
                case["packetType"].as_u64().unwrap() as u8
            );
            assert_eq!(
                packet.encode_payload().expect("payload"),
                expected_payload,
                "{id}"
            );
            assert_eq!(
                Packet::decode(packet.packet_type(), &expected_payload).expect("decode payload"),
                packet,
                "{id}"
            );
            let frame = Frame::from_packet(&packet).expect("frame");
            assert_eq!(
                encode_frame(network, &frame).expect("encode"),
                expected_frame,
                "{id}"
            );
            assert_eq!(
                decode_frame(network, &expected_frame).expect("decode frame"),
                frame,
                "{id}"
            );
        }
    }

    #[test]
    fn hsd_oracle_decode_normalization_matches() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/hsd/p2p/wire-v1.json"))
                .expect("hsrd p2p wire fixture");

        for name in [
            "canonical",
            "noRelayByteTwo",
            "highBitAscii",
            "reservedHighServiceWords",
        ] {
            let payload = decode_hex(
                fixture["versionDecoding"]["payloads"][name]
                    .as_str()
                    .expect("version payload"),
            );
            let Packet::Version(decoded) =
                Packet::decode(PacketType::Version, &payload).expect("decode version")
            else {
                panic!("version fixture decoded to wrong packet");
            };
            let expected = &fixture["versionDecoding"][name];
            assert_eq!(
                decoded.version,
                expected["version"].as_u64().unwrap() as u32
            );
            assert_eq!(decoded.services, expected["services"].as_u64().unwrap());
            assert_eq!(decoded.agent, expected["agent"].as_str().unwrap());
            assert_eq!(decoded.no_relay, expected["noRelay"].as_bool().unwrap());
            assert_eq!(
                decoded.remote.services,
                expected["remote"]["services"].as_u64().unwrap()
            );
        }

        let input = decode_hex(
            fixture["netAddressNormalization"]["unsupportedKindInput"]
                .as_str()
                .unwrap(),
        );
        let decoded = NetAddress::decode(&input).expect("decode unsupported address");
        assert_eq!(decoded.host, AddressHost::Ip([0; 16]));
        assert_eq!(
            decoded.encode(),
            decode_hex(
                fixture["netAddressNormalization"]["canonicalReencode"]
                    .as_str()
                    .unwrap(),
            )
        );
    }
}
