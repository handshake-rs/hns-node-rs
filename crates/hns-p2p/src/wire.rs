use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use hns_consensus::Network;
use hns_primitives::{Block, BlockHash, Header, Reader, Transaction, Txid, Writer};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    constants::{
        FRAME_HEADER_SIZE, MAX_ADDR_ITEMS, MAX_FRAME_PAYLOAD_SIZE, MAX_HEADERS,
        MAX_INVENTORY_ITEMS, MAX_LOCATOR_HASHES, MAX_REJECT_REASON_SIZE, MAX_USER_AGENT_SIZE,
        NET_ADDRESS_SIZE,
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
    Reject(RejectPacket),
    Mempool,
    FeeFilter(i64),
    SendCmpct {
        mode: u8,
        version: u64,
    },
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
            Self::Reject(_) => PacketType::Reject,
            Self::Mempool => PacketType::Mempool,
            Self::FeeFilter(_) => PacketType::FeeFilter,
            Self::SendCmpct { .. } => PacketType::SendCmpct,
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
            PacketType::FilterLoad
            | PacketType::FilterAdd
            | PacketType::FilterClear
            | PacketType::MerkleBlock
            | PacketType::CmpctBlock
            | PacketType::GetBlockTxn
            | PacketType::BlockTxn
            | PacketType::GetProof
            | PacketType::Proof
            | PacketType::Claim
            | PacketType::Airdrop
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
    fn hsd_oracle_wire_frames_match_byte_for_byte() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../../fixtures/hsd/p2p/wire-v1.json"))
                .expect("hsrd p2p wire fixture");
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
