//! Handshake P2P protocol constants.
//!
//! Values in this module are pinned to the HSD oracle revision documented by
//! the workspace fixture manifest. Local operational bounds may be stricter,
//! but wire codecs must not silently exceed these limits.

pub const PROTOCOL_VERSION: u32 = 3;
pub const MIN_PROTOCOL_VERSION: u32 = 1;
pub const SERVICE_NETWORK: u64 = 1 << 0;
pub const SERVICE_BLOOM: u64 = 1 << 1;
pub const DEFAULT_USER_AGENT: &str = "/hsrd:0.1.0/";

pub const FRAME_HEADER_SIZE: usize = 9;
pub const MAX_FRAME_PAYLOAD_SIZE: usize = 8_000_000;
pub const MAX_INVENTORY_ITEMS: usize = 50_000;
pub const MAX_LOCATOR_HASHES: usize = MAX_INVENTORY_ITEMS;
pub const MAX_HEADERS: usize = 2_000;
/// HSD's compact-block hash-DoS bound, derived from the one-megabyte base
/// block size, the 236-byte HNS header, one transaction-count byte, and the
/// 60-byte minimum serialized transaction size.
pub const MAX_COMPACT_BLOCK_TRANSACTIONS: usize = 16_662;

/// HSD does not impose a dedicated ADDR item-count assertion, so the frame
/// bound is the ultimate protocol limit. HSRD intentionally applies a much
/// smaller operational ceiling to avoid allocating tens of thousands of
/// 88-byte address records from an unsolicited packet.
pub const MAX_ADDR_ITEMS: usize = 1_000;
pub const MAX_USER_AGENT_SIZE: usize = u8::MAX as usize;
pub const MAX_REJECT_REASON_SIZE: usize = u8::MAX as usize;
pub const NET_ADDRESS_SIZE: usize = 88;
pub const BAN_SCORE: i32 = 100;
