use std::{
    cmp::Reverse,
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use anyhow::{Context, Result};
use hns_consensus::Network;
use hns_p2p::{normalize_peer_ip, PeerBan};
use hns_primitives::{blake2b_256, Reader, Writer};
use hns_store::{ColumnFamily, ReadSnapshot, Store, StoreHandle, WriteBatch};

pub(crate) const HSD_BAN_SCORE: u32 = 100;
pub(crate) const HSD_BAN_TIME_SECONDS: u64 = 24 * 60 * 60;
pub(crate) const MAX_PEER_BANS: usize = 16_384;

const BAN_LIST_KEY: &[u8] = b"ban-list/v1";
const BAN_LIST_MAGIC: &[u8; 4] = b"HBL1";
const BAN_LIST_VERSION: u8 = 1;
const BAN_LIST_CHECKSUM_SIZE: usize = 32;
const BAN_LIST_HEADER_SIZE: usize = 26;
const BAN_LIST_ENTRY_SIZE: usize = 41;
const MAX_BAN_LIST_RECORD_SIZE: usize =
    BAN_LIST_HEADER_SIZE + MAX_PEER_BANS * BAN_LIST_ENTRY_SIZE + BAN_LIST_CHECKSUM_SIZE;

#[derive(Clone, Debug, Eq, PartialEq)]
struct PersistedPeerBan {
    address: IpAddr,
    banned_at: u64,
    ban_until: u64,
    sequence: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct PeerBanRecord {
    network: Network,
    generation: u64,
    updated_at: u64,
    entries: Vec<PersistedPeerBan>,
}

#[derive(Clone, Debug)]
struct PeerBanEntry {
    banned_at: u64,
    ban_until: u64,
    sequence: u64,
}

#[derive(Debug)]
pub(crate) struct PeerBanBook {
    network: Network,
    maximum: usize,
    sequence: u64,
    durable_sequence: u64,
    dirty: bool,
    entries: BTreeMap<IpAddr, PeerBanEntry>,
}

#[derive(Debug)]
pub(crate) struct PeerBanLoad {
    pub book: PeerBanBook,
    pub loaded: usize,
    pub pruned: usize,
    pub decode_error: Option<String>,
}

impl PeerBanBook {
    pub fn new(network: Network, maximum: usize) -> Result<Self> {
        if maximum == 0 || maximum > MAX_PEER_BANS {
            anyhow::bail!("peer-ban limit {maximum} must be within 1..={MAX_PEER_BANS}");
        }
        Ok(Self {
            network,
            maximum,
            sequence: 0,
            durable_sequence: 0,
            dirty: false,
            entries: BTreeMap::new(),
        })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub const fn durable_sequence(&self) -> u64 {
        self.durable_sequence
    }

    pub const fn is_dirty(&self) -> bool {
        self.dirty
    }

    pub fn is_banned(&self, address: IpAddr, now: u64) -> bool {
        self.entries
            .get(&normalize_peer_ip(address))
            .is_some_and(|entry| now <= entry.ban_until)
    }

    pub fn active_bans(&self, now: u64) -> Vec<(IpAddr, u64)> {
        self.entries
            .iter()
            .filter_map(|(address, entry)| {
                (now <= entry.ban_until).then_some((*address, entry.ban_until))
            })
            .collect()
    }

    pub fn ban(&mut self, ban: &PeerBan) -> Result<bool> {
        let address = normalize_peer_ip(ban.address);
        if !is_valid_ban_address(address) {
            anyhow::bail!("invalid peer-ban address {address}");
        }
        if ban.ban_until < ban.banned_at {
            anyhow::bail!("peer ban for {address} expires before its creation timestamp");
        }

        if self.entries.get(&address).is_some_and(|entry| {
            entry.banned_at == ban.banned_at && entry.ban_until == ban.ban_until
        }) {
            return Ok(false);
        }

        self.sequence = self.sequence.saturating_add(1);
        if let Some(entry) = self.entries.get_mut(&address) {
            entry.banned_at = ban.banned_at;
            entry.ban_until = ban.ban_until;
            entry.sequence = self.sequence;
            self.dirty = true;
            return Ok(true);
        }

        if self.entries.len() >= self.maximum {
            let eviction = self
                .entries
                .iter()
                .min_by_key(|(address, entry)| (entry.ban_until, entry.sequence, **address))
                .map(|(address, _)| *address)
                .expect("a full nonzero ban list has an eviction candidate");
            self.entries.remove(&eviction);
        }
        self.entries.insert(
            address,
            PeerBanEntry {
                banned_at: ban.banned_at,
                ban_until: ban.ban_until,
                sequence: self.sequence,
            },
        );
        self.dirty = true;
        Ok(true)
    }

    pub fn remove_expired(&mut self, now: u64) -> usize {
        let before = self.entries.len();
        self.entries.retain(|_, entry| now <= entry.ban_until);
        let removed = before.saturating_sub(self.entries.len());
        self.dirty |= removed > 0;
        removed
    }

    fn durable_entries(&self) -> Vec<PersistedPeerBan> {
        self.entries
            .iter()
            .map(|(address, entry)| PersistedPeerBan {
                address: *address,
                banned_at: entry.banned_at,
                ban_until: entry.ban_until,
                sequence: entry.sequence,
            })
            .collect()
    }

    fn restore(&mut self, mut record: PeerBanRecord, now: u64) -> Result<(usize, usize)> {
        if record.network != self.network {
            anyhow::bail!(
                "peer-ban network {} does not match configured {}",
                record.network,
                self.network
            );
        }
        let original = record.entries.len();
        record.entries.retain(|entry| {
            is_valid_ban_address(entry.address)
                && entry.banned_at <= entry.ban_until
                && now <= entry.ban_until
        });
        record.entries.sort_by_key(|entry| {
            (
                Reverse(entry.ban_until),
                Reverse(entry.banned_at),
                entry.sequence,
                entry.address,
            )
        });

        let mut loaded = 0usize;
        for entry in record.entries.into_iter().take(self.maximum) {
            self.sequence = self.sequence.max(entry.sequence);
            self.entries.insert(
                normalize_peer_ip(entry.address),
                PeerBanEntry {
                    banned_at: entry.banned_at,
                    ban_until: entry.ban_until,
                    sequence: entry.sequence,
                },
            );
            loaded = loaded.saturating_add(1);
        }
        self.durable_sequence = record.generation;
        let pruned = original.saturating_sub(loaded);
        self.dirty = pruned > 0;
        Ok((loaded, pruned))
    }
}

pub(crate) fn load_peer_bans(
    store: &StoreHandle,
    network: Network,
    maximum: usize,
    now: u64,
) -> Result<PeerBanLoad> {
    let mut book = PeerBanBook::new(network, maximum)?;
    let raw = {
        let snapshot = store
            .snapshot()
            .context("failed to open peer-ban snapshot")?;
        snapshot
            .get(ColumnFamily::Peers, BAN_LIST_KEY)
            .context("failed to read durable peer-ban list")?
    };
    let Some(raw) = raw else {
        return Ok(PeerBanLoad {
            book,
            loaded: 0,
            pruned: 0,
            decode_error: None,
        });
    };
    match PeerBanRecord::decode(&raw, network).and_then(|record| book.restore(record, now)) {
        Ok((loaded, pruned)) => Ok(PeerBanLoad {
            book,
            loaded,
            pruned,
            decode_error: None,
        }),
        Err(error) => {
            book.dirty = true;
            Ok(PeerBanLoad {
                book,
                loaded: 0,
                pruned: 0,
                decode_error: Some(error.to_string()),
            })
        }
    }
}

pub(crate) fn persist_peer_bans(
    store: &StoreHandle,
    bans: &mut PeerBanBook,
    timestamp: u64,
) -> Result<bool> {
    if !bans.dirty {
        return Ok(false);
    }
    let generation = bans
        .durable_sequence
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("peer-ban generation exhausted"))?;
    let record = PeerBanRecord {
        network: bans.network,
        generation,
        updated_at: timestamp,
        entries: bans.durable_entries(),
    };
    let raw = record.encode()?;
    let mut batch = store.batch();
    batch.put(ColumnFamily::Peers, BAN_LIST_KEY, &raw)?;
    store.commit(batch)?;
    bans.durable_sequence = generation;
    bans.dirty = false;
    Ok(true)
}

impl PeerBanRecord {
    fn encode(&self) -> Result<Vec<u8>> {
        if self.entries.len() > MAX_PEER_BANS {
            anyhow::bail!(
                "peer-ban record has {} entries; maximum is {MAX_PEER_BANS}",
                self.entries.len()
            );
        }
        let count = u32::try_from(self.entries.len())
            .map_err(|_| anyhow::anyhow!("peer-ban entry count exceeds u32"))?;
        let mut writer = Writer::with_capacity(
            BAN_LIST_HEADER_SIZE
                + self.entries.len() * BAN_LIST_ENTRY_SIZE
                + BAN_LIST_CHECKSUM_SIZE,
        );
        writer.write_bytes(BAN_LIST_MAGIC);
        writer.write_u8(BAN_LIST_VERSION);
        writer.write_u8(self.network.canonical_id());
        writer.write_u64(self.generation);
        writer.write_u64(self.updated_at);
        writer.write_u32(count);
        for entry in &self.entries {
            write_ip(&mut writer, entry.address);
            writer.write_u64(entry.banned_at);
            writer.write_u64(entry.ban_until);
            writer.write_u64(entry.sequence);
        }
        let mut raw = writer.finish();
        raw.extend_from_slice(&blake2b_256(&raw));
        Ok(raw)
    }

    fn decode(raw: &[u8], expected_network: Network) -> Result<Self> {
        if raw.len() < BAN_LIST_HEADER_SIZE + BAN_LIST_CHECKSUM_SIZE
            || raw.len() > MAX_BAN_LIST_RECORD_SIZE
        {
            anyhow::bail!("peer-ban record has invalid length {}", raw.len());
        }
        let body_len = raw.len() - BAN_LIST_CHECKSUM_SIZE;
        let (body, checksum) = raw.split_at(body_len);
        if checksum != blake2b_256(body) {
            anyhow::bail!("peer-ban checksum mismatch");
        }
        let mut reader = Reader::new(body, MAX_BAN_LIST_RECORD_SIZE)?;
        if reader.read_vec(BAN_LIST_MAGIC.len())? != BAN_LIST_MAGIC {
            anyhow::bail!("peer-ban magic mismatch");
        }
        let version = reader.read_u8()?;
        if version != BAN_LIST_VERSION {
            anyhow::bail!("unsupported peer-ban version {version}");
        }
        let network_id = reader.read_u8()?;
        let network = Network::from_canonical_id(network_id)
            .ok_or_else(|| anyhow::anyhow!("unknown peer-ban network ID {network_id}"))?;
        if network != expected_network {
            anyhow::bail!(
                "peer-ban network {network} does not match configured {expected_network}"
            );
        }
        let generation = reader.read_u64()?;
        let updated_at = reader.read_u64()?;
        let count = usize::try_from(reader.read_u32()?)
            .map_err(|_| anyhow::anyhow!("peer-ban count exceeds usize"))?;
        if count > MAX_PEER_BANS {
            anyhow::bail!("peer-ban record has {count} entries; maximum is {MAX_PEER_BANS}");
        }
        let expected_body_len = BAN_LIST_HEADER_SIZE
            .checked_add(count.saturating_mul(BAN_LIST_ENTRY_SIZE))
            .ok_or_else(|| anyhow::anyhow!("peer-ban record length overflow"))?;
        if body.len() != expected_body_len {
            anyhow::bail!(
                "peer-ban body has {} bytes; expected {expected_body_len}",
                body.len()
            );
        }
        let mut entries = Vec::with_capacity(count);
        let mut seen = BTreeSet::new();
        for _ in 0..count {
            let address = read_ip(&mut reader)?;
            if !seen.insert(address) {
                anyhow::bail!("peer-ban record contains duplicate address {address}");
            }
            entries.push(PersistedPeerBan {
                address,
                banned_at: reader.read_u64()?,
                ban_until: reader.read_u64()?,
                sequence: reader.read_u64()?,
            });
        }
        reader.ensure_finished()?;
        Ok(Self {
            network,
            generation,
            updated_at,
            entries,
        })
    }
}

fn write_ip(writer: &mut Writer, address: IpAddr) {
    match normalize_peer_ip(address) {
        IpAddr::V4(address) => {
            writer.write_u8(4);
            writer.write_bytes(&address.octets());
            writer.write_bytes(&[0; 12]);
        }
        IpAddr::V6(address) => {
            writer.write_u8(6);
            writer.write_bytes(&address.octets());
        }
    }
}

fn read_ip(reader: &mut Reader<'_>) -> Result<IpAddr> {
    let family = reader.read_u8()?;
    let bytes = reader.read_vec(16)?;
    match family {
        4 => {
            if bytes[4..] != [0; 12] {
                anyhow::bail!("peer-ban IPv4 padding is nonzero");
            }
            Ok(IpAddr::V4(Ipv4Addr::new(
                bytes[0], bytes[1], bytes[2], bytes[3],
            )))
        }
        6 => {
            let bytes: [u8; 16] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("peer-ban IPv6 length mismatch"))?;
            Ok(normalize_peer_ip(IpAddr::V6(Ipv6Addr::from(bytes))))
        }
        other => anyhow::bail!("unknown peer-ban address family {other}"),
    }
}

fn is_valid_ban_address(address: IpAddr) -> bool {
    match normalize_peer_ip(address) {
        IpAddr::V4(address) => {
            !address.is_unspecified() && !address.is_multicast() && !address.is_broadcast()
        }
        IpAddr::V6(address) => !address.is_unspecified() && !address.is_multicast(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ban(address: &str, banned_at: u64, ban_until: u64) -> PeerBan {
        PeerBan {
            address: address.parse().expect("IP"),
            banned_at,
            ban_until,
            score: 100,
        }
    }

    #[test]
    fn peer_ban_record_is_versioned_network_bound_and_checksummed() {
        let record = PeerBanRecord {
            network: Network::Mainnet,
            generation: 3,
            updated_at: 1_800_000_000,
            entries: vec![
                PersistedPeerBan {
                    address: "8.8.8.8".parse().expect("IPv4"),
                    banned_at: 1_800_000_000,
                    ban_until: 1_800_086_400,
                    sequence: 1,
                },
                PersistedPeerBan {
                    address: "2606:4700:4700::1111".parse().expect("IPv6"),
                    banned_at: 1_800_000_001,
                    ban_until: 1_800_086_401,
                    sequence: 2,
                },
            ],
        };
        let raw = record.encode().expect("encode");
        assert_eq!(
            raw.len(),
            BAN_LIST_HEADER_SIZE + 2 * BAN_LIST_ENTRY_SIZE + BAN_LIST_CHECKSUM_SIZE
        );
        assert_eq!(
            PeerBanRecord::decode(&raw, Network::Mainnet).expect("decode"),
            record
        );
        assert!(PeerBanRecord::decode(&raw, Network::Testnet)
            .expect_err("network binding")
            .to_string()
            .contains("network"));

        let mut corrupt = raw;
        corrupt[BAN_LIST_HEADER_SIZE] ^= 1;
        assert!(PeerBanRecord::decode(&corrupt, Network::Mainnet)
            .expect_err("checksum")
            .to_string()
            .contains("checksum"));
    }

    #[test]
    fn durable_peer_bans_round_trip_expire_and_remain_bounded() {
        let now = 1_800_000_000;
        let store = StoreHandle::memory();
        let mut bans = PeerBanBook::new(Network::Mainnet, 2).expect("book");
        bans.ban(&ban("8.8.8.8", now, now + 100)).expect("first");
        bans.ban(&ban("1.1.1.1", now, now + 200)).expect("second");
        bans.ban(&ban("9.9.9.9", now, now + 300)).expect("third");
        assert_eq!(bans.len(), 2);
        assert!(!bans.is_banned("8.8.8.8".parse().expect("IP"), now));
        assert!(persist_peer_bans(&store, &mut bans, now).expect("persist"));
        assert!(!persist_peer_bans(&store, &mut bans, now).expect("clean no-op"));

        let loaded = load_peer_bans(&store, Network::Mainnet, 2, now + 250).expect("load");
        assert_eq!((loaded.loaded, loaded.pruned), (1, 1));
        assert!(loaded.decode_error.is_none());
        assert!(loaded
            .book
            .is_banned("9.9.9.9".parse().expect("IP"), now + 250));
        assert!(!loaded
            .book
            .is_banned("1.1.1.1".parse().expect("IP"), now + 250));
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn durable_peer_ban_survives_rocksdb_reopen() {
        let path = std::env::temp_dir().join(format!(
            "hsrd-peer-ban-reopen-{}-{}",
            std::process::id(),
            crate::current_unix_time().expect("time")
        ));
        let _ = std::fs::remove_dir_all(&path);
        let config = hns_store::StoreConfig {
            path: path.clone(),
            backend: hns_store::StoreBackend::RocksDb,
            durability: hns_store::DurabilityPolicy::Sync,
        };
        let now = 1_800_000_000;
        {
            let store = hns_store::open_store(&config).expect("open");
            let mut bans = PeerBanBook::new(Network::Mainnet, 4).expect("book");
            bans.ban(&ban("8.8.8.8", now, now + HSD_BAN_TIME_SECONDS))
                .expect("ban");
            assert!(persist_peer_bans(&store, &mut bans, now).expect("persist"));
        }
        {
            let store = hns_store::open_store(&config).expect("reopen");
            let loaded = load_peer_bans(&store, Network::Mainnet, 4, now + 1).expect("load");
            assert_eq!((loaded.loaded, loaded.pruned), (1, 0));
            assert!(loaded
                .book
                .is_banned("8.8.8.8".parse().expect("IP"), now + 1));
        }
        std::fs::remove_dir_all(&path).expect("remove store");
    }
}
