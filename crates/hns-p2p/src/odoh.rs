//! Authenticated, bounded HIP-77 requester state for live HNS peers.
//!
//! The runtime deliberately implements only the privacy-preserving requester
//! side. It neither decrypts target queries nor performs DNS output work. A
//! caller supplies signed target records, and the live peer manager selects a
//! distinct Brontide-authenticated proxy before this state creates an HPKE
//! query. Public signed target metadata has a checksummed restart format;
//! proxy connections, request IDs, HPKE contexts, and in-flight work never do.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::SocketAddr,
    time::Duration,
};

pub use hns_odoh_protocol::DirectTargetLocator;
use hns_odoh_protocol::{
    seal_query, ClientQuery, GetConfigBody, OdnsPacket, OdohConfig, OdohConfigBody, OdohErrorBody,
    OdohOpcode, OdohProtocolError, OdohResponseBody, QueryContext, TargetConfigRecord,
    MAX_ODOH_CONFIG_SIZE, MAX_ODOH_PACKET_SIZE, MAX_ODOH_QUERY_SIZE, MAX_OUTER_PADDING_SIZE,
};
use hns_p2p_experimental::{
    ExperimentalWireProfile, NegotiatedRegistry, Network as ExperimentalNetwork,
    DENUO_EXTENSION_SERVICE, DENUO_V1_REGISTRY_FINGERPRINT, DENUO_V1_REGISTRY_PROTOCOL_VERSION,
    DENUO_V1_REGISTRY_VERSION, DENUO_V1_WIRE_PROFILE, ODOH_PACKET, ODOH_SERVICE,
    REGISTRY_NEGOTIATION_PROTOCOL_ID,
};
use hns_primitives::blake2b_256_many;
use serde::{Deserialize, Serialize};
use tokio::{sync::oneshot, time::Instant};

use crate::{AuthenticatedPeerKey, Packet, PacketType, PeerDirection, PeerId, PeerTransportKind};

pub const fn is_odoh_packet_type(packet_type: PacketType) -> bool {
    matches!(packet_type, PacketType::Unknown(value) if value == ODOH_PACKET.value())
}

pub const ODOH_DEFAULT_MAXIMUM_LIVE_REQUESTS: u16 = 64;
pub const ODOH_MAXIMUM_TARGET_CACHE_BLOB_BYTES: usize = 264_224;
const ODOH_MAXIMUM_CACHED_TARGETS: usize = 16;
const ODOH_MAXIMUM_TARGET_RECORD_BYTES: usize = MAX_ODOH_CONFIG_SIZE;
const ODOH_MAXIMUM_TARGET_LOCATOR_BYTES: usize = 64;
const ODOH_TARGET_CACHE_MAGIC: &[u8; 8] = b"HNSODC1\0";
const ODOH_TARGET_CACHE_SCHEMA: u16 = 2;
const ODOH_TARGET_CACHE_CHECKSUM_BYTES: usize = 32;
const ODOH_DURABLE_FLOOR_MAGIC: &[u8; 8] = b"HNSODF1\0";
const ODOH_DURABLE_FLOOR_SCHEMA: u16 = 1;
const ODOH_DURABLE_FLOOR_BYTES: usize = 70;

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OdohRuntimePhase {
    AwaitingProxy,
    AwaitingTarget,
    Ready,
    Disabled,
    Revoked,
    ClockRollback,
}

impl OdohRuntimePhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingProxy => "awaiting-proxy",
            Self::AwaitingTarget => "awaiting-target",
            Self::Ready => "ready",
            Self::Disabled => "disabled",
            Self::Revoked => "revoked",
            Self::ClockRollback => "clock-rollback",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum OdohFailureReason {
    RequesterDisabled,
    UnauthenticatedProxy,
    RemoteServiceNotAdvertised,
    RegistryNotNegotiated,
    ProxyTargetCollision,
    TargetUnavailable,
    TargetExpired,
    CapacityExceeded,
    RequestTooLarge,
    PacketTooLarge,
    InvalidLocalRequest,
    MalformedResponse,
    UnexpectedOpcode,
    UncorrelatedResponse,
    WrongProxy,
    DeadlineExpired,
    StaleGeneration,
    Revoked,
    Disconnected,
    LocalSendUnavailable,
    TrustedTimeRollback,
}

impl fmt::Display for OdohFailureReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}",
            match self {
                Self::RequesterDisabled => "requester-disabled",
                Self::UnauthenticatedProxy => "unauthenticated-proxy",
                Self::RemoteServiceNotAdvertised => "remote-service-not-advertised",
                Self::RegistryNotNegotiated => "registry-not-negotiated",
                Self::ProxyTargetCollision => "proxy-target-collision",
                Self::TargetUnavailable => "target-unavailable",
                Self::TargetExpired => "target-expired",
                Self::CapacityExceeded => "capacity-exceeded",
                Self::RequestTooLarge => "request-too-large",
                Self::PacketTooLarge => "packet-too-large",
                Self::InvalidLocalRequest => "invalid-local-request",
                Self::MalformedResponse => "malformed-response",
                Self::UnexpectedOpcode => "unexpected-opcode",
                Self::UncorrelatedResponse => "uncorrelated-response",
                Self::WrongProxy => "wrong-proxy",
                Self::DeadlineExpired => "deadline-expired",
                Self::StaleGeneration => "stale-generation",
                Self::Revoked => "revoked",
                Self::Disconnected => "disconnected",
                Self::LocalSendUnavailable => "local-send-unavailable",
                Self::TrustedTimeRollback => "trusted-time-rollback",
            }
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OdohRequesterConfig {
    pub enabled: bool,
    pub maximum_live_requests: u16,
    pub request_timeout: Duration,
    pub outer_padding_bucket: usize,
    pub allow_private_targets: bool,
}

impl Default for OdohRequesterConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            maximum_live_requests: ODOH_DEFAULT_MAXIMUM_LIVE_REQUESTS,
            request_timeout: Duration::from_secs(10),
            outer_padding_bucket: 512,
            allow_private_targets: false,
        }
    }
}

impl OdohRequesterConfig {
    pub fn validate(self) -> Result<Self, OdohCacheError> {
        if self.maximum_live_requests == 0
            || self.maximum_live_requests > 256
            || self.request_timeout.is_zero()
            || self.request_timeout > Duration::from_secs(60)
            || (self.outer_padding_bucket != 0
                && (!(128..=MAX_OUTER_PADDING_SIZE).contains(&self.outer_padding_bucket)
                    || !self.outer_padding_bucket.is_power_of_two()))
        {
            return Err(OdohCacheError::InvalidConfiguration);
        }
        Ok(self)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OdohPeerProvenance {
    pub peer: PeerId,
    pub address: SocketAddr,
    pub direction: PeerDirection,
    pub transport: PeerTransportKind,
    pub authenticated_remote_static: Option<AuthenticatedPeerKey>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OdohProxyAdmission {
    pub provenance: OdohPeerProvenance,
    pub remote_services: u64,
    pub wire_profile: ExperimentalWireProfile,
    pub negotiated: NegotiatedRegistry,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OdohNetworkBinding {
    pub magic: u32,
    pub network: ExperimentalNetwork,
    pub genesis_hash: [u8; 32],
}

impl OdohNetworkBinding {
    pub fn for_network(network: hns_consensus::Network) -> Self {
        let experimental = match network {
            hns_consensus::Network::Mainnet => ExperimentalNetwork::Mainnet,
            hns_consensus::Network::Testnet => ExperimentalNetwork::Testnet,
            hns_consensus::Network::Regtest => ExperimentalNetwork::Regtest,
            hns_consensus::Network::Simnet => ExperimentalNetwork::Simnet,
        };
        Self {
            magic: network.params().packet_magic,
            network: experimental,
            genesis_hash: network.params().genesis_hash.into_inner(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OdohRequestAdmission {
    pub request_id: u64,
    pub generation: u64,
    pub deadline: Instant,
    pub proxy: OdohPeerProvenance,
    pub target: AuthenticatedPeerKey,
}

#[derive(Debug)]
pub struct OdohPendingRequest {
    pub admission: OdohRequestAdmission,
    outcome: oneshot::Receiver<OdohRequestOutcome>,
}

impl OdohPendingRequest {
    pub async fn outcome(self) -> OdohRequestOutcome {
        self.outcome
            .await
            .unwrap_or(OdohRequestOutcome::Disconnected)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OdohUntrustedDnsResponse(pub Vec<u8>);

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OdohRequestOutcome {
    Response {
        proxy: OdohPeerProvenance,
        target: AuthenticatedPeerKey,
        response: OdohUntrustedDnsResponse,
    },
    ConfigurationInstalled {
        record_id: [u8; 32],
        sequence: u64,
        expires_at: u64,
    },
    RemoteError {
        status: hns_odoh_protocol::OdohStatus,
        retry_after: u32,
        error_class: u16,
    },
    Expired,
    Revoked,
    Disconnected,
    LocalSendUnavailable,
    Rejected(OdohFailureReason),
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct OdohProcessTotals {
    pub requests_created: u64,
    pub requests_socket_written: u64,
    pub responses_received: u64,
    pub configurations_installed: u64,
    pub socket_write_failures: u64,
    pub expired_requests: u64,
    pub revoked_requests: u64,
    pub rejected_packets: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct OdohRequesterStatus {
    pub schema_version: u16,
    pub phase: OdohRuntimePhase,
    pub policy_generation: u64,
    pub requester_enabled: bool,
    pub requester_default_enabled: bool,
    pub service_bit: u64,
    pub packet_type: u8,
    pub registry_fingerprint: String,
    pub registry_wire_profile: String,
    pub eligible_authenticated_proxies: u64,
    pub faulted_proxies: u64,
    pub target_slots: u16,
    pub current_targets: u16,
    pub earliest_target_expiry: u64,
    pub live_requests: u16,
    pub maximum_live_requests: u16,
    pub cache_generation: u64,
    pub cache_dirty: bool,
    pub policy_dirty: bool,
    pub durable_state_dirty: bool,
    pub trusted_time_high_water: u64,
    pub proxy_provider_available: bool,
    pub target_provider_available: bool,
    pub output_provider_available: bool,
    pub process: OdohProcessTotals,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OdohTargetCacheSnapshot {
    pub generation: u64,
    pub policy_generation: u64,
    pub trusted_time_high_water: u64,
    pub bytes: Vec<u8>,
}

impl OdohTargetCacheSnapshot {
    pub const fn durable_floor(&self) -> OdohDurableFloor {
        OdohDurableFloor {
            cache_generation: self.generation,
            policy_generation: self.policy_generation,
            trusted_time_high_water: self.trusted_time_high_water,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OdohDurableFloor {
    pub cache_generation: u64,
    pub policy_generation: u64,
    pub trusted_time_high_water: u64,
}

impl OdohDurableFloor {
    pub fn encode(self, network_magic: u32) -> Vec<u8> {
        let mut output = Vec::with_capacity(ODOH_DURABLE_FLOOR_BYTES);
        output.extend_from_slice(ODOH_DURABLE_FLOOR_MAGIC);
        output.extend_from_slice(&ODOH_DURABLE_FLOOR_SCHEMA.to_le_bytes());
        output.extend_from_slice(&network_magic.to_le_bytes());
        output.extend_from_slice(&self.cache_generation.to_le_bytes());
        output.extend_from_slice(&self.policy_generation.to_le_bytes());
        output.extend_from_slice(&self.trusted_time_high_water.to_le_bytes());
        let checksum = blake2b_256_many([output.as_slice()]);
        output.extend_from_slice(&checksum);
        output
    }

    pub fn decode(input: &[u8], network_magic: u32) -> Result<Self, OdohCacheError> {
        if input.len() != ODOH_DURABLE_FLOOR_BYTES {
            return Err(OdohCacheError::InvalidDurableFloor);
        }
        let payload_length = input.len() - ODOH_TARGET_CACHE_CHECKSUM_BYTES;
        let (payload, checksum) = input.split_at(payload_length);
        if blake2b_256_many([payload]).as_slice() != checksum {
            return Err(OdohCacheError::ChecksumMismatch);
        }
        let mut decoder = CacheDecoder::new(payload);
        if decoder.take(8)? != ODOH_DURABLE_FLOOR_MAGIC {
            return Err(OdohCacheError::InvalidDurableFloor);
        }
        if decoder.u16()? != ODOH_DURABLE_FLOOR_SCHEMA {
            return Err(OdohCacheError::UnsupportedSnapshotSchema);
        }
        if decoder.u32()? != network_magic {
            return Err(OdohCacheError::NetworkMismatch);
        }
        let floor = Self {
            cache_generation: decoder.u64()?,
            policy_generation: decoder.u64()?,
            trusted_time_high_water: decoder.u64()?,
        };
        decoder.finish()?;
        if floor.cache_generation == 0 || floor.policy_generation == 0 {
            return Err(OdohCacheError::InvalidDurableFloor);
        }
        Ok(floor)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum OdohCacheError {
    #[error("invalid ODoH requester configuration")]
    InvalidConfiguration,
    #[error("invalid ODoH target record length")]
    InvalidRecordLength,
    #[error("invalid ODoH target locator")]
    InvalidLocator,
    #[error("invalid ODoH target configuration index")]
    InvalidConfigurationIndex,
    #[error("ODoH target sequence rollback")]
    SequenceRollback,
    #[error("ODoH target sequence conflict")]
    SequenceConflict,
    #[error("ODoH target cache is full")]
    CacheFull,
    #[error("invalid ODoH target-cache snapshot")]
    InvalidSnapshot,
    #[error("invalid ODoH durable generation floor")]
    InvalidDurableFloor,
    #[error("unsupported ODoH target-cache snapshot schema")]
    UnsupportedSnapshotSchema,
    #[error("ODoH target-cache network mismatch")]
    NetworkMismatch,
    #[error("ODoH target-cache address policy mismatch")]
    AddressPolicyMismatch,
    #[error("ODoH target-cache checksum mismatch")]
    ChecksumMismatch,
    #[error("noncanonical ODoH target-cache ordering")]
    NonCanonicalSnapshot,
    #[error("ODoH durable generation rollback")]
    GenerationRollback,
    #[error("ODoH durable generation exhausted")]
    GenerationExhausted,
    #[error("ODoH trusted time moved below its durable high-water mark")]
    TrustedTimeRollback,
    #[error(transparent)]
    Protocol(#[from] OdohProtocolError),
}

#[derive(Clone, Debug)]
struct VerifiedTarget {
    locator: DirectTargetLocator,
    configuration: OdohConfig,
    record_id: [u8; 32],
    sequence: u64,
    expires_at: u64,
    configuration_index: u16,
    signed_record: Vec<u8>,
}

impl VerifiedTarget {
    fn decode(
        locator: DirectTargetLocator,
        signed_record: &[u8],
        configuration_index: usize,
        network_magic: u32,
        now: u64,
        allow_private: bool,
    ) -> Result<Self, OdohCacheError> {
        if signed_record.is_empty() || signed_record.len() > ODOH_MAXIMUM_TARGET_RECORD_BYTES {
            return Err(OdohCacheError::InvalidRecordLength);
        }
        let configuration_index = u16::try_from(configuration_index)
            .map_err(|_| OdohCacheError::InvalidConfigurationIndex)?;
        let record = TargetConfigRecord::decode_and_verify(
            signed_record,
            &locator,
            network_magic,
            now,
            allow_private,
        )?;
        let configuration = record
            .configurations
            .get(usize::from(configuration_index))
            .cloned()
            .ok_or(OdohCacheError::InvalidConfigurationIndex)?;
        Ok(Self {
            locator,
            configuration,
            record_id: record.record_id,
            sequence: record.sequence,
            expires_at: record.expires_at,
            configuration_index,
            signed_record: signed_record.to_vec(),
        })
    }
}

#[derive(Clone, Debug)]
struct TargetSlot {
    locator: DirectTargetLocator,
    highest_sequence: u64,
    current: Option<VerifiedTarget>,
}

#[derive(Clone, Debug)]
struct TargetCache {
    network_magic: u32,
    allow_private: bool,
    slots: BTreeMap<Vec<u8>, TargetSlot>,
    generation: u64,
    persisted_generation: u64,
    trusted_time_high_water: u64,
}

impl TargetCache {
    fn empty(network_magic: u32, allow_private: bool, trusted_now: u64) -> Self {
        Self {
            network_magic,
            allow_private,
            slots: BTreeMap::new(),
            generation: 1,
            persisted_generation: 0,
            trusted_time_high_water: trusted_now,
        }
    }

    fn install(
        &mut self,
        locator: DirectTargetLocator,
        signed_record: &[u8],
        configuration_index: usize,
        now: u64,
    ) -> Result<(bool, [u8; 32], u64, u64), OdohCacheError> {
        self.advance_time_and_prune(now)?;
        let verified = VerifiedTarget::decode(
            locator.clone(),
            signed_record,
            configuration_index,
            self.network_magic,
            now,
            self.allow_private,
        )?;
        let locator_key = locator.encode();
        if locator_key.is_empty() || locator_key.len() > ODOH_MAXIMUM_TARGET_LOCATOR_BYTES {
            return Err(OdohCacheError::InvalidLocator);
        }
        let record_id = verified.record_id;
        let sequence = verified.sequence;
        let expires_at = verified.expires_at;
        if let Some(slot) = self.slots.get(&locator_key) {
            if sequence < slot.highest_sequence {
                return Err(OdohCacheError::SequenceRollback);
            }
            if sequence == slot.highest_sequence {
                if slot.current.as_ref().is_some_and(|current| {
                    current.record_id == record_id
                        && current.configuration_index == verified.configuration_index
                }) {
                    return Ok((false, record_id, sequence, expires_at));
                } else {
                    return Err(OdohCacheError::SequenceConflict);
                }
            }
        } else if self.slots.len() == ODOH_MAXIMUM_CACHED_TARGETS {
            return Err(OdohCacheError::CacheFull);
        }
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(OdohCacheError::GenerationExhausted)?;
        if let Some(slot) = self.slots.get_mut(&locator_key) {
            slot.highest_sequence = sequence;
            slot.current = Some(verified);
        } else {
            self.slots.insert(
                locator_key,
                TargetSlot {
                    locator,
                    highest_sequence: sequence,
                    current: Some(verified),
                },
            );
        }
        self.generation = next_generation;
        Ok((true, record_id, sequence, expires_at))
    }

    fn advance_time_and_prune(&mut self, now: u64) -> Result<(), OdohCacheError> {
        if now < self.trusted_time_high_water {
            return Err(OdohCacheError::TrustedTimeRollback);
        }
        let changed = now > self.trusted_time_high_water
            || self.slots.values().any(|slot| {
                slot.current
                    .as_ref()
                    .is_some_and(|target| now >= target.expires_at)
            });
        let next_generation = if changed {
            Some(
                self.generation
                    .checked_add(1)
                    .ok_or(OdohCacheError::GenerationExhausted)?,
            )
        } else {
            None
        };
        self.trusted_time_high_water = now;
        for slot in self.slots.values_mut() {
            if slot
                .current
                .as_ref()
                .is_some_and(|target| now >= target.expires_at)
            {
                slot.current = None;
            }
        }
        if let Some(next_generation) = next_generation {
            self.generation = next_generation;
        }
        Ok(())
    }

    fn inspect_time_and_prune(&mut self, now: u64) -> Result<(), OdohCacheError> {
        if now < self.trusted_time_high_water {
            return Err(OdohCacheError::TrustedTimeRollback);
        }
        let changed = self.slots.values().any(|slot| {
            slot.current
                .as_ref()
                .is_some_and(|target| now >= target.expires_at)
        });
        let next_generation = if changed {
            Some(
                self.generation
                    .checked_add(1)
                    .ok_or(OdohCacheError::GenerationExhausted)?,
            )
        } else {
            None
        };
        for slot in self.slots.values_mut() {
            if slot
                .current
                .as_ref()
                .is_some_and(|target| now >= target.expires_at)
            {
                slot.current = None;
            }
        }
        if let Some(next_generation) = next_generation {
            self.generation = next_generation;
        }
        Ok(())
    }

    fn target(
        &mut self,
        record_id: [u8; 32],
        now: u64,
    ) -> Result<VerifiedTarget, OdohFailureReason> {
        self.advance_time_and_prune(now)
            .map_err(|_| OdohFailureReason::TrustedTimeRollback)?;
        let target = self
            .slots
            .values()
            .filter_map(|slot| slot.current.as_ref())
            .find(|target| target.record_id == record_id)
            .ok_or(OdohFailureReason::TargetUnavailable)?;
        if now >= target.expires_at {
            return Err(OdohFailureReason::TargetExpired);
        }
        Ok(target.clone())
    }

    fn current_count(&self) -> usize {
        self.slots
            .values()
            .filter(|slot| slot.current.is_some())
            .count()
    }

    fn earliest_expiry(&self) -> u64 {
        self.slots
            .values()
            .filter_map(|slot| slot.current.as_ref())
            .map(|target| target.expires_at)
            .min()
            .unwrap_or(0)
    }

    fn snapshot(
        &self,
        policy_generation: u64,
        requester_enabled: bool,
        revoked: bool,
    ) -> Result<Vec<u8>, OdohCacheError> {
        let count = u16::try_from(self.slots.len()).map_err(|_| OdohCacheError::CacheFull)?;
        let mut output = Vec::new();
        output.extend_from_slice(ODOH_TARGET_CACHE_MAGIC);
        output.extend_from_slice(&ODOH_TARGET_CACHE_SCHEMA.to_le_bytes());
        output.extend_from_slice(&self.network_magic.to_le_bytes());
        output.push(u8::from(self.allow_private));
        output.extend_from_slice(&self.generation.to_le_bytes());
        output.extend_from_slice(&self.trusted_time_high_water.to_le_bytes());
        output.extend_from_slice(&policy_generation.to_le_bytes());
        output.push(u8::from(requester_enabled));
        output.push(u8::from(revoked));
        output.extend_from_slice(&count.to_le_bytes());
        for (locator_key, slot) in &self.slots {
            if slot.locator.encode() != *locator_key {
                return Err(OdohCacheError::InvalidLocator);
            }
            let locator_length =
                u16::try_from(locator_key.len()).map_err(|_| OdohCacheError::InvalidLocator)?;
            output.extend_from_slice(&locator_length.to_le_bytes());
            output.extend_from_slice(locator_key);
            output.extend_from_slice(&slot.highest_sequence.to_le_bytes());
            if let Some(target) = &slot.current {
                let record_length = u16::try_from(target.signed_record.len())
                    .map_err(|_| OdohCacheError::InvalidRecordLength)?;
                output.push(1);
                output.extend_from_slice(&target.configuration_index.to_le_bytes());
                output.extend_from_slice(&target.expires_at.to_le_bytes());
                output.extend_from_slice(&record_length.to_le_bytes());
                output.extend_from_slice(&target.signed_record);
            } else {
                output.push(0);
            }
        }
        if output
            .len()
            .saturating_add(ODOH_TARGET_CACHE_CHECKSUM_BYTES)
            > ODOH_MAXIMUM_TARGET_CACHE_BLOB_BYTES
        {
            return Err(OdohCacheError::InvalidSnapshot);
        }
        let checksum = blake2b_256_many([output.as_slice()]);
        output.extend_from_slice(&checksum);
        Ok(output)
    }

    fn restore(
        input: &[u8],
        network_magic: u32,
        allow_private: bool,
        now: u64,
        minimum: OdohDurableFloor,
    ) -> Result<(Self, u64, bool, bool), OdohCacheError> {
        if input.len() < 75 || input.len() > ODOH_MAXIMUM_TARGET_CACHE_BLOB_BYTES {
            return Err(OdohCacheError::InvalidSnapshot);
        }
        let payload_length = input
            .len()
            .checked_sub(ODOH_TARGET_CACHE_CHECKSUM_BYTES)
            .ok_or(OdohCacheError::InvalidSnapshot)?;
        let (payload, checksum) = input.split_at(payload_length);
        if blake2b_256_many([payload]).as_slice() != checksum {
            return Err(OdohCacheError::ChecksumMismatch);
        }
        let mut decoder = CacheDecoder::new(payload);
        if decoder.take(8)? != ODOH_TARGET_CACHE_MAGIC {
            return Err(OdohCacheError::InvalidSnapshot);
        }
        if decoder.u16()? != ODOH_TARGET_CACHE_SCHEMA {
            return Err(OdohCacheError::UnsupportedSnapshotSchema);
        }
        if decoder.u32()? != network_magic {
            return Err(OdohCacheError::NetworkMismatch);
        }
        if decoder.u8()? != u8::from(allow_private) {
            return Err(OdohCacheError::AddressPolicyMismatch);
        }
        let generation = decoder.u64()?;
        let trusted_time_high_water = decoder.u64()?;
        let policy_generation = decoder.u64()?;
        let requester_enabled = match decoder.u8()? {
            0 => false,
            1 => true,
            _ => return Err(OdohCacheError::InvalidSnapshot),
        };
        let revoked = match decoder.u8()? {
            0 => false,
            1 => true,
            _ => return Err(OdohCacheError::InvalidSnapshot),
        };
        if generation == 0
            || policy_generation == 0
            || generation < minimum.cache_generation
            || policy_generation < minimum.policy_generation
            || trusted_time_high_water < minimum.trusted_time_high_water
        {
            return Err(OdohCacheError::GenerationRollback);
        }
        if now < trusted_time_high_water {
            return Err(OdohCacheError::TrustedTimeRollback);
        }
        let count = usize::from(decoder.u16()?);
        if count > ODOH_MAXIMUM_CACHED_TARGETS {
            return Err(OdohCacheError::CacheFull);
        }
        let mut slots = BTreeMap::new();
        let mut previous_locator: Option<Vec<u8>> = None;
        for _ in 0..count {
            let locator_length = usize::from(decoder.u16()?);
            if locator_length == 0 || locator_length > ODOH_MAXIMUM_TARGET_LOCATOR_BYTES {
                return Err(OdohCacheError::InvalidLocator);
            }
            let locator_key = decoder.take(locator_length)?.to_vec();
            if previous_locator
                .as_ref()
                .is_some_and(|previous| previous >= &locator_key)
            {
                return Err(OdohCacheError::NonCanonicalSnapshot);
            }
            previous_locator = Some(locator_key.clone());
            let locator = DirectTargetLocator::decode(&locator_key, allow_private)
                .map_err(|_| OdohCacheError::InvalidLocator)?;
            if locator.encode() != locator_key {
                return Err(OdohCacheError::NonCanonicalSnapshot);
            }
            let highest_sequence = decoder.u64()?;
            if highest_sequence == 0 {
                return Err(OdohCacheError::SequenceConflict);
            }
            let current = match decoder.u8()? {
                0 => None,
                1 => {
                    let configuration_index = decoder.u16()?;
                    let persisted_expiry = decoder.u64()?;
                    let record_length = usize::from(decoder.u16()?);
                    if record_length == 0 || record_length > ODOH_MAXIMUM_TARGET_RECORD_BYTES {
                        return Err(OdohCacheError::InvalidRecordLength);
                    }
                    let signed_record = decoder.take(record_length)?.to_vec();
                    if persisted_expiry == 0 {
                        return Err(OdohCacheError::SequenceConflict);
                    }
                    if now >= persisted_expiry {
                        // Never move the verification clock backwards to
                        // revive an expired configuration. Its previously
                        // persisted sequence high-water remains authoritative.
                        None
                    } else {
                        let target = VerifiedTarget::decode(
                            locator.clone(),
                            &signed_record,
                            usize::from(configuration_index),
                            network_magic,
                            now,
                            allow_private,
                        )?;
                        if target.expires_at != persisted_expiry
                            || target.sequence != highest_sequence
                        {
                            return Err(OdohCacheError::SequenceConflict);
                        }
                        Some(target)
                    }
                }
                _ => return Err(OdohCacheError::InvalidSnapshot),
            };
            slots.insert(
                locator_key,
                TargetSlot {
                    locator,
                    highest_sequence,
                    current,
                },
            );
        }
        decoder.finish()?;
        let changed_since_snapshot = now > trusted_time_high_water;
        let current_generation = if changed_since_snapshot {
            generation
                .checked_add(1)
                .ok_or(OdohCacheError::GenerationExhausted)?
        } else {
            generation
        };
        Ok((
            Self {
                network_magic,
                allow_private,
                slots,
                generation: current_generation,
                persisted_generation: generation,
                trusted_time_high_water: now,
            },
            policy_generation,
            requester_enabled,
            revoked,
        ))
    }
}

enum PendingKind {
    Query {
        context: Box<QueryContext>,
        target: AuthenticatedPeerKey,
        target_expiry: u64,
    },
    Configuration {
        locator: DirectTargetLocator,
        configuration_index: usize,
    },
}

struct PendingRequest {
    proxy: OdohPeerProvenance,
    generation: u64,
    deadline: Instant,
    kind: PendingKind,
    completion: oneshot::Sender<OdohRequestOutcome>,
}

pub(crate) struct PreparedOdohRequest {
    pub packet: Packet,
    pub request_id: u64,
    pub generation: u64,
    pub deadline: Instant,
    pub pending: OdohPendingRequest,
}

pub struct OdohRequesterRuntime {
    binding: OdohNetworkBinding,
    config: OdohRequesterConfig,
    generation: u64,
    persisted_policy_generation: u64,
    next_request_id: Option<u64>,
    revoked: bool,
    pending: BTreeMap<u64, PendingRequest>,
    faulted_proxies: BTreeSet<PeerId>,
    cache: TargetCache,
    process: OdohProcessTotals,
}

impl fmt::Debug for OdohRequesterRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OdohRequesterRuntime")
            .field("config", &self.config)
            .field("generation", &self.generation)
            .field("revoked", &self.revoked)
            .field("pending", &self.pending.len())
            .field("faulted_proxies", &self.faulted_proxies)
            .field("target_slots", &self.cache.slots.len())
            .field("process", &self.process)
            .finish()
    }
}

impl OdohRequesterRuntime {
    pub fn new(
        binding: OdohNetworkBinding,
        config: OdohRequesterConfig,
        first_request_id: u64,
        trusted_now: u64,
    ) -> Result<Self, OdohCacheError> {
        let config = config.validate()?;
        Ok(Self {
            binding,
            config,
            generation: 1,
            persisted_policy_generation: 0,
            next_request_id: Some(first_request_id.max(1)),
            revoked: false,
            pending: BTreeMap::new(),
            faulted_proxies: BTreeSet::new(),
            cache: TargetCache::empty(binding.magic, config.allow_private_targets, trusted_now),
            process: OdohProcessTotals::default(),
        })
    }

    pub fn restore(
        binding: OdohNetworkBinding,
        config: OdohRequesterConfig,
        first_request_id: u64,
        snapshot: &[u8],
        minimum: OdohDurableFloor,
        now: u64,
    ) -> Result<Self, OdohCacheError> {
        let mut config = config.validate()?;
        let (cache, persisted_policy_generation, persisted_enabled, revoked) =
            TargetCache::restore(
                snapshot,
                binding.magic,
                config.allow_private_targets,
                now,
                minimum,
            )?;
        let mut generation = persisted_policy_generation;
        let persisted_generation = persisted_policy_generation;
        config.enabled = config.enabled && persisted_enabled;
        if !config.enabled && persisted_enabled {
            generation = generation
                .checked_add(1)
                .ok_or(OdohCacheError::GenerationExhausted)?;
        }
        Ok(Self {
            binding,
            config,
            generation,
            persisted_policy_generation: persisted_generation,
            next_request_id: Some(first_request_id.max(1)),
            revoked,
            pending: BTreeMap::new(),
            faulted_proxies: BTreeSet::new(),
            cache,
            process: OdohProcessTotals::default(),
        })
    }

    pub fn install_target(
        &mut self,
        locator: DirectTargetLocator,
        signed_record: &[u8],
        configuration_index: usize,
        now: u64,
    ) -> Result<[u8; 32], OdohCacheError> {
        let (changed, record_id, _, _) =
            self.cache
                .install(locator, signed_record, configuration_index, now)?;
        if changed {
            self.process.configurations_installed =
                self.process.configurations_installed.saturating_add(1);
        }
        Ok(record_id)
    }

    pub fn target_cache_snapshot(
        &mut self,
        now: u64,
    ) -> Result<OdohTargetCacheSnapshot, OdohCacheError> {
        self.cache.advance_time_and_prune(now)?;
        Ok(OdohTargetCacheSnapshot {
            generation: self.cache.generation,
            policy_generation: self.generation,
            trusted_time_high_water: self.cache.trusted_time_high_water,
            bytes: self
                .cache
                .snapshot(self.generation, self.config.enabled, self.revoked)?,
        })
    }

    pub fn acknowledge_target_cache_persisted(&mut self, floor: OdohDurableFloor) {
        if floor.cache_generation <= self.cache.generation
            && floor.policy_generation <= self.generation
            && floor.trusted_time_high_water <= self.cache.trusted_time_high_water
        {
            self.cache.persisted_generation =
                self.cache.persisted_generation.max(floor.cache_generation);
            self.persisted_policy_generation = self
                .persisted_policy_generation
                .max(floor.policy_generation);
        }
    }

    pub fn status(
        &mut self,
        now: u64,
        eligible_authenticated_proxies: usize,
    ) -> OdohRequesterStatus {
        let clock_rollback = self.cache.inspect_time_and_prune(now).is_err();
        let current_targets = self.cache.current_count();
        let phase = if clock_rollback {
            OdohRuntimePhase::ClockRollback
        } else if self.revoked {
            OdohRuntimePhase::Revoked
        } else if !self.config.enabled {
            OdohRuntimePhase::Disabled
        } else if eligible_authenticated_proxies == 0 {
            OdohRuntimePhase::AwaitingProxy
        } else if current_targets == 0 {
            OdohRuntimePhase::AwaitingTarget
        } else {
            OdohRuntimePhase::Ready
        };
        OdohRequesterStatus {
            schema_version: 1,
            phase,
            policy_generation: self.generation,
            requester_enabled: self.config.enabled && !self.revoked && !clock_rollback,
            requester_default_enabled: true,
            service_bit: ODOH_SERVICE.value(),
            packet_type: ODOH_PACKET.value(),
            registry_fingerprint: DENUO_V1_REGISTRY_FINGERPRINT.to_string(),
            registry_wire_profile: DENUO_V1_WIRE_PROFILE.to_owned(),
            eligible_authenticated_proxies: eligible_authenticated_proxies as u64,
            faulted_proxies: self.faulted_proxies.len() as u64,
            target_slots: self.cache.slots.len() as u16,
            current_targets: current_targets as u16,
            earliest_target_expiry: self.cache.earliest_expiry(),
            live_requests: self.pending.len() as u16,
            maximum_live_requests: self.config.maximum_live_requests,
            cache_generation: self.cache.generation,
            cache_dirty: self.cache.persisted_generation < self.cache.generation,
            policy_dirty: self.persisted_policy_generation < self.generation,
            durable_state_dirty: self.cache.persisted_generation < self.cache.generation
                || self.persisted_policy_generation < self.generation,
            trusted_time_high_water: self.cache.trusted_time_high_water,
            proxy_provider_available: false,
            target_provider_available: false,
            output_provider_available: false,
            process: self.process,
        }
    }

    pub fn replace_enabled(
        &mut self,
        enabled: bool,
        next_generation: u64,
    ) -> Result<usize, OdohFailureReason> {
        if next_generation <= self.generation {
            return Err(OdohFailureReason::StaleGeneration);
        }
        self.generation = next_generation;
        self.config.enabled = enabled;
        self.revoked = false;
        self.faulted_proxies.clear();
        Ok(self.revoke_pending(OdohRequestOutcome::Revoked))
    }

    pub fn revoke(&mut self, next_generation: u64) -> Result<usize, OdohFailureReason> {
        if next_generation <= self.generation {
            return Err(OdohFailureReason::StaleGeneration);
        }
        self.generation = next_generation;
        self.revoked = true;
        self.faulted_proxies.clear();
        Ok(self.revoke_pending(OdohRequestOutcome::Revoked))
    }

    /// Validate reusable exact peer evidence before an adapter attempts ODoH
    /// work. The live manager applies this same gate again when it creates a
    /// request, so a stale preflight result never grants authority.
    pub fn validate_proxy_admission(
        &self,
        proxy: &OdohProxyAdmission,
    ) -> Result<(), OdohFailureReason> {
        self.ensure_proxy(proxy)
    }

    pub(crate) fn proxy_faulted(&self, peer: PeerId) -> bool {
        self.faulted_proxies.contains(&peer)
    }

    pub(crate) fn target_peer_key(
        &mut self,
        record_id: [u8; 32],
        now: u64,
    ) -> Result<AuthenticatedPeerKey, OdohFailureReason> {
        Ok(AuthenticatedPeerKey::new(
            self.cache.target(record_id, now)?.locator.target_peer_key,
        ))
    }

    pub(crate) fn begin_query(
        &mut self,
        proxy: OdohProxyAdmission,
        target_record_id: [u8; 32],
        query: Vec<u8>,
        now_unix: u64,
        now: Instant,
    ) -> Result<PreparedOdohRequest, OdohFailureReason> {
        self.ensure_proxy(&proxy)?;
        let target = self.cache.target(target_record_id, now_unix)?;
        let target_key = AuthenticatedPeerKey::new(target.locator.target_peer_key);
        ensure_distinct_proxy_target(proxy.provenance, target_key)?;
        if query.is_empty() || query.len() > MAX_ODOH_QUERY_SIZE {
            return Err(OdohFailureReason::RequestTooLarge);
        }
        let (message, context) = seal_query(&target.configuration, &query)
            .map_err(|_| OdohFailureReason::InvalidLocalRequest)?;
        let body = encode_padded_client_query(
            ClientQuery {
                locator: target.locator,
                config_id: target.record_id,
                message,
                padding: Vec::new(),
            },
            self.config.outer_padding_bucket,
        )?;
        self.begin(
            proxy,
            OdohOpcode::ClientQuery,
            body,
            PendingKind::Query {
                context: Box::new(context),
                target: target_key,
                target_expiry: target.expires_at,
            },
            now,
        )
    }

    pub(crate) fn begin_configuration(
        &mut self,
        proxy: OdohProxyAdmission,
        locator: DirectTargetLocator,
        configuration_index: usize,
        now_unix: u64,
        now: Instant,
    ) -> Result<PreparedOdohRequest, OdohFailureReason> {
        self.cache
            .advance_time_and_prune(now_unix)
            .map_err(|_| OdohFailureReason::TrustedTimeRollback)?;
        self.ensure_proxy(&proxy)?;
        let locator =
            DirectTargetLocator::decode(&locator.encode(), self.config.allow_private_targets)
                .map_err(|_| OdohFailureReason::InvalidLocalRequest)?;
        ensure_distinct_proxy_target(
            proxy.provenance,
            AuthenticatedPeerKey::new(locator.target_peer_key),
        )?;
        if configuration_index > u16::MAX as usize {
            return Err(OdohFailureReason::InvalidLocalRequest);
        }
        let body = GetConfigBody {
            locator: locator.clone(),
            allow_cached: true,
        }
        .encode();
        self.begin(
            proxy,
            OdohOpcode::GetConfig,
            body,
            PendingKind::Configuration {
                locator,
                configuration_index,
            },
            now,
        )
    }

    fn begin(
        &mut self,
        proxy: OdohProxyAdmission,
        opcode: OdohOpcode,
        body: Vec<u8>,
        kind: PendingKind,
        now: Instant,
    ) -> Result<PreparedOdohRequest, OdohFailureReason> {
        let negotiated_live = usize::from(proxy.negotiated.maximum_live_requests);
        if self.pending.len() >= usize::from(self.config.maximum_live_requests).min(negotiated_live)
        {
            return Err(OdohFailureReason::CapacityExceeded);
        }
        let request_id = self.allocate_request_id()?;
        let encoded = OdnsPacket::new(opcode, request_id, body)
            .and_then(|packet| packet.encode())
            .map_err(|_| OdohFailureReason::InvalidLocalRequest)?;
        if encoded.len() > MAX_ODOH_PACKET_SIZE
            || encoded.len()
                > usize::try_from(proxy.negotiated.maximum_send_size).unwrap_or(usize::MAX)
        {
            return Err(OdohFailureReason::PacketTooLarge);
        }
        let deadline = now + self.config.request_timeout;
        let generation = self.generation;
        let target = match &kind {
            PendingKind::Query { target, .. } => *target,
            PendingKind::Configuration { locator, .. } => {
                AuthenticatedPeerKey::new(locator.target_peer_key)
            }
        };
        let admission = OdohRequestAdmission {
            request_id,
            generation,
            deadline,
            proxy: proxy.provenance,
            target,
        };
        let (completion, outcome) = oneshot::channel();
        self.pending.insert(
            request_id,
            PendingRequest {
                proxy: proxy.provenance,
                generation,
                deadline,
                kind,
                completion,
            },
        );
        self.process.requests_created = self.process.requests_created.saturating_add(1);
        Ok(PreparedOdohRequest {
            packet: Packet::Unknown {
                packet_type: PacketType::Unknown(ODOH_PACKET.value()),
                payload: encoded,
            },
            request_id,
            generation,
            deadline,
            pending: OdohPendingRequest { admission, outcome },
        })
    }

    pub(crate) fn socket_written(&mut self, request_id: u64, generation: u64) {
        if self
            .pending
            .get(&request_id)
            .is_some_and(|pending| pending.generation == generation)
        {
            self.process.requests_socket_written =
                self.process.requests_socket_written.saturating_add(1);
        }
    }

    pub(crate) fn socket_failed(&mut self, request_id: u64, generation: u64) {
        if self
            .pending
            .get(&request_id)
            .is_some_and(|pending| pending.generation == generation)
        {
            if let Some(pending) = self.pending.remove(&request_id) {
                let _ = pending
                    .completion
                    .send(OdohRequestOutcome::LocalSendUnavailable);
            }
            self.process.socket_write_failures =
                self.process.socket_write_failures.saturating_add(1);
        }
    }

    pub(crate) fn receive(
        &mut self,
        admission: OdohProxyAdmission,
        payload: &[u8],
        now_unix: u64,
        now: Instant,
    ) {
        let provenance = admission.provenance;
        self.expire(now);
        if self.cache.advance_time_and_prune(now_unix).is_err() {
            self.fault_peer(provenance.peer, OdohFailureReason::TrustedTimeRollback);
            return;
        }
        if let Err(reason) = self.ensure_proxy(&admission) {
            self.fault_peer(provenance.peer, reason);
            return;
        }
        let packet = match OdnsPacket::decode(payload) {
            Ok(packet) => packet,
            Err(_) => {
                self.fault_peer(provenance.peer, OdohFailureReason::MalformedResponse);
                return;
            }
        };
        if !matches!(
            packet.opcode,
            OdohOpcode::Config | OdohOpcode::ClientResponse | OdohOpcode::Error
        ) {
            // This requester-only runtime does not implement proxy, target,
            // configuration-provider, or plaintext output roles.
            self.fault_peer(provenance.peer, OdohFailureReason::UnexpectedOpcode);
            return;
        }
        let Some(expected) = self.pending.get(&packet.request_id) else {
            self.fault_peer(provenance.peer, OdohFailureReason::UncorrelatedResponse);
            return;
        };
        if expected.proxy.peer != provenance.peer
            || expected.proxy.authenticated_remote_static != provenance.authenticated_remote_static
        {
            self.fault_peer(provenance.peer, OdohFailureReason::WrongProxy);
            return;
        }
        let pending = self
            .pending
            .remove(&packet.request_id)
            .expect("correlated ODoH request remains pending");
        if pending.generation != self.generation || now >= pending.deadline {
            let _ = pending.completion.send(OdohRequestOutcome::Expired);
            self.process.expired_requests = self.process.expired_requests.saturating_add(1);
            return;
        }
        let outcome = match (pending.kind, packet.opcode) {
            (
                PendingKind::Query {
                    context,
                    target,
                    target_expiry,
                },
                OdohOpcode::ClientResponse,
            ) if now_unix < target_expiry => OdohResponseBody::decode(&packet.body)
                .and_then(|response| context.open_response(&response.message))
                .map(|response| OdohRequestOutcome::Response {
                    proxy: provenance,
                    target,
                    response: OdohUntrustedDnsResponse(response),
                })
                .unwrap_or(OdohRequestOutcome::Rejected(
                    OdohFailureReason::MalformedResponse,
                )),
            (PendingKind::Query { .. }, OdohOpcode::ClientResponse) => {
                OdohRequestOutcome::Rejected(OdohFailureReason::TargetExpired)
            }
            (
                PendingKind::Configuration {
                    locator,
                    configuration_index,
                },
                OdohOpcode::Config,
            ) => match OdohConfigBody::decode(&packet.body).and_then(|body| {
                self.cache
                    .install(locator, &body.record, configuration_index, now_unix)
                    .map_err(|_| OdohProtocolError::Invalid("target cache rejected record"))
            }) {
                Ok((changed, record_id, sequence, expires_at)) => {
                    if changed {
                        self.process.configurations_installed =
                            self.process.configurations_installed.saturating_add(1);
                    }
                    OdohRequestOutcome::ConfigurationInstalled {
                        record_id,
                        sequence,
                        expires_at,
                    }
                }
                Err(_) => OdohRequestOutcome::Rejected(OdohFailureReason::MalformedResponse),
            },
            (_, OdohOpcode::Error) => match OdohErrorBody::decode(&packet.body) {
                Ok(error) => OdohRequestOutcome::RemoteError {
                    status: error.status,
                    retry_after: error.retry_after,
                    error_class: error.error_class,
                },
                Err(_) => OdohRequestOutcome::Rejected(OdohFailureReason::MalformedResponse),
            },
            _ => OdohRequestOutcome::Rejected(OdohFailureReason::UnexpectedOpcode),
        };
        if matches!(outcome, OdohRequestOutcome::Rejected(_)) {
            self.faulted_proxies.insert(provenance.peer);
            self.process.rejected_packets = self.process.rejected_packets.saturating_add(1);
        } else {
            self.process.responses_received = self.process.responses_received.saturating_add(1);
        }
        let _ = pending.completion.send(outcome);
    }

    pub(crate) fn expire(&mut self, now: Instant) {
        let expired = self
            .pending
            .iter()
            .filter_map(|(request_id, pending)| (now >= pending.deadline).then_some(*request_id))
            .collect::<Vec<_>>();
        for request_id in expired {
            if let Some(pending) = self.pending.remove(&request_id) {
                let _ = pending.completion.send(OdohRequestOutcome::Expired);
                self.process.expired_requests = self.process.expired_requests.saturating_add(1);
            }
        }
    }

    pub(crate) fn disconnect(&mut self, peer: PeerId) {
        self.faulted_proxies.remove(&peer);
        let requests = self
            .pending
            .iter()
            .filter_map(|(request_id, pending)| (pending.proxy.peer == peer).then_some(*request_id))
            .collect::<Vec<_>>();
        for request_id in requests {
            if let Some(pending) = self.pending.remove(&request_id) {
                let _ = pending.completion.send(OdohRequestOutcome::Disconnected);
            }
        }
    }

    pub(crate) fn fault_peer(&mut self, peer: PeerId, reason: OdohFailureReason) {
        self.faulted_proxies.insert(peer);
        self.process.rejected_packets = self.process.rejected_packets.saturating_add(1);
        let requests = self
            .pending
            .iter()
            .filter_map(|(request_id, pending)| (pending.proxy.peer == peer).then_some(*request_id))
            .collect::<Vec<_>>();
        for request_id in requests {
            if let Some(pending) = self.pending.remove(&request_id) {
                let _ = pending
                    .completion
                    .send(OdohRequestOutcome::Rejected(reason));
            }
        }
    }

    fn ensure_proxy(&self, proxy: &OdohProxyAdmission) -> Result<(), OdohFailureReason> {
        if self.revoked {
            return Err(OdohFailureReason::Revoked);
        }
        if !self.config.enabled {
            return Err(OdohFailureReason::RequesterDisabled);
        }
        if self.faulted_proxies.contains(&proxy.provenance.peer)
            || proxy.provenance.transport != PeerTransportKind::Brontide
            || proxy.provenance.authenticated_remote_static.is_none()
        {
            return Err(OdohFailureReason::UnauthenticatedProxy);
        }
        if proxy.remote_services & ODOH_SERVICE.value() == 0 {
            return Err(OdohFailureReason::RemoteServiceNotAdvertised);
        }
        if proxy.remote_services & DENUO_EXTENSION_SERVICE.value() == 0
            || proxy.wire_profile != ExperimentalWireProfile::DenuoV1
            || proxy.negotiated.fingerprint != DENUO_V1_REGISTRY_FINGERPRINT
            || proxy.negotiated.registry_version != DENUO_V1_REGISTRY_VERSION
            || !proxy.negotiated.protocols.contains(&(
                REGISTRY_NEGOTIATION_PROTOCOL_ID,
                DENUO_V1_REGISTRY_PROTOCOL_VERSION,
            ))
            || proxy.negotiated.network != self.binding.network
            || proxy.negotiated.genesis_hash != self.binding.genesis_hash
        {
            return Err(OdohFailureReason::RegistryNotNegotiated);
        }
        if proxy.negotiated.maximum_send_size == 0 || proxy.negotiated.maximum_live_requests == 0 {
            return Err(OdohFailureReason::RegistryNotNegotiated);
        }
        Ok(())
    }

    fn allocate_request_id(&mut self) -> Result<u64, OdohFailureReason> {
        let mut candidate = self
            .next_request_id
            .ok_or(OdohFailureReason::CapacityExceeded)?;
        for _ in 0..=self.pending.len() {
            if candidate != 0 && !self.pending.contains_key(&candidate) {
                self.next_request_id = candidate.checked_add(1).filter(|next| *next != 0);
                return Ok(candidate);
            }
            candidate = candidate
                .checked_add(1)
                .filter(|next| *next != 0)
                .ok_or(OdohFailureReason::CapacityExceeded)?;
        }
        Err(OdohFailureReason::CapacityExceeded)
    }

    fn revoke_pending(&mut self, outcome: OdohRequestOutcome) -> usize {
        let pending = std::mem::take(&mut self.pending);
        let count = pending.len();
        for (_, request) in pending {
            let delivered = match &outcome {
                OdohRequestOutcome::Revoked => OdohRequestOutcome::Revoked,
                _ => OdohRequestOutcome::Rejected(OdohFailureReason::Revoked),
            };
            let _ = request.completion.send(delivered);
        }
        self.process.revoked_requests = self.process.revoked_requests.saturating_add(count as u64);
        count
    }
}

fn encode_padded_client_query(
    mut query: ClientQuery,
    bucket: usize,
) -> Result<Vec<u8>, OdohFailureReason> {
    let unpadded = query
        .encode()
        .map_err(|_| OdohFailureReason::InvalidLocalRequest)?;
    if bucket == 0 {
        return Ok(unpadded);
    }
    let packet_length = 12usize
        .checked_add(unpadded.len())
        .ok_or(OdohFailureReason::PacketTooLarge)?;
    let padding = (bucket - packet_length % bucket) % bucket;
    if padding > MAX_OUTER_PADDING_SIZE {
        return Err(OdohFailureReason::PacketTooLarge);
    }
    query.padding = vec![0; padding];
    query
        .encode()
        .map_err(|_| OdohFailureReason::InvalidLocalRequest)
}

fn ensure_distinct_proxy_target(
    proxy: OdohPeerProvenance,
    target: AuthenticatedPeerKey,
) -> Result<(), OdohFailureReason> {
    if proxy.authenticated_remote_static == Some(target) {
        Err(OdohFailureReason::ProxyTargetCollision)
    } else {
        Ok(())
    }
}

struct CacheDecoder<'input> {
    input: &'input [u8],
    position: usize,
}

impl<'input> CacheDecoder<'input> {
    const fn new(input: &'input [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn take(&mut self, length: usize) -> Result<&'input [u8], OdohCacheError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(OdohCacheError::InvalidSnapshot)?;
        let bytes = self
            .input
            .get(self.position..end)
            .ok_or(OdohCacheError::InvalidSnapshot)?;
        self.position = end;
        Ok(bytes)
    }

    fn u8(&mut self) -> Result<u8, OdohCacheError> {
        self.take(1)?
            .first()
            .copied()
            .ok_or(OdohCacheError::InvalidSnapshot)
    }

    fn u16(&mut self) -> Result<u16, OdohCacheError> {
        Ok(u16::from_le_bytes(
            self.take(2)?
                .try_into()
                .map_err(|_| OdohCacheError::InvalidSnapshot)?,
        ))
    }

    fn u32(&mut self) -> Result<u32, OdohCacheError> {
        Ok(u32::from_le_bytes(
            self.take(4)?
                .try_into()
                .map_err(|_| OdohCacheError::InvalidSnapshot)?,
        ))
    }

    fn u64(&mut self) -> Result<u64, OdohCacheError> {
        Ok(u64::from_le_bytes(
            self.take(8)?
                .try_into()
                .map_err(|_| OdohCacheError::InvalidSnapshot)?,
        ))
    }

    fn finish(self) -> Result<(), OdohCacheError> {
        if self.position == self.input.len() {
            Ok(())
        } else {
            Err(OdohCacheError::InvalidSnapshot)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_p2p_experimental::DENUO_V2_REGISTRY_FINGERPRINT;

    const TEST_MAGIC: u32 = 0xae38_95cf;
    const TEST_GENESIS: [u8; 32] = [0x42; 32];

    const fn binding() -> OdohNetworkBinding {
        OdohNetworkBinding {
            magic: TEST_MAGIC,
            network: ExperimentalNetwork::Regtest,
            genesis_hash: TEST_GENESIS,
        }
    }

    fn negotiated() -> NegotiatedRegistry {
        NegotiatedRegistry {
            fingerprint: DENUO_V1_REGISTRY_FINGERPRINT,
            registry_version: DENUO_V1_REGISTRY_VERSION,
            protocols: vec![(
                REGISTRY_NEGOTIATION_PROTOCOL_ID,
                DENUO_V1_REGISTRY_PROTOCOL_VERSION,
            )],
            maximum_send_size: MAX_ODOH_PACKET_SIZE as u32,
            maximum_live_requests: 8,
            network: ExperimentalNetwork::Regtest,
            genesis_hash: TEST_GENESIS,
            feature_flags: 0,
        }
    }

    fn proxy(target_key: AuthenticatedPeerKey) -> OdohProxyAdmission {
        OdohProxyAdmission {
            provenance: OdohPeerProvenance {
                peer: PeerId(1),
                address: "127.0.0.1:14039".parse().expect("address"),
                direction: PeerDirection::Outbound,
                transport: PeerTransportKind::Brontide,
                authenticated_remote_static: Some(target_key),
            },
            remote_services: DENUO_EXTENSION_SERVICE.value() | ODOH_SERVICE.value(),
            wire_profile: ExperimentalWireProfile::DenuoV1,
            negotiated: negotiated(),
        }
    }

    fn locator() -> DirectTargetLocator {
        DirectTargetLocator::new(
            [
                0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
                0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
                0x5b, 0x16, 0xf8, 0x17, 0x98,
            ],
            "127.0.0.1:14039".parse().expect("address"),
            true,
        )
        .expect("locator")
    }

    #[test]
    fn production_followup_odoh_defaults_enable_only_requester() {
        let config = OdohRequesterConfig::default();
        assert!(config.enabled);
        let mut runtime =
            OdohRequesterRuntime::new(binding(), config, 7, 1_700_000_000).expect("runtime");
        let status = runtime.status(1_700_000_000, 0);
        assert_eq!(status.phase, OdohRuntimePhase::AwaitingProxy);
        assert!(status.requester_enabled);
        assert!(!status.proxy_provider_available);
        assert!(!status.target_provider_available);
        assert!(!status.output_provider_available);
    }

    #[test]
    fn production_followup_odoh_cache_rejects_corruption_and_wrong_network() {
        let mut runtime = OdohRequesterRuntime::new(
            binding(),
            OdohRequesterConfig {
                allow_private_targets: true,
                ..OdohRequesterConfig::default()
            },
            7,
            1_700_000_000,
        )
        .expect("runtime");
        let snapshot = runtime
            .target_cache_snapshot(1_700_000_000)
            .expect("snapshot");
        let floor = snapshot.durable_floor();
        let mut corrupt = snapshot.bytes.clone();
        corrupt[10] ^= 1;
        assert!(matches!(
            TargetCache::restore(&corrupt, TEST_MAGIC, true, 1_700_000_000, floor),
            Err(OdohCacheError::ChecksumMismatch)
        ));
        assert!(matches!(
            TargetCache::restore(&snapshot.bytes, 0x5b6e_f2d3, true, 1_700_000_000, floor,),
            Err(OdohCacheError::NetworkMismatch)
        ));
        assert!(matches!(
            TargetCache::restore(&snapshot.bytes, TEST_MAGIC, false, 1_700_000_000, floor,),
            Err(OdohCacheError::AddressPolicyMismatch)
        ));
        assert!(matches!(
            TargetCache::restore(&snapshot.bytes, TEST_MAGIC, true, 1_699_999_999, floor,),
            Err(OdohCacheError::TrustedTimeRollback)
        ));
        let newer_floor = OdohDurableFloor {
            cache_generation: floor.cache_generation + 1,
            ..floor
        };
        assert!(matches!(
            TargetCache::restore(
                &snapshot.bytes,
                TEST_MAGIC,
                true,
                1_700_000_000,
                newer_floor,
            ),
            Err(OdohCacheError::GenerationRollback)
        ));
    }

    #[test]
    fn production_followup_odoh_target_locator_never_selects_same_proxy() {
        let target = locator();
        let target_key = AuthenticatedPeerKey::new(target.target_peer_key);
        let proxy = proxy(target_key);
        assert_eq!(
            ensure_distinct_proxy_target(proxy.provenance, target_key),
            Err(OdohFailureReason::ProxyTargetCollision)
        );
    }

    #[test]
    fn production_followup_odoh_requires_exact_denuo_v1_admission_evidence() {
        let target_key = AuthenticatedPeerKey::new(locator().target_peer_key);
        let runtime = OdohRequesterRuntime::new(
            binding(),
            OdohRequesterConfig {
                allow_private_targets: true,
                ..OdohRequesterConfig::default()
            },
            7,
            1_700_000_000,
        )
        .expect("runtime");
        let canonical = proxy(target_key);
        assert_eq!(runtime.ensure_proxy(&canonical), Ok(()));

        for profile in [
            ExperimentalWireProfile::Official(1),
            ExperimentalWireProfile::LegacyDraftRegtest,
            ExperimentalWireProfile::Auto,
            ExperimentalWireProfile::DenuoV2,
        ] {
            let mut rejected = canonical.clone();
            rejected.wire_profile = profile;
            assert_eq!(
                runtime.ensure_proxy(&rejected),
                Err(OdohFailureReason::RegistryNotNegotiated)
            );
        }

        let mut missing_odoh = canonical.clone();
        missing_odoh.remote_services &= !ODOH_SERVICE.value();
        assert_eq!(
            runtime.ensure_proxy(&missing_odoh),
            Err(OdohFailureReason::RemoteServiceNotAdvertised)
        );
        let mut missing_denuo = canonical.clone();
        missing_denuo.remote_services &= !DENUO_EXTENSION_SERVICE.value();
        assert_eq!(
            runtime.ensure_proxy(&missing_denuo),
            Err(OdohFailureReason::RegistryNotNegotiated)
        );

        let mut wrong_registry = canonical.clone();
        wrong_registry.negotiated.fingerprint = DENUO_V2_REGISTRY_FINGERPRINT;
        assert_eq!(
            runtime.ensure_proxy(&wrong_registry),
            Err(OdohFailureReason::RegistryNotNegotiated)
        );
        let mut wrong_network = canonical.clone();
        wrong_network.negotiated.network = ExperimentalNetwork::Mainnet;
        assert_eq!(
            runtime.ensure_proxy(&wrong_network),
            Err(OdohFailureReason::RegistryNotNegotiated)
        );
        let mut wrong_genesis = canonical;
        wrong_genesis.negotiated.genesis_hash = [9; 32];
        assert_eq!(
            runtime.ensure_proxy(&wrong_genesis),
            Err(OdohFailureReason::RegistryNotNegotiated)
        );
    }

    #[test]
    fn production_followup_odoh_restore_preserves_policy_and_requires_matching_floor() {
        let mut runtime = OdohRequesterRuntime::new(
            binding(),
            OdohRequesterConfig {
                allow_private_targets: true,
                ..OdohRequesterConfig::default()
            },
            7,
            1_700_000_000,
        )
        .expect("runtime");
        runtime.replace_enabled(false, 2).expect("opt out");
        let snapshot = runtime
            .target_cache_snapshot(1_700_000_001)
            .expect("snapshot");
        let floor = snapshot.durable_floor();
        let encoded_floor = floor.encode(TEST_MAGIC);
        assert_eq!(
            OdohDurableFloor::decode(&encoded_floor, TEST_MAGIC).expect("floor"),
            floor
        );

        let mut restored = OdohRequesterRuntime::restore(
            binding(),
            OdohRequesterConfig {
                allow_private_targets: true,
                ..OdohRequesterConfig::default()
            },
            9,
            &snapshot.bytes,
            floor,
            1_700_000_001,
        )
        .expect("restore");
        let status = restored.status(1_700_000_001, 1);
        assert_eq!(status.phase, OdohRuntimePhase::Disabled);
        assert!(!status.requester_enabled);
        assert_eq!(status.policy_generation, 2);

        restored.revoke(3).expect("revoke");
        let revoked_snapshot = restored
            .target_cache_snapshot(1_700_000_002)
            .expect("revoked snapshot");
        let mut revoked = OdohRequesterRuntime::restore(
            binding(),
            OdohRequesterConfig {
                allow_private_targets: true,
                ..OdohRequesterConfig::default()
            },
            10,
            &revoked_snapshot.bytes,
            revoked_snapshot.durable_floor(),
            1_700_000_002,
        )
        .expect("revoked restore");
        let status = revoked.status(1_700_000_002, 1);
        assert_eq!(status.phase, OdohRuntimePhase::Revoked);
        assert!(!status.requester_enabled);
        assert_eq!(status.policy_generation, 3);
    }
}
