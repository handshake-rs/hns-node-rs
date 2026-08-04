//! Role-safe, bounded per-peer session state for draft HIP-76.
//!
//! This module deliberately stops at the transport/session boundary. It
//! validates the canonical wire messages, correlates bounded live work, and
//! produces typed requests for a separately configured resolver backend. It
//! does not perform DNS recursion and does not authenticate DNS answers.
//!
//! HIP-76's "relay" is an output/provider role: it observes a plaintext DNS
//! query and performs DNS egress. Provider advertisement and request handling
//! therefore require both explicit local opt-in and a ready backend. Requester
//! eligibility is independent and never grants or advertises that provider
//! role.

use std::{
    collections::{BTreeMap, VecDeque},
    fmt,
    time::Duration,
};

use hns_dns_relay_protocol::{
    DnsRelay, DnsRelayProtocolError, GetDnsRelay, MAX_DNS_RELAY_QUERY_BODY_SIZE,
    MAX_DNS_RELAY_RESPONSE_BODY_SIZE,
};
pub use hns_dns_relay_protocol::{
    DnsRelayStatus, MAX_DNS_RELAY_REQUEST_PAYLOAD_SIZE, MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE,
};
pub use hns_p2p_experimental::{DnsRelayOutputPolicy, DnsRelayRequesterPolicy};
use hns_p2p_experimental::{
    DENUO_EXTENSION_SERVICE, DENUO_V1_REGISTRY_FINGERPRINT, DENUO_V1_WIRE_PROFILE,
    DNS_RELAY_REQUEST_PACKET, DNS_RELAY_RESPONSE_PACKET, DNS_RELAY_SERVICE,
    EXPERIMENTAL_STATUS_LABEL, HIP_76_PROTOCOL_VERSION,
};
use hns_primitives::{blake2b_256, verify_name};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

use crate::{
    handshake::PeerDirection,
    wire::{Frame, Packet, PacketType},
};

pub const HIP76_DEFAULT_MAXIMUM_LIVE_REQUESTS: u16 = 64;
const HIP76_POLICY_STATE_MAGIC: &[u8; 8] = b"HNSH7P1\0";
const HIP76_POLICY_FLOOR_MAGIC: &[u8; 8] = b"HNSH7F1\0";
const HIP76_POLICY_STATE_SCHEMA: u16 = 1;
const HIP76_POLICY_FLOOR_SCHEMA: u16 = 1;
const HIP76_POLICY_CHECKSUM_BYTES: usize = 32;
const HIP76_POLICY_STATE_BYTES: usize = 55;
const HIP76_POLICY_FLOOR_BYTES: usize = 54;

/// Provider consent is explicit and backend readiness is a separate fact.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Hip76ProviderPolicy {
    output: DnsRelayOutputPolicy,
    backend_ready: bool,
}

impl Hip76ProviderPolicy {
    pub const fn disabled() -> Self {
        Self {
            output: DnsRelayOutputPolicy::disabled(),
            backend_ready: false,
        }
    }

    pub const fn opted_in(backend_ready: bool) -> Self {
        Self {
            output: DnsRelayOutputPolicy::opted_in(),
            backend_ready,
        }
    }

    pub const fn is_opted_in(self) -> bool {
        self.output.is_enabled()
    }

    pub const fn is_backend_ready(self) -> bool {
        self.backend_ready
    }

    pub const fn is_available(self) -> bool {
        self.output.is_enabled() && self.backend_ready
    }
}

/// Derive the service mask placed in VERSION from explicit provider policy.
///
/// The DNS relay bit is always stripped first. It is restored only when the
/// output role is opted in, its backend is ready, and Denuo negotiation support
/// is advertised. This makes an accidentally pre-populated base mask safe.
pub const fn hip76_advertised_services(base_services: u64, provider: Hip76ProviderPolicy) -> u64 {
    let without_provider = base_services & !DNS_RELAY_SERVICE.value();
    if provider.is_available() && without_provider & DENUO_EXTENSION_SERVICE.value() != 0 {
        without_provider | DNS_RELAY_SERVICE.value()
    } else {
        without_provider
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hip76SessionConfig {
    pub requester_policy: DnsRelayRequesterPolicy,
    pub provider_policy: Hip76ProviderPolicy,
    pub policy_generation: u64,
    /// Per-direction capacity, bounded by `u16` and expected to be no greater
    /// than the canonical Denuo agreement's `maximum_live_requests`.
    pub maximum_live_requests: u16,
    pub maximum_send_size: u32,
    pub request_timeout: Duration,
    pub first_request_id: u64,
}

impl Default for Hip76SessionConfig {
    fn default() -> Self {
        Self {
            requester_policy: DnsRelayRequesterPolicy::Auto,
            provider_policy: Hip76ProviderPolicy::disabled(),
            policy_generation: 1,
            maximum_live_requests: HIP76_DEFAULT_MAXIMUM_LIVE_REQUESTS,
            maximum_send_size: MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE as u32,
            request_timeout: Duration::from_secs(10),
            first_request_id: 1,
        }
    }
}

impl Hip76SessionConfig {
    pub fn validate(&self) -> Result<(), Hip76ConfigurationError> {
        if self.policy_generation == 0 {
            return Err(Hip76ConfigurationError::ZeroGeneration);
        }
        if self.maximum_live_requests == 0 {
            return Err(Hip76ConfigurationError::ZeroCapacity);
        }
        if self.maximum_send_size == 0 {
            return Err(Hip76ConfigurationError::ZeroSendSize);
        }
        if self.request_timeout.is_zero() {
            return Err(Hip76ConfigurationError::ZeroTimeout);
        }
        if self.first_request_id == 0 {
            return Err(Hip76ConfigurationError::ZeroFirstRequestId);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
pub enum Hip76ConfigurationError {
    #[error("HIP-76 policy generation must be nonzero")]
    ZeroGeneration,
    #[error("HIP-76 live request capacity must be nonzero")]
    ZeroCapacity,
    #[error("HIP-76 negotiated packet ceiling must be nonzero")]
    ZeroSendSize,
    #[error("HIP-76 request timeout must be nonzero")]
    ZeroTimeout,
    #[error("HIP-76 first request ID must be nonzero")]
    ZeroFirstRequestId,
}

/// Process-wide HIP-76 requester policy restored before any peer is admitted.
///
/// Provider/output consent deliberately remains in [`Hip76ProviderPolicy`] and
/// is never encoded in this requester-only record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hip76RequesterPolicyStatus {
    pub schema_version: u16,
    pub requester_policy: DnsRelayRequesterPolicy,
    pub generation: u64,
    pub durable_state_dirty: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hip76RequesterPolicySnapshot {
    pub bytes: Vec<u8>,
    pub floor: Hip76RequesterPolicyFloor,
}

/// Independently checksummed generation floor committed atomically with the
/// requester policy record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Hip76RequesterPolicyFloor {
    pub generation: u64,
    pub network_magic: u32,
}

impl Hip76RequesterPolicyFloor {
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(HIP76_POLICY_FLOOR_BYTES);
        bytes.extend_from_slice(HIP76_POLICY_FLOOR_MAGIC);
        bytes.extend_from_slice(&HIP76_POLICY_FLOOR_SCHEMA.to_le_bytes());
        bytes.extend_from_slice(&self.network_magic.to_le_bytes());
        bytes.extend_from_slice(&self.generation.to_le_bytes());
        append_policy_checksum(&mut bytes);
        debug_assert_eq!(bytes.len(), HIP76_POLICY_FLOOR_BYTES);
        bytes
    }

    pub fn decode(input: &[u8]) -> Result<Self, Hip76RequesterPolicyError> {
        let payload =
            verified_policy_payload(input, HIP76_POLICY_FLOOR_MAGIC, HIP76_POLICY_FLOOR_BYTES)?;
        if u16::from_le_bytes(payload[8..10].try_into().expect("fixed schema field"))
            != HIP76_POLICY_FLOOR_SCHEMA
        {
            return Err(Hip76RequesterPolicyError::UnsupportedSchema);
        }
        let floor = Self {
            network_magic: u32::from_le_bytes(
                payload[10..14].try_into().expect("fixed network field"),
            ),
            generation: u64::from_le_bytes(
                payload[14..22].try_into().expect("fixed generation field"),
            ),
        };
        if floor.generation == 0 {
            return Err(Hip76RequesterPolicyError::GenerationRollback);
        }
        Ok(floor)
    }
}

/// Storage-independent authority for one process-wide requester policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Hip76RequesterPolicyRuntime {
    network_magic: u32,
    requester_policy: DnsRelayRequesterPolicy,
    generation: u64,
    persisted_generation: u64,
}

impl Hip76RequesterPolicyRuntime {
    pub fn fresh(
        network_magic: u32,
        requester_policy: DnsRelayRequesterPolicy,
        generation: u64,
    ) -> Result<Self, Hip76RequesterPolicyError> {
        if generation == 0 {
            return Err(Hip76RequesterPolicyError::GenerationRollback);
        }
        Ok(Self {
            network_magic,
            requester_policy,
            generation,
            persisted_generation: 0,
        })
    }

    pub fn restore(
        network_magic: u32,
        requester_override: Option<DnsRelayRequesterPolicy>,
        snapshot: &[u8],
        floor: Hip76RequesterPolicyFloor,
    ) -> Result<Self, Hip76RequesterPolicyError> {
        if floor.network_magic != network_magic {
            return Err(Hip76RequesterPolicyError::NetworkMismatch);
        }
        let payload =
            verified_policy_payload(snapshot, HIP76_POLICY_STATE_MAGIC, HIP76_POLICY_STATE_BYTES)?;
        if u16::from_le_bytes(payload[8..10].try_into().expect("fixed schema field"))
            != HIP76_POLICY_STATE_SCHEMA
        {
            return Err(Hip76RequesterPolicyError::UnsupportedSchema);
        }
        if u32::from_le_bytes(payload[10..14].try_into().expect("fixed network field"))
            != network_magic
        {
            return Err(Hip76RequesterPolicyError::NetworkMismatch);
        }
        let persisted_generation =
            u64::from_le_bytes(payload[14..22].try_into().expect("fixed generation field"));
        if persisted_generation == 0 || persisted_generation < floor.generation {
            return Err(Hip76RequesterPolicyError::GenerationRollback);
        }
        let persisted_policy = decode_requester_policy(payload[22])?;
        let mut runtime = Self {
            network_magic,
            requester_policy: persisted_policy,
            generation: persisted_generation,
            persisted_generation,
        };
        if let Some(requester_override) = requester_override {
            if requester_override != runtime.requester_policy {
                runtime.generation = runtime
                    .generation
                    .checked_add(1)
                    .ok_or(Hip76RequesterPolicyError::GenerationExhausted)?;
                runtime.requester_policy = requester_override;
            }
        }
        Ok(runtime)
    }

    pub const fn status(&self) -> Hip76RequesterPolicyStatus {
        Hip76RequesterPolicyStatus {
            schema_version: HIP76_POLICY_STATE_SCHEMA,
            requester_policy: self.requester_policy,
            generation: self.generation,
            durable_state_dirty: self.persisted_generation < self.generation,
        }
    }

    pub fn replace(
        &mut self,
        expected_generation: u64,
        requester_policy: DnsRelayRequesterPolicy,
        next_generation: u64,
    ) -> Result<Hip76RequesterPolicyStatus, Hip76RequesterPolicyError> {
        if expected_generation != self.generation {
            return Err(Hip76RequesterPolicyError::StaleGeneration);
        }
        if next_generation <= self.generation {
            return Err(Hip76RequesterPolicyError::StaleGeneration);
        }
        self.requester_policy = requester_policy;
        self.generation = next_generation;
        Ok(self.status())
    }

    pub fn snapshot(&self) -> Hip76RequesterPolicySnapshot {
        let mut bytes = Vec::with_capacity(HIP76_POLICY_STATE_BYTES);
        bytes.extend_from_slice(HIP76_POLICY_STATE_MAGIC);
        bytes.extend_from_slice(&HIP76_POLICY_STATE_SCHEMA.to_le_bytes());
        bytes.extend_from_slice(&self.network_magic.to_le_bytes());
        bytes.extend_from_slice(&self.generation.to_le_bytes());
        bytes.push(encode_requester_policy(self.requester_policy));
        append_policy_checksum(&mut bytes);
        debug_assert_eq!(bytes.len(), HIP76_POLICY_STATE_BYTES);
        Hip76RequesterPolicySnapshot {
            bytes,
            floor: Hip76RequesterPolicyFloor {
                generation: self.generation,
                network_magic: self.network_magic,
            },
        }
    }

    pub fn acknowledge_persisted(&mut self, floor: Hip76RequesterPolicyFloor) {
        if floor.network_magic == self.network_magic && floor.generation == self.generation {
            self.persisted_generation = self.persisted_generation.max(floor.generation);
        }
    }
}

const fn encode_requester_policy(policy: DnsRelayRequesterPolicy) -> u8 {
    match policy {
        DnsRelayRequesterPolicy::Auto => 0,
        DnsRelayRequesterPolicy::Disabled => 1,
        DnsRelayRequesterPolicy::Required => 2,
    }
}

fn decode_requester_policy(
    value: u8,
) -> Result<DnsRelayRequesterPolicy, Hip76RequesterPolicyError> {
    match value {
        0 => Ok(DnsRelayRequesterPolicy::Auto),
        1 => Ok(DnsRelayRequesterPolicy::Disabled),
        2 => Ok(DnsRelayRequesterPolicy::Required),
        _ => Err(Hip76RequesterPolicyError::CorruptSnapshot),
    }
}

fn append_policy_checksum(bytes: &mut Vec<u8>) {
    let checksum = blake2b_256(bytes);
    bytes.extend_from_slice(&checksum);
}

fn verified_policy_payload<'a>(
    input: &'a [u8],
    magic: &[u8; 8],
    exact_bytes: usize,
) -> Result<&'a [u8], Hip76RequesterPolicyError> {
    if input.len() != exact_bytes {
        return Err(Hip76RequesterPolicyError::CorruptSnapshot);
    }
    let payload_length = exact_bytes - HIP76_POLICY_CHECKSUM_BYTES;
    let (payload, checksum) = input.split_at(payload_length);
    if !payload.starts_with(magic) || blake2b_256(payload).as_slice() != checksum {
        return Err(Hip76RequesterPolicyError::CorruptSnapshot);
    }
    Ok(payload)
}

#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
pub enum Hip76RequesterPolicyError {
    #[error("corrupt HIP-76 requester policy snapshot")]
    CorruptSnapshot,
    #[error("unsupported HIP-76 requester policy snapshot schema")]
    UnsupportedSchema,
    #[error("HIP-76 requester policy network mismatch")]
    NetworkMismatch,
    #[error("HIP-76 requester policy generation rollback")]
    GenerationRollback,
    #[error("stale HIP-76 requester policy generation")]
    StaleGeneration,
    #[error("HIP-76 requester policy generation exhausted")]
    GenerationExhausted,
}

#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum Hip76ConnectionPhase {
    #[default]
    AwaitingRegistry,
    Active,
    Revoked,
    Faulted,
    Disconnected,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Hip76FailureReason {
    RequesterDisabled,
    ProviderNotOptedIn,
    BackendNotReady,
    LocalProviderNotAdvertised,
    RemoteProviderNotAdvertised,
    RegistryNotNegotiated,
    Revoked,
    PeerFaulted,
    Disconnected,
    RequestTooLarge,
    ResponseTooLarge,
    MalformedRequest,
    MalformedResponse,
    InvalidLocalRequest,
    InvalidLocalResponse,
    InvalidDnsQuery,
    InvalidDnsResponse,
    DnsCorrelationMismatch,
    DuplicateOrReplay,
    CapacityExceeded,
    LocalSendUnavailable,
    UncorrelatedResponse,
    DuplicateOrLateResponse,
    StaleGeneration,
    DeadlineExpired,
    UnexpectedPacket,
}

impl Hip76FailureReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RequesterDisabled => "requester-disabled",
            Self::ProviderNotOptedIn => "provider-not-opted-in",
            Self::BackendNotReady => "backend-not-ready",
            Self::LocalProviderNotAdvertised => "local-provider-not-advertised",
            Self::RemoteProviderNotAdvertised => "remote-provider-not-advertised",
            Self::RegistryNotNegotiated => "registry-not-negotiated",
            Self::Revoked => "revoked",
            Self::PeerFaulted => "peer-faulted",
            Self::Disconnected => "disconnected",
            Self::RequestTooLarge => "request-too-large",
            Self::ResponseTooLarge => "response-too-large",
            Self::MalformedRequest => "malformed-request",
            Self::MalformedResponse => "malformed-response",
            Self::InvalidLocalRequest => "invalid-local-request",
            Self::InvalidLocalResponse => "invalid-local-response",
            Self::InvalidDnsQuery => "invalid-dns-query",
            Self::InvalidDnsResponse => "invalid-dns-response",
            Self::DnsCorrelationMismatch => "dns-correlation-mismatch",
            Self::DuplicateOrReplay => "duplicate-or-replay",
            Self::CapacityExceeded => "capacity-exceeded",
            Self::LocalSendUnavailable => "local-send-unavailable",
            Self::UncorrelatedResponse => "uncorrelated-response",
            Self::DuplicateOrLateResponse => "duplicate-or-late-response",
            Self::StaleGeneration => "stale-generation",
            Self::DeadlineExpired => "deadline-expired",
            Self::UnexpectedPacket => "unexpected-packet",
        }
    }
}

impl fmt::Display for Hip76FailureReason {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
#[error("HIP-76 operation rejected: {reason}")]
pub struct Hip76Error {
    pub reason: Hip76FailureReason,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Hip76ProcessTotals {
    /// Request packets created by the local requester. Creation is not a claim
    /// that a later queue or socket write succeeded.
    pub outbound_requests_created: u64,
    /// Locally created request packets admitted to the bounded peer writer.
    pub outbound_requests_queue_admitted: u64,
    /// Locally created request packets whose socket write completed.
    pub outbound_requests_socket_written: u64,
    /// Canonical remote request envelopes received from the peer. This includes
    /// requests answered locally with a protocol status before backend work.
    pub inbound_requests_received: u64,
    /// Valid remote requests admitted to the local provider backend boundary.
    pub inbound_requests_accepted: u64,
    /// Response packets created from a backend result. The result is only
    /// codec-valid; this counter makes no DNS authentication claim.
    pub provider_responses_created: u64,
    /// Provider response packets admitted to the bounded peer writer.
    pub provider_responses_queue_admitted: u64,
    /// Provider response packets whose socket write completed.
    pub provider_responses_socket_written: u64,
    /// Valid, correlated response packets received for local requests.
    pub requester_responses_received: u64,
    /// Queue admissions later reported as failed socket writes.
    pub outbound_socket_write_failures: u64,
    /// Queue admissions discarded by the writer because their generation,
    /// role, or deadline was stale before any socket write was attempted.
    pub outbound_queue_dropped_stale: u64,
    pub expired_requests: u64,
    pub revoked_requests: u64,
    pub rejected_operations: u64,
}

impl Hip76ProcessTotals {
    pub fn saturating_add_assign(&mut self, other: &Self) {
        self.outbound_requests_created = self
            .outbound_requests_created
            .saturating_add(other.outbound_requests_created);
        self.outbound_requests_queue_admitted = self
            .outbound_requests_queue_admitted
            .saturating_add(other.outbound_requests_queue_admitted);
        self.outbound_requests_socket_written = self
            .outbound_requests_socket_written
            .saturating_add(other.outbound_requests_socket_written);
        self.inbound_requests_received = self
            .inbound_requests_received
            .saturating_add(other.inbound_requests_received);
        self.inbound_requests_accepted = self
            .inbound_requests_accepted
            .saturating_add(other.inbound_requests_accepted);
        self.provider_responses_created = self
            .provider_responses_created
            .saturating_add(other.provider_responses_created);
        self.provider_responses_queue_admitted = self
            .provider_responses_queue_admitted
            .saturating_add(other.provider_responses_queue_admitted);
        self.provider_responses_socket_written = self
            .provider_responses_socket_written
            .saturating_add(other.provider_responses_socket_written);
        self.requester_responses_received = self
            .requester_responses_received
            .saturating_add(other.requester_responses_received);
        self.outbound_socket_write_failures = self
            .outbound_socket_write_failures
            .saturating_add(other.outbound_socket_write_failures);
        self.outbound_queue_dropped_stale = self
            .outbound_queue_dropped_stale
            .saturating_add(other.outbound_queue_dropped_stale);
        self.expired_requests = self.expired_requests.saturating_add(other.expired_requests);
        self.revoked_requests = self.revoked_requests.saturating_add(other.revoked_requests);
        self.rejected_operations = self
            .rejected_operations
            .saturating_add(other.rejected_operations);
    }
}

/// Immutable, qname-free identity of the implemented HIP-76 wire profile.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Hip76ProtocolIdentity {
    pub semantic_version: u16,
    pub service_bit: u64,
    pub request_packet_type: u8,
    pub response_packet_type: u8,
    pub maximum_query_body_size: u32,
    pub maximum_request_payload_size: u32,
    pub maximum_response_body_size: u32,
    pub maximum_response_payload_size: u32,
    pub registry_fingerprint: String,
    pub registry_wire_profile: String,
    pub experimental_status: String,
    pub requester_default: String,
    pub provider_default_opted_in: bool,
}

impl Default for Hip76ProtocolIdentity {
    fn default() -> Self {
        Self {
            semantic_version: HIP_76_PROTOCOL_VERSION,
            service_bit: DNS_RELAY_SERVICE.value(),
            request_packet_type: DNS_RELAY_REQUEST_PACKET.value(),
            response_packet_type: DNS_RELAY_RESPONSE_PACKET.value(),
            maximum_query_body_size: u32::try_from(MAX_DNS_RELAY_QUERY_BODY_SIZE)
                .unwrap_or(u32::MAX),
            maximum_request_payload_size: u32::try_from(MAX_DNS_RELAY_REQUEST_PAYLOAD_SIZE)
                .unwrap_or(u32::MAX),
            maximum_response_body_size: u32::try_from(MAX_DNS_RELAY_RESPONSE_BODY_SIZE)
                .unwrap_or(u32::MAX),
            maximum_response_payload_size: u32::try_from(MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE)
                .unwrap_or(u32::MAX),
            registry_fingerprint: DENUO_V1_REGISTRY_FINGERPRINT.to_string(),
            registry_wire_profile: DENUO_V1_WIRE_PROFILE.to_owned(),
            experimental_status: EXPERIMENTAL_STATUS_LABEL.to_owned(),
            requester_default: "auto".to_owned(),
            provider_default_opted_in: false,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Hip76PhaseCounts {
    pub awaiting_registry: u64,
    pub active: u64,
    pub revoked: u64,
    pub faulted: u64,
    pub disconnected: u64,
}

/// Manager-aggregatable, qname-free HIP-76 status.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Hip76Summary {
    pub identity: Hip76ProtocolIdentity,
    pub peers: u64,
    pub phases: Hip76PhaseCounts,
    pub requester_enabled_peers: u64,
    pub requester_eligible_peers: u64,
    pub provider_opted_in_peers: u64,
    pub provider_backend_ready_peers: u64,
    pub provider_available_peers: u64,
    pub provider_advertised_peers: u64,
    pub outbound_live_requests: u64,
    pub inbound_live_requests: u64,
    pub process: Hip76ProcessTotals,
}

impl Hip76Summary {
    pub fn observe(&mut self, diagnostics: &Hip76SessionDiagnostics) {
        self.peers = self.peers.saturating_add(1);
        match diagnostics.phase {
            Hip76ConnectionPhase::AwaitingRegistry => {
                self.phases.awaiting_registry = self.phases.awaiting_registry.saturating_add(1);
            }
            Hip76ConnectionPhase::Active => {
                self.phases.active = self.phases.active.saturating_add(1);
            }
            Hip76ConnectionPhase::Revoked => {
                self.phases.revoked = self.phases.revoked.saturating_add(1);
            }
            Hip76ConnectionPhase::Faulted => {
                self.phases.faulted = self.phases.faulted.saturating_add(1);
            }
            Hip76ConnectionPhase::Disconnected => {
                self.phases.disconnected = self.phases.disconnected.saturating_add(1);
            }
        }
        self.requester_enabled_peers = self
            .requester_enabled_peers
            .saturating_add(u64::from(diagnostics.requester_enabled));
        self.requester_eligible_peers = self
            .requester_eligible_peers
            .saturating_add(u64::from(diagnostics.requester_eligible));
        self.provider_opted_in_peers = self
            .provider_opted_in_peers
            .saturating_add(u64::from(diagnostics.provider_opted_in));
        self.provider_backend_ready_peers = self
            .provider_backend_ready_peers
            .saturating_add(u64::from(diagnostics.provider_backend_ready));
        self.provider_available_peers = self
            .provider_available_peers
            .saturating_add(u64::from(diagnostics.provider_available));
        self.provider_advertised_peers = self
            .provider_advertised_peers
            .saturating_add(u64::from(diagnostics.local_provider_advertised));
        self.outbound_live_requests = self
            .outbound_live_requests
            .saturating_add(diagnostics.outbound_live_requests);
        self.inbound_live_requests = self
            .inbound_live_requests
            .saturating_add(diagnostics.inbound_live_requests);
        self.process.saturating_add_assign(&diagnostics.process);
    }
}

/// Structured diagnostics intentionally omit request IDs, qnames, DNS message
/// bytes, response status, and deadlines.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Hip76SessionDiagnostics {
    pub phase: Hip76ConnectionPhase,
    pub connection_direction: PeerDirection,
    pub policy_generation: u64,
    pub requester_enabled: bool,
    pub requester_eligible: bool,
    pub provider_opted_in: bool,
    pub provider_backend_ready: bool,
    pub provider_available: bool,
    pub local_provider_advertised: bool,
    pub remote_provider_advertised: bool,
    pub registry_negotiated: bool,
    pub peer_faulted: bool,
    pub maximum_live_requests: u16,
    pub maximum_send_size: u32,
    pub outbound_live_requests: u64,
    pub inbound_live_requests: u64,
    pub process: Hip76ProcessTotals,
    pub last_failure: Option<Hip76FailureReason>,
}

impl Hip76SessionDiagnostics {
    pub fn awaiting_registry(connection_direction: PeerDirection) -> Self {
        Self {
            phase: Hip76ConnectionPhase::AwaitingRegistry,
            connection_direction,
            policy_generation: 1,
            requester_enabled: true,
            requester_eligible: false,
            provider_opted_in: false,
            provider_backend_ready: false,
            provider_available: false,
            local_provider_advertised: false,
            remote_provider_advertised: false,
            registry_negotiated: false,
            peer_faulted: false,
            maximum_live_requests: HIP76_DEFAULT_MAXIMUM_LIVE_REQUESTS,
            maximum_send_size: MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE as u32,
            outbound_live_requests: 0,
            inbound_live_requests: 0,
            process: Hip76ProcessTotals::default(),
            last_failure: None,
        }
    }
}

#[derive(Eq, PartialEq)]
pub struct Hip76OutboundRequest {
    pub request_id: u64,
    pub generation: u64,
    pub deadline: Instant,
    pub packet: Packet,
    work_token: Hip76WriteToken,
}

impl Hip76OutboundRequest {
    /// Opaque receipt used to report bounded-queue and socket-write outcomes.
    pub const fn work_token(&self) -> Hip76WriteToken {
        self.work_token
    }

    pub fn into_parts(self) -> (Packet, Hip76WriteToken) {
        (self.packet, self.work_token)
    }
}

impl fmt::Debug for Hip76OutboundRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Hip76OutboundRequest")
            .field("request_id", &self.request_id)
            .field("generation", &self.generation)
            .field("deadline", &self.deadline)
            .field("packet_type", &self.packet.packet_type())
            .field("payload", &"<redacted DNS query>")
            .finish()
    }
}

/// A decoded request handed to a separately configured provider backend.
///
/// The session never stores `query`; callers must also keep it out of logs and
/// structured status.
#[derive(Eq, PartialEq)]
pub struct Hip76ProviderRequest {
    pub request_id: u64,
    pub generation: u64,
    pub deadline: Instant,
    query: Vec<u8>,
    work_token: u64,
}

impl Hip76ProviderRequest {
    pub fn query(&self) -> &[u8] {
        &self.query
    }

    pub fn into_query(self) -> Vec<u8> {
        self.query
    }

    pub fn into_parts(self) -> (Hip76ProviderWork, Vec<u8>) {
        (
            Hip76ProviderWork {
                request_id: self.request_id,
                generation: self.generation,
                deadline: self.deadline,
                work_token: self.work_token,
            },
            self.query,
        )
    }
}

#[derive(Eq, PartialEq)]
pub struct Hip76ProviderWork {
    request_id: u64,
    generation: u64,
    deadline: Instant,
    work_token: u64,
}

impl Hip76ProviderWork {
    pub const fn request_id(&self) -> u64 {
        self.request_id
    }

    pub const fn generation(&self) -> u64 {
        self.generation
    }

    pub const fn deadline(&self) -> Instant {
        self.deadline
    }

    pub const fn work_token(&self) -> Hip76WriteToken {
        Hip76WriteToken {
            sequence: self.work_token,
            request_id: self.request_id,
            generation: self.generation,
            kind: Hip76WriteKind::ProviderResponse,
        }
    }
}

impl fmt::Debug for Hip76ProviderWork {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Hip76ProviderWork")
            .field("request_id", &self.request_id)
            .field("generation", &self.generation)
            .field("deadline", &self.deadline)
            .field("work_token", &"<redacted>")
            .finish()
    }
}

impl fmt::Debug for Hip76ProviderRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Hip76ProviderRequest")
            .field("request_id", &self.request_id)
            .field("generation", &self.generation)
            .field("deadline", &self.deadline)
            .field("query_length", &self.query.len())
            .finish()
    }
}

#[derive(Eq, PartialEq)]
pub struct Hip76OutboundResponse {
    pub request_id: u64,
    pub generation: u64,
    pub status: DnsRelayStatus,
    pub packet: Packet,
    pub deadline: Instant,
    work_token: Hip76WriteToken,
}

impl Hip76OutboundResponse {
    /// Opaque receipt used to report bounded-queue and socket-write outcomes.
    pub const fn work_token(&self) -> Hip76WriteToken {
        self.work_token
    }

    pub fn into_parts(self) -> (Packet, Hip76WriteToken) {
        (self.packet, self.work_token)
    }
}

impl fmt::Debug for Hip76OutboundResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Hip76OutboundResponse")
            .field("request_id", &self.request_id)
            .field("generation", &self.generation)
            .field("status", &self.status)
            .field("deadline", &self.deadline)
            .field("packet_type", &self.packet.packet_type())
            .field("payload", &"<redacted DNS relay response>")
            .finish()
    }
}

/// Opaque per-packet lifecycle receipt.
///
/// The token contains no DNS data and cannot be constructed outside this
/// module. It is copyable so a writer queue can retain it independently of the
/// packet while the provider work capability itself remains non-cloneable.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Hip76WriteToken {
    sequence: u64,
    request_id: u64,
    generation: u64,
    kind: Hip76WriteKind,
}

impl fmt::Debug for Hip76WriteToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Hip76WriteToken")
            .field("value", &"<redacted>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
enum Hip76WriteKind {
    Request,
    ProviderResponse,
    ProviderRejection,
}

/// A correlated status response created while classifying a remote request.
///
/// This is returned only for a canonical `getdnsrelay` envelope whose request
/// ID can safely be echoed. DNS bytes and the opaque write token are redacted
/// from `Debug`.
#[derive(Eq, PartialEq)]
pub struct Hip76ProviderRejection {
    pub request_id: u64,
    pub generation: u64,
    pub deadline: Instant,
    pub status: DnsRelayStatus,
    pub packet: Box<Packet>,
    work_token: Hip76WriteToken,
}

impl Hip76ProviderRejection {
    pub const fn work_token(&self) -> Hip76WriteToken {
        self.work_token
    }

    pub fn into_parts(self) -> (Packet, Hip76WriteToken) {
        (*self.packet, self.work_token)
    }
}

impl fmt::Debug for Hip76ProviderRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Hip76ProviderRejection")
            .field("request_id", &self.request_id)
            .field("generation", &self.generation)
            .field("deadline", &self.deadline)
            .field("status", &self.status)
            .field("packet_type", &self.packet.packet_type())
            .field("payload", &"<redacted DNS relay rejection>")
            .finish()
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Hip76ProviderDisposition {
    Request(Hip76ProviderRequest),
    Rejection(Hip76ProviderRejection),
}

/// Raw DNS bytes received from a remote HIP-76 provider.
///
/// The private representation and redacted `Debug` prevent accidental status
/// serialization or ordinary debug logging. Callers must explicitly cross the
/// requester boundary with [`Self::as_bytes`] or [`Self::into_bytes`].
#[derive(Eq, PartialEq)]
pub struct Hip76UntrustedDnsResponse(Vec<u8>);

impl Hip76UntrustedDnsResponse {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

impl fmt::Debug for Hip76UntrustedDnsResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Hip76UntrustedDnsResponse")
            .field("length", &self.0.len())
            .finish()
    }
}

/// A correlated wire response returned to the requester boundary.
///
/// `response` is a codec-valid DNS message only when `status` is `Ok`. This
/// type deliberately does not claim DNSSEC validation or answer authenticity.
/// Brontide or another authenticated peer transport supplies peer provenance;
/// it does not make these DNS bytes trustworthy.
#[derive(Debug, Eq, PartialEq)]
pub struct Hip76RequesterResponse {
    pub request_id: u64,
    pub generation: u64,
    pub status: DnsRelayStatus,
    pub response: Hip76UntrustedDnsResponse,
}

impl Hip76RequesterResponse {
    pub fn into_parts(self) -> (u64, u64, DnsRelayStatus, Hip76UntrustedDnsResponse) {
        (self.request_id, self.generation, self.status, self.response)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Hip76Inbound {
    ProviderRequest(Hip76ProviderRequest),
    ProviderRejection(Hip76ProviderRejection),
    RequesterResponse(Hip76RequesterResponse),
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Hip76RevokedWork {
    pub requester_request_ids: Vec<u64>,
    pub provider_request_ids: Vec<u64>,
}

impl Hip76RevokedWork {
    pub fn count(&self) -> usize {
        self.requester_request_ids
            .len()
            .saturating_add(self.provider_request_ids.len())
    }

    pub fn is_empty(&self) -> bool {
        self.requester_request_ids.is_empty() && self.provider_request_ids.is_empty()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Hip76Expiration {
    pub requester_request_ids: Vec<u64>,
    pub provider_request_ids: Vec<u64>,
}

impl Hip76Expiration {
    pub fn count(&self) -> usize {
        self.requester_request_ids
            .len()
            .saturating_add(self.provider_request_ids.len())
    }

    pub fn is_empty(&self) -> bool {
        self.requester_request_ids.is_empty() && self.provider_request_ids.is_empty()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LiveRequest {
    generation: u64,
    deadline: Instant,
    dns_correlation: Option<DnsCorrelation>,
    work_token: u64,
    response_prepared: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DnsCorrelation {
    transaction_id: u16,
    question_hash: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TombstoneKind {
    Completed,
    Expired,
    Revoked,
}

#[derive(Debug)]
struct RequestBook {
    maximum_live: usize,
    live: BTreeMap<u64, LiveRequest>,
    tombstone_order: VecDeque<u64>,
    tombstones: BTreeMap<u64, TombstoneKind>,
}

impl RequestBook {
    fn new(maximum_live: usize) -> Self {
        Self {
            maximum_live,
            live: BTreeMap::new(),
            tombstone_order: VecDeque::with_capacity(maximum_live),
            tombstones: BTreeMap::new(),
        }
    }

    fn admit(
        &mut self,
        request_id: u64,
        generation: u64,
        deadline: Instant,
        dns_correlation: Option<DnsCorrelation>,
        work_token: u64,
    ) -> Result<(), Hip76FailureReason> {
        if self.live.contains_key(&request_id) || self.tombstones.contains_key(&request_id) {
            return Err(Hip76FailureReason::DuplicateOrReplay);
        }
        if self.live.len() >= self.maximum_live {
            return Err(Hip76FailureReason::CapacityExceeded);
        }
        self.live.insert(
            request_id,
            LiveRequest {
                generation,
                deadline,
                dns_correlation,
                work_token,
                response_prepared: false,
            },
        );
        Ok(())
    }

    fn set_maximum_live(&mut self, maximum_live: usize) {
        self.maximum_live = maximum_live;
        while self.tombstone_order.len() > maximum_live {
            if let Some(expired) = self.tombstone_order.pop_front() {
                self.tombstones.remove(&expired);
            }
        }
    }

    fn pending_deadline(&self) -> Option<Instant> {
        self.live.values().map(|request| request.deadline).min()
    }

    fn live(&self, request_id: u64) -> Option<LiveRequest> {
        self.live.get(&request_id).copied()
    }

    fn live_mut(&mut self, request_id: u64) -> Option<&mut LiveRequest> {
        self.live.get_mut(&request_id)
    }

    fn tombstone(&self, request_id: u64) -> Option<TombstoneKind> {
        self.tombstones.get(&request_id).copied()
    }

    fn complete(&mut self, request_id: u64, kind: TombstoneKind) -> Option<LiveRequest> {
        let request = self.live.remove(&request_id)?;
        self.remember(request_id, kind);
        Some(request)
    }

    fn expire(&mut self, now: Instant) -> Vec<u64> {
        let expired = self
            .live
            .iter()
            .filter_map(|(request_id, request)| (now >= request.deadline).then_some(*request_id))
            .collect::<Vec<_>>();
        for request_id in &expired {
            let _ = self.complete(*request_id, TombstoneKind::Expired);
        }
        expired
    }

    fn revoke_all(&mut self) -> Vec<u64> {
        let revoked = self.live.keys().copied().collect::<Vec<_>>();
        for request_id in &revoked {
            let _ = self.complete(*request_id, TombstoneKind::Revoked);
        }
        revoked
    }

    fn remember(&mut self, request_id: u64, kind: TombstoneKind) {
        if self.tombstones.insert(request_id, kind).is_none() {
            self.tombstone_order.push_back(request_id);
        }
        while self.tombstone_order.len() > self.maximum_live {
            if let Some(expired) = self.tombstone_order.pop_front() {
                self.tombstones.remove(&expired);
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Hip76WriteStage {
    Created,
    QueueAdmitted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Hip76PendingWrite {
    token: Hip76WriteToken,
    stage: Hip76WriteStage,
}

#[derive(Debug, Default)]
struct Hip76WriteBook {
    pending: BTreeMap<u64, Hip76PendingWrite>,
}

impl Hip76WriteBook {
    fn create(&mut self, token: Hip76WriteToken) -> Result<(), Hip76FailureReason> {
        match self.pending.entry(token.sequence) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                entry.insert(Hip76PendingWrite {
                    token,
                    stage: Hip76WriteStage::Created,
                });
                Ok(())
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                Err(Hip76FailureReason::DuplicateOrReplay)
            }
        }
    }

    fn queue_admitted(
        &mut self,
        token: Hip76WriteToken,
    ) -> Result<Hip76WriteKind, Hip76FailureReason> {
        let Some(pending) = self.pending.get_mut(&token.sequence) else {
            return Err(Hip76FailureReason::StaleGeneration);
        };
        if pending.token != token || pending.stage != Hip76WriteStage::Created {
            return Err(Hip76FailureReason::DuplicateOrReplay);
        }
        pending.stage = Hip76WriteStage::QueueAdmitted;
        Ok(token.kind)
    }

    fn stage(&self, token: Hip76WriteToken) -> Result<Hip76WriteStage, Hip76FailureReason> {
        let Some(pending) = self.pending.get(&token.sequence) else {
            return Err(Hip76FailureReason::StaleGeneration);
        };
        if pending.token != token {
            return Err(Hip76FailureReason::StaleGeneration);
        }
        Ok(pending.stage)
    }

    fn queue_rejected(
        &mut self,
        token: Hip76WriteToken,
    ) -> Result<Hip76WriteKind, Hip76FailureReason> {
        let Some(pending) = self.pending.remove(&token.sequence) else {
            return Err(Hip76FailureReason::StaleGeneration);
        };
        if pending.token != token || pending.stage != Hip76WriteStage::Created {
            self.pending.insert(token.sequence, pending);
            return Err(Hip76FailureReason::DuplicateOrReplay);
        }
        Ok(token.kind)
    }

    fn socket_result(
        &mut self,
        token: Hip76WriteToken,
    ) -> Result<Hip76WriteKind, Hip76FailureReason> {
        let Some(pending) = self.pending.remove(&token.sequence) else {
            return Err(Hip76FailureReason::StaleGeneration);
        };
        if pending.token != token || pending.stage != Hip76WriteStage::QueueAdmitted {
            self.pending.insert(token.sequence, pending);
            return Err(Hip76FailureReason::DuplicateOrReplay);
        }
        Ok(token.kind)
    }
}

/// A single connected peer's HIP-76 state.
///
/// HIP-76 traffic direction is defined relative to the local process, not by
/// whether this TCP/Brontide connection was accepted or initiated. Either
/// connection direction can carry a local request or a remote provider request
/// when the corresponding independent role checks pass.
pub struct Hip76Session {
    connection_direction: PeerDirection,
    local_services: u64,
    remote_services: u64,
    requester_policy: DnsRelayRequesterPolicy,
    provider_policy: Hip76ProviderPolicy,
    policy_generation: u64,
    request_timeout: Duration,
    next_request_id: u64,
    next_work_token: u64,
    registry_negotiated: bool,
    connected: bool,
    revoked: bool,
    peer_faulted: bool,
    outbound: RequestBook,
    inbound: RequestBook,
    writes: Hip76WriteBook,
    process: Hip76ProcessTotals,
    last_failure: Option<Hip76FailureReason>,
    configured_maximum_live_requests: u16,
    configured_maximum_send_size: usize,
    negotiated_maximum_send_size: usize,
}

impl fmt::Debug for Hip76Session {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Hip76Session")
            .field("diagnostics", &self.diagnostics())
            .field("request_state", &"<redacted>")
            .finish()
    }
}

impl Hip76Session {
    pub fn new(
        connection_direction: PeerDirection,
        local_services: u64,
        remote_services: u64,
        registry_negotiated: bool,
        config: Hip76SessionConfig,
    ) -> Result<Self, Hip76ConfigurationError> {
        config.validate()?;
        Ok(Self {
            connection_direction,
            local_services,
            remote_services,
            requester_policy: config.requester_policy,
            provider_policy: config.provider_policy,
            policy_generation: config.policy_generation,
            request_timeout: config.request_timeout,
            next_request_id: config.first_request_id,
            next_work_token: (config.first_request_id.rotate_left(29) ^ 0xa076_1d64_78bd_642f)
                .max(1),
            registry_negotiated,
            connected: true,
            revoked: false,
            peer_faulted: false,
            outbound: RequestBook::new(usize::from(config.maximum_live_requests)),
            inbound: RequestBook::new(usize::from(config.maximum_live_requests)),
            writes: Hip76WriteBook::default(),
            process: Hip76ProcessTotals::default(),
            last_failure: None,
            configured_maximum_live_requests: config.maximum_live_requests,
            configured_maximum_send_size: usize::try_from(config.maximum_send_size)
                .unwrap_or(usize::MAX)
                .min(MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE),
            negotiated_maximum_send_size: usize::try_from(config.maximum_send_size)
                .unwrap_or(usize::MAX)
                .min(MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE),
        })
    }

    pub fn diagnostics(&self) -> Hip76SessionDiagnostics {
        Hip76SessionDiagnostics {
            phase: self.phase(),
            connection_direction: self.connection_direction,
            policy_generation: self.policy_generation,
            requester_enabled: self.requester_policy != DnsRelayRequesterPolicy::Disabled,
            requester_eligible: self.requester_failure().is_none(),
            provider_opted_in: self.provider_policy.is_opted_in(),
            provider_backend_ready: self.provider_policy.is_backend_ready(),
            provider_available: self.provider_failure().is_none(),
            local_provider_advertised: services_advertise_provider(self.local_services),
            remote_provider_advertised: services_advertise_provider(self.remote_services),
            registry_negotiated: self.registry_negotiated,
            peer_faulted: self.peer_faulted,
            maximum_live_requests: u16::try_from(self.outbound.maximum_live).unwrap_or(u16::MAX),
            maximum_send_size: u32::try_from(self.negotiated_maximum_send_size).unwrap_or(u32::MAX),
            outbound_live_requests: saturating_usize_to_u64(self.outbound.live.len()),
            inbound_live_requests: saturating_usize_to_u64(self.inbound.live.len()),
            process: self.process.clone(),
            last_failure: self.last_failure,
        }
    }

    pub const fn ordinary_peer_remains_available(&self) -> bool {
        true
    }

    pub fn begin_request(
        &mut self,
        query: Vec<u8>,
        now: Instant,
    ) -> Result<Hip76OutboundRequest, Hip76Error> {
        let _ = self.expire(now);
        if let Some(reason) = self.requester_failure() {
            return Err(self.reject(reason));
        }
        if self.outbound.live.len() >= self.outbound.maximum_live {
            return Err(self.reject(Hip76FailureReason::CapacityExceeded));
        }

        let request_id = self.allocate_request_id()?;
        let dns_correlation = validate_dns_query(&query)
            .map_err(|_| self.reject(Hip76FailureReason::InvalidDnsQuery))?;
        let message =
            GetDnsRelay::new(request_id, query).map_err(|error| self.local_request_error(error))?;
        let payload = message
            .encode()
            .map_err(|error| self.local_request_error(error))?;
        if payload.len() > self.negotiated_maximum_send_size {
            return Err(self.reject(Hip76FailureReason::RequestTooLarge));
        }
        debug_assert!(payload.len() <= MAX_DNS_RELAY_REQUEST_PAYLOAD_SIZE);
        let deadline = now + self.request_timeout;
        let work_token = self.allocate_write_token(request_id, Hip76WriteKind::Request)?;
        self.writes
            .create(work_token)
            .map_err(|reason| self.reject(reason))?;
        self.outbound
            .admit(
                request_id,
                self.policy_generation,
                deadline,
                Some(dns_correlation),
                work_token.sequence,
            )
            .map_err(|reason| {
                let _ = self.writes.queue_rejected(work_token);
                self.reject(reason)
            })?;
        self.process.outbound_requests_created =
            self.process.outbound_requests_created.saturating_add(1);

        Ok(Hip76OutboundRequest {
            request_id,
            generation: self.policy_generation,
            deadline,
            packet: hip76_packet(DNS_RELAY_REQUEST_PACKET.value(), payload),
            work_token,
        })
    }

    /// Record admission of a request packet to the bounded writer queue.
    pub fn outbound_request_queue_admitted(
        &mut self,
        work_token: Hip76WriteToken,
    ) -> Result<(), Hip76Error> {
        if work_token.kind != Hip76WriteKind::Request {
            return Err(self.reject(Hip76FailureReason::UnexpectedPacket));
        }
        let Some(live) = self.outbound.live(work_token.request_id) else {
            return Err(self.reject(self.outbound_absent_reason(work_token.request_id)));
        };
        if live.generation != work_token.generation || live.work_token != work_token.sequence {
            return Err(self.reject(Hip76FailureReason::StaleGeneration));
        }
        self.writes
            .queue_admitted(work_token)
            .map_err(|reason| self.reject(reason))?;
        self.process.outbound_requests_queue_admitted = self
            .process
            .outbound_requests_queue_admitted
            .saturating_add(1);
        Ok(())
    }

    /// Cancel a locally created request when an outer bounded queue rejects it.
    pub fn cancel_outbound_request(
        &mut self,
        work_token: Hip76WriteToken,
    ) -> Result<(), Hip76Error> {
        if work_token.kind != Hip76WriteKind::Request {
            return Err(self.reject(Hip76FailureReason::UnexpectedPacket));
        }
        if work_token.generation != self.policy_generation {
            return Err(self.reject(Hip76FailureReason::StaleGeneration));
        }
        let Some(live) = self.outbound.live(work_token.request_id) else {
            return Err(self.reject(self.outbound_absent_reason(work_token.request_id)));
        };
        if work_token.generation != live.generation || work_token.sequence != live.work_token {
            return Err(self.reject(Hip76FailureReason::StaleGeneration));
        }
        match self
            .writes
            .stage(work_token)
            .map_err(|reason| self.reject(reason))?
        {
            Hip76WriteStage::Created => {
                self.writes
                    .queue_rejected(work_token)
                    .map_err(|reason| self.reject(reason))?;
            }
            Hip76WriteStage::QueueAdmitted => {
                // Keep the receipt until the writer reports whether the
                // already-admitted packet was dropped or reached the socket.
            }
        }
        let _ = self
            .outbound
            .complete(work_token.request_id, TombstoneKind::Revoked);
        self.process.revoked_requests = self.process.revoked_requests.saturating_add(1);
        Ok(())
    }

    /// Report that a created HIP-76 packet was not admitted to the writer.
    ///
    /// Provider response rejection leaves the inbound request live and clears
    /// only its prepared state, so queue pressure cannot manufacture a
    /// completion tombstone. Request packets are cancelled because their caller
    /// has already been told that admission failed.
    pub fn outbound_queue_rejected(
        &mut self,
        work_token: Hip76WriteToken,
    ) -> Result<(), Hip76Error> {
        match work_token.kind {
            Hip76WriteKind::Request => self.cancel_outbound_request(work_token),
            Hip76WriteKind::ProviderResponse => {
                let Some(live) = self.inbound.live(work_token.request_id) else {
                    return Err(self.reject(self.inbound_absent_reason(work_token.request_id)));
                };
                if live.generation != work_token.generation
                    || live.work_token != work_token.sequence
                    || !live.response_prepared
                {
                    return Err(self.reject(Hip76FailureReason::StaleGeneration));
                }
                self.writes
                    .queue_rejected(work_token)
                    .map_err(|reason| self.reject(reason))?;
                self.inbound
                    .live_mut(work_token.request_id)
                    .expect("provider response work was checked live")
                    .response_prepared = false;
                Ok(())
            }
            Hip76WriteKind::ProviderRejection => {
                self.writes
                    .queue_rejected(work_token)
                    .map_err(|reason| self.reject(reason))?;
                Ok(())
            }
        }
    }

    /// Report a completed socket write for an admitted HIP-76 packet.
    pub fn outbound_socket_written(
        &mut self,
        work_token: Hip76WriteToken,
    ) -> Result<(), Hip76Error> {
        let kind = self
            .writes
            .socket_result(work_token)
            .map_err(|reason| self.reject(reason))?;
        match kind {
            Hip76WriteKind::Request => {
                self.process.outbound_requests_socket_written = self
                    .process
                    .outbound_requests_socket_written
                    .saturating_add(1);
            }
            Hip76WriteKind::ProviderResponse | Hip76WriteKind::ProviderRejection => {
                self.process.provider_responses_socket_written = self
                    .process
                    .provider_responses_socket_written
                    .saturating_add(1);
            }
        }
        Ok(())
    }

    /// Report a failed socket write after bounded-queue admission.
    pub fn outbound_socket_failed(
        &mut self,
        work_token: Hip76WriteToken,
    ) -> Result<(), Hip76Error> {
        self.writes
            .socket_result(work_token)
            .map_err(|reason| self.reject(reason))?;
        self.process.outbound_socket_write_failures = self
            .process
            .outbound_socket_write_failures
            .saturating_add(1);
        Ok(())
    }

    /// Report a stale bounded-queue entry discarded before a socket attempt.
    pub fn outbound_write_dropped(
        &mut self,
        work_token: Hip76WriteToken,
    ) -> Result<(), Hip76Error> {
        self.writes
            .socket_result(work_token)
            .map_err(|reason| self.reject(reason))?;
        self.process.outbound_queue_dropped_stale =
            self.process.outbound_queue_dropped_stale.saturating_add(1);
        Ok(())
    }

    pub fn receive_packet(
        &mut self,
        packet_type: PacketType,
        payload: &[u8],
        now: Instant,
    ) -> Result<Hip76Inbound, Hip76Error> {
        if packet_type == PacketType::Unknown(DNS_RELAY_REQUEST_PACKET.value()) {
            return self
                .receive_request(payload, now)
                .map(|disposition| match disposition {
                    Hip76ProviderDisposition::Request(request) => {
                        Hip76Inbound::ProviderRequest(request)
                    }
                    Hip76ProviderDisposition::Rejection(rejection) => {
                        Hip76Inbound::ProviderRejection(rejection)
                    }
                });
        }
        if packet_type == PacketType::Unknown(DNS_RELAY_RESPONSE_PACKET.value()) {
            return self
                .receive_response(payload, now)
                .map(Hip76Inbound::RequesterResponse);
        }
        Err(self.reject(Hip76FailureReason::UnexpectedPacket))
    }

    /// Borrow a HIP-76 frame directly, before [`Frame::decode_packet`] clones
    /// an unknown packet payload. The request/response methods enforce their
    /// exact 4,106/65,546-byte full-payload caps before codec allocation.
    pub fn receive_frame(
        &mut self,
        frame: &Frame,
        now: Instant,
    ) -> Result<Hip76Inbound, Hip76Error> {
        self.receive_packet(frame.packet_type, &frame.payload, now)
    }

    pub fn receive_request(
        &mut self,
        payload: &[u8],
        now: Instant,
    ) -> Result<Hip76ProviderDisposition, Hip76Error> {
        let _ = self.expire(now);
        if payload.len() > MAX_DNS_RELAY_REQUEST_PAYLOAD_SIZE.min(self.negotiated_maximum_send_size)
        {
            return Err(self.fault_peer(Hip76FailureReason::RequestTooLarge));
        }
        let request =
            GetDnsRelay::decode(payload).map_err(|error| self.fault_remote_request(error))?;
        self.process.inbound_requests_received =
            self.process.inbound_requests_received.saturating_add(1);

        if let Some(reason) = self.provider_connection_failure() {
            return Err(self.fault_peer(reason));
        }
        if self.inbound.live.contains_key(&request.request_id)
            || self.inbound.tombstones.contains_key(&request.request_id)
        {
            return Err(self.fault_peer(Hip76FailureReason::DuplicateOrReplay));
        }
        let dns_correlation = match validate_dns_query(&request.query) {
            Ok(correlation) => correlation,
            Err(_) => {
                return self
                    .provider_rejection(request.request_id, DnsRelayStatus::InvalidQuery, now)
                    .map(Hip76ProviderDisposition::Rejection);
            }
        };
        if !self.provider_policy.is_backend_ready() {
            return self
                .provider_rejection(request.request_id, DnsRelayStatus::ResolverUnavailable, now)
                .map(Hip76ProviderDisposition::Rejection);
        }
        if self.inbound.live.len() >= self.inbound.maximum_live {
            return self
                .provider_rejection(request.request_id, DnsRelayStatus::Busy, now)
                .map(Hip76ProviderDisposition::Rejection);
        }

        let deadline = now + self.request_timeout;
        let work_token =
            self.allocate_write_token(request.request_id, Hip76WriteKind::ProviderResponse)?;
        self.inbound
            .admit(
                request.request_id,
                self.policy_generation,
                deadline,
                Some(dns_correlation),
                work_token.sequence,
            )
            .map_err(|reason| self.fault_peer(reason))?;
        self.process.inbound_requests_accepted =
            self.process.inbound_requests_accepted.saturating_add(1);

        Ok(Hip76ProviderDisposition::Request(Hip76ProviderRequest {
            request_id: request.request_id,
            generation: self.policy_generation,
            deadline,
            query: request.query,
            work_token: work_token.sequence,
        }))
    }

    /// Prepare a separately supplied backend result for bounded queue admission.
    ///
    /// This only enforces HIP-76 encoding and correlation. It does not certify
    /// that the backend performed recursion, DNSSEC validation, or any other
    /// authentication. Preparation does not complete or tombstone the request.
    pub fn prepare_provider_response(
        &mut self,
        work: &Hip76ProviderWork,
        status: DnsRelayStatus,
        response: Vec<u8>,
        now: Instant,
    ) -> Result<Hip76OutboundResponse, Hip76Error> {
        let _ = self.expire(now);
        if work.generation != self.policy_generation {
            return Err(self.reject(Hip76FailureReason::StaleGeneration));
        }
        if let Some(reason) = self.provider_failure() {
            return Err(self.reject(reason));
        }
        let Some(live) = self.inbound.live(work.request_id) else {
            return Err(self.reject(self.inbound_absent_reason(work.request_id)));
        };
        if live.generation != work.generation || live.work_token != work.work_token {
            return Err(self.reject(Hip76FailureReason::StaleGeneration));
        }
        if live.response_prepared {
            return Err(self.reject(Hip76FailureReason::DuplicateOrReplay));
        }
        if status == DnsRelayStatus::Ok {
            let actual = validate_dns_response(&response)
                .map_err(|_| self.reject(Hip76FailureReason::InvalidDnsResponse))?;
            if live.dns_correlation != Some(actual) {
                return Err(self.reject(Hip76FailureReason::DnsCorrelationMismatch));
            }
        }
        let message = DnsRelay::new(work.request_id, status, response)
            .map_err(|error| self.local_response_error(error))?;
        let payload = message
            .encode()
            .map_err(|error| self.local_response_error(error))?;
        if payload.len() > self.negotiated_maximum_send_size {
            return Err(self.reject(Hip76FailureReason::ResponseTooLarge));
        }
        debug_assert!(payload.len() <= MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE);
        let work_token = Hip76WriteToken {
            sequence: work.work_token,
            request_id: work.request_id,
            generation: work.generation,
            kind: Hip76WriteKind::ProviderResponse,
        };
        self.writes
            .create(work_token)
            .map_err(|reason| self.reject(reason))?;
        self.inbound
            .live_mut(work.request_id)
            .expect("provider work was checked live")
            .response_prepared = true;
        self.process.provider_responses_created =
            self.process.provider_responses_created.saturating_add(1);

        Ok(Hip76OutboundResponse {
            request_id: work.request_id,
            generation: work.generation,
            status,
            packet: hip76_packet(DNS_RELAY_RESPONSE_PACKET.value(), payload),
            deadline: work.deadline,
            work_token,
        })
    }

    /// Commit provider work only after its prepared packet enters the writer.
    ///
    /// Consuming the non-cloneable work capability makes a backend completion
    /// single-use. A stale capability cannot complete a later request that
    /// reuses the same peer-supplied request ID.
    pub fn commit_provider_response(
        &mut self,
        work: Hip76ProviderWork,
        now: Instant,
    ) -> Result<(), Hip76Error> {
        let _ = self.expire(now);
        if work.generation != self.policy_generation {
            return Err(self.reject(Hip76FailureReason::StaleGeneration));
        }
        let Some(live) = self.inbound.live(work.request_id) else {
            return Err(self.reject(self.inbound_absent_reason(work.request_id)));
        };
        if live.generation != work.generation
            || live.work_token != work.work_token
            || !live.response_prepared
        {
            return Err(self.reject(Hip76FailureReason::StaleGeneration));
        }
        let work_token = Hip76WriteToken {
            sequence: work.work_token,
            request_id: work.request_id,
            generation: work.generation,
            kind: Hip76WriteKind::ProviderResponse,
        };
        self.writes
            .queue_admitted(work_token)
            .map_err(|reason| self.reject(reason))?;
        let _ = self
            .inbound
            .complete(work.request_id, TombstoneKind::Completed);
        self.process.provider_responses_queue_admitted = self
            .process
            .provider_responses_queue_admitted
            .saturating_add(1);
        Ok(())
    }

    /// Record queue admission for a correlated automatic provider status.
    pub fn provider_rejection_queue_admitted(
        &mut self,
        work_token: Hip76WriteToken,
    ) -> Result<(), Hip76Error> {
        if work_token.kind != Hip76WriteKind::ProviderRejection {
            return Err(self.reject(Hip76FailureReason::UnexpectedPacket));
        }
        self.writes
            .queue_admitted(work_token)
            .map_err(|reason| self.reject(reason))?;
        self.process.provider_responses_queue_admitted = self
            .process
            .provider_responses_queue_admitted
            .saturating_add(1);
        Ok(())
    }

    pub fn receive_response(
        &mut self,
        payload: &[u8],
        now: Instant,
    ) -> Result<Hip76RequesterResponse, Hip76Error> {
        let _ = self.expire(now);
        if payload.len()
            > MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE.min(self.negotiated_maximum_send_size)
        {
            return Err(self.fault_peer(Hip76FailureReason::ResponseTooLarge));
        }
        if let Some(reason) = self.connection_failure() {
            return Err(self.reject(reason));
        }
        let response =
            DnsRelay::decode(payload).map_err(|error| self.fault_remote_response(error))?;
        let Some(live) = self.outbound.live(response.request_id) else {
            let reason = self.outbound_absent_reason(response.request_id);
            return Err(self.fault_peer(reason));
        };
        if live.generation != self.policy_generation {
            return Err(self.fault_peer(Hip76FailureReason::StaleGeneration));
        }
        if response.status == DnsRelayStatus::Ok {
            let actual = validate_dns_response(&response.response)
                .map_err(|_| self.fault_peer(Hip76FailureReason::InvalidDnsResponse))?;
            if live.dns_correlation != Some(actual) {
                return Err(self.fault_peer(Hip76FailureReason::DnsCorrelationMismatch));
            }
        }
        let _ = self
            .outbound
            .complete(response.request_id, TombstoneKind::Completed);
        self.process.requester_responses_received =
            self.process.requester_responses_received.saturating_add(1);

        Ok(Hip76RequesterResponse {
            request_id: response.request_id,
            generation: live.generation,
            status: response.status,
            response: Hip76UntrustedDnsResponse(response.response),
        })
    }

    pub fn expire(&mut self, now: Instant) -> Hip76Expiration {
        let expiration = Hip76Expiration {
            requester_request_ids: self.outbound.expire(now),
            provider_request_ids: self.inbound.expire(now),
        };
        self.process.expired_requests = self
            .process
            .expired_requests
            .saturating_add(saturating_usize_to_u64(expiration.count()));
        expiration
    }

    /// Return the next HIP-76 work deadline without exposing request identity.
    pub fn pending_deadline(&self) -> Option<Instant> {
        match (
            self.outbound.pending_deadline(),
            self.inbound.pending_deadline(),
        ) {
            (Some(left), Some(right)) => Some(left.min(right)),
            (Some(deadline), None) | (None, Some(deadline)) => Some(deadline),
            (None, None) => None,
        }
    }

    /// Record the service mask authenticated by the completed VERSION exchange.
    pub fn observe_remote_services(&mut self, services: u64) {
        self.remote_services = services;
    }

    /// Apply the live-request ceiling agreed by the canonical Denuo registry.
    ///
    /// HIP-76 cannot be active before registry negotiation, so this normally
    /// runs with empty books. If a caller attempts to shrink an active session
    /// beneath its current work, all HIP-76 work is revoked fail-closed while
    /// the ordinary peer remains connected.
    pub fn set_negotiated_maximum_live_requests(
        &mut self,
        maximum_live_requests: u16,
    ) -> Result<Hip76RevokedWork, Hip76Error> {
        if maximum_live_requests == 0 {
            return Err(self.reject(Hip76FailureReason::CapacityExceeded));
        }
        let effective = self
            .configured_maximum_live_requests
            .min(maximum_live_requests);
        let effective = usize::from(effective);
        let revoked = if self.outbound.live.len() > effective || self.inbound.live.len() > effective
        {
            self.revoke_live_work()
        } else {
            Hip76RevokedWork::default()
        };
        self.outbound.set_maximum_live(effective);
        self.inbound.set_maximum_live(effective);
        Ok(revoked)
    }

    /// Apply the symmetric packet ceiling and live-request capacity computed by
    /// the canonical Denuo agreement.
    pub fn set_negotiated_resource_limits(
        &mut self,
        maximum_send_size: u32,
        maximum_live_requests: u16,
    ) -> Result<Hip76RevokedWork, Hip76Error> {
        if maximum_send_size == 0 {
            return Err(self.reject(Hip76FailureReason::CapacityExceeded));
        }
        if maximum_live_requests == 0 {
            return Err(self.reject(Hip76FailureReason::CapacityExceeded));
        }
        let effective_send_size = self
            .configured_maximum_send_size
            .min(usize::try_from(maximum_send_size).unwrap_or(usize::MAX))
            .min(MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE);
        let revoked = self.set_negotiated_maximum_live_requests(maximum_live_requests)?;
        self.negotiated_maximum_send_size = effective_send_size;
        Ok(revoked)
    }

    /// Fail closed for this experimental protocol without disconnecting or
    /// penalizing the ordinary Handshake peer session.
    pub fn disable_protocol(&mut self, reason: Hip76FailureReason) -> Hip76RevokedWork {
        self.last_failure = Some(reason);
        self.revoked = true;
        self.revoke_live_work()
    }

    /// Record an irreversible remote HIP-76 protocol fault for this
    /// connection while leaving the ordinary Handshake peer session intact.
    ///
    /// Outer framing code uses this after it has safely drained a
    /// packet-specific violation before a payload reaches the session codec.
    pub fn fault_protocol(&mut self, reason: Hip76FailureReason) -> Hip76RevokedWork {
        self.last_failure = Some(reason);
        self.process.rejected_operations = self.process.rejected_operations.saturating_add(1);
        self.peer_faulted = true;
        self.revoked = true;
        self.revoke_live_work()
    }

    /// Replace requester/provider policy and invalidate all work from the
    /// previous policy generation.
    pub fn replace_policy(
        &mut self,
        requester_policy: DnsRelayRequesterPolicy,
        provider_policy: Hip76ProviderPolicy,
        next_generation: u64,
    ) -> Result<Hip76RevokedWork, Hip76Error> {
        if next_generation <= self.policy_generation {
            return Err(self.reject(Hip76FailureReason::StaleGeneration));
        }
        let revoked = self.revoke_live_work();
        self.requester_policy = requester_policy;
        self.provider_policy = provider_policy;
        self.policy_generation = next_generation;
        self.revoked = false;
        Ok(revoked)
    }

    /// Disable both HIP-76 roles and invalidate all asynchronous work.
    pub fn revoke(&mut self, next_generation: u64) -> Result<Hip76RevokedWork, Hip76Error> {
        if next_generation <= self.policy_generation {
            return Err(self.reject(Hip76FailureReason::StaleGeneration));
        }
        let revoked = self.revoke_live_work();
        self.requester_policy = DnsRelayRequesterPolicy::Disabled;
        self.provider_policy = Hip76ProviderPolicy::disabled();
        self.policy_generation = next_generation;
        self.revoked = true;
        Ok(revoked)
    }

    /// Update the Denuo agreement. Losing it revokes HIP-76 work only.
    pub fn set_registry_negotiated(&mut self, negotiated: bool) -> Hip76RevokedWork {
        self.registry_negotiated = negotiated;
        if negotiated {
            Hip76RevokedWork::default()
        } else {
            self.revoke_live_work()
        }
    }

    /// Revoke every live ID before the outer peer handle is discarded.
    pub fn disconnect(&mut self) -> Hip76RevokedWork {
        let revoked = self.revoke_live_work();
        self.connected = false;
        revoked
    }

    fn phase(&self) -> Hip76ConnectionPhase {
        if !self.connected {
            Hip76ConnectionPhase::Disconnected
        } else if self.peer_faulted {
            Hip76ConnectionPhase::Faulted
        } else if self.revoked {
            Hip76ConnectionPhase::Revoked
        } else if !self.registry_negotiated {
            Hip76ConnectionPhase::AwaitingRegistry
        } else {
            Hip76ConnectionPhase::Active
        }
    }

    fn connection_failure(&self) -> Option<Hip76FailureReason> {
        if !self.connected {
            Some(Hip76FailureReason::Disconnected)
        } else if self.peer_faulted {
            Some(Hip76FailureReason::PeerFaulted)
        } else if self.revoked {
            Some(Hip76FailureReason::Revoked)
        } else if !self.registry_negotiated {
            Some(Hip76FailureReason::RegistryNotNegotiated)
        } else {
            None
        }
    }

    fn requester_failure(&self) -> Option<Hip76FailureReason> {
        if let Some(reason) = self.connection_failure() {
            return Some(reason);
        }
        if self.requester_policy == DnsRelayRequesterPolicy::Disabled {
            return Some(Hip76FailureReason::RequesterDisabled);
        }
        if self.local_services & DENUO_EXTENSION_SERVICE.value() == 0 {
            return Some(Hip76FailureReason::RegistryNotNegotiated);
        }
        if !services_advertise_provider(self.remote_services) {
            return Some(Hip76FailureReason::RemoteProviderNotAdvertised);
        }
        None
    }

    fn provider_failure(&self) -> Option<Hip76FailureReason> {
        if let Some(reason) = self.provider_connection_failure() {
            return Some(reason);
        }
        if !self.provider_policy.is_backend_ready() {
            return Some(Hip76FailureReason::BackendNotReady);
        }
        None
    }

    fn provider_connection_failure(&self) -> Option<Hip76FailureReason> {
        if let Some(reason) = self.connection_failure() {
            return Some(reason);
        }
        if !self.provider_policy.is_opted_in() {
            return Some(Hip76FailureReason::ProviderNotOptedIn);
        }
        if !services_advertise_provider(self.local_services) {
            return Some(Hip76FailureReason::LocalProviderNotAdvertised);
        }
        None
    }

    fn allocate_request_id(&mut self) -> Result<u64, Hip76Error> {
        let maximum_attempts = self
            .outbound
            .live
            .len()
            .saturating_add(self.outbound.tombstones.len())
            .saturating_add(1);
        for _ in 0..maximum_attempts {
            let candidate = self.next_request_id.max(1);
            self.next_request_id = candidate.wrapping_add(1).max(1);
            if !self.outbound.live.contains_key(&candidate)
                && !self.outbound.tombstones.contains_key(&candidate)
            {
                return Ok(candidate);
            }
        }
        Err(self.reject(Hip76FailureReason::CapacityExceeded))
    }

    fn allocate_write_token(
        &mut self,
        request_id: u64,
        kind: Hip76WriteKind,
    ) -> Result<Hip76WriteToken, Hip76Error> {
        let sequence = self.next_work_token;
        self.next_work_token = sequence
            .checked_add(1)
            .ok_or_else(|| self.reject(Hip76FailureReason::CapacityExceeded))?;
        Ok(Hip76WriteToken {
            sequence,
            request_id,
            generation: self.policy_generation,
            kind,
        })
    }

    fn provider_rejection(
        &mut self,
        request_id: u64,
        status: DnsRelayStatus,
        now: Instant,
    ) -> Result<Hip76ProviderRejection, Hip76Error> {
        debug_assert!(matches!(
            status,
            DnsRelayStatus::InvalidQuery
                | DnsRelayStatus::Busy
                | DnsRelayStatus::ResolverUnavailable
        ));
        let message = DnsRelay::new(request_id, status, Vec::new())
            .map_err(|error| self.local_response_error(error))?;
        let payload = message
            .encode()
            .map_err(|error| self.local_response_error(error))?;
        if payload.len() > self.negotiated_maximum_send_size {
            self.disable_protocol(Hip76FailureReason::ResponseTooLarge);
            return Err(self.reject(Hip76FailureReason::ResponseTooLarge));
        }
        let work_token =
            self.allocate_write_token(request_id, Hip76WriteKind::ProviderRejection)?;
        self.writes
            .create(work_token)
            .map_err(|reason| self.reject(reason))?;
        self.process.provider_responses_created =
            self.process.provider_responses_created.saturating_add(1);
        Ok(Hip76ProviderRejection {
            request_id,
            generation: self.policy_generation,
            deadline: now + self.request_timeout,
            status,
            packet: Box::new(hip76_packet(DNS_RELAY_RESPONSE_PACKET.value(), payload)),
            work_token,
        })
    }

    fn revoke_live_work(&mut self) -> Hip76RevokedWork {
        let revoked = Hip76RevokedWork {
            requester_request_ids: self.outbound.revoke_all(),
            provider_request_ids: self.inbound.revoke_all(),
        };
        self.process.revoked_requests = self
            .process
            .revoked_requests
            .saturating_add(saturating_usize_to_u64(revoked.count()));
        revoked
    }

    fn outbound_absent_reason(&self, request_id: u64) -> Hip76FailureReason {
        match self.outbound.tombstone(request_id) {
            Some(TombstoneKind::Expired) => Hip76FailureReason::DeadlineExpired,
            Some(TombstoneKind::Completed | TombstoneKind::Revoked) => {
                Hip76FailureReason::DuplicateOrLateResponse
            }
            None => Hip76FailureReason::UncorrelatedResponse,
        }
    }

    fn inbound_absent_reason(&self, request_id: u64) -> Hip76FailureReason {
        match self.inbound.tombstone(request_id) {
            Some(TombstoneKind::Expired) => Hip76FailureReason::DeadlineExpired,
            Some(TombstoneKind::Revoked) => Hip76FailureReason::StaleGeneration,
            Some(TombstoneKind::Completed) => Hip76FailureReason::DuplicateOrReplay,
            None => Hip76FailureReason::UncorrelatedResponse,
        }
    }

    fn local_request_error(&mut self, error: DnsRelayProtocolError) -> Hip76Error {
        let reason = match error {
            DnsRelayProtocolError::QueryTooLarge(_) => Hip76FailureReason::RequestTooLarge,
            _ => Hip76FailureReason::InvalidLocalRequest,
        };
        self.reject(reason)
    }

    fn fault_remote_request(&mut self, error: DnsRelayProtocolError) -> Hip76Error {
        let reason = match error {
            DnsRelayProtocolError::QueryTooLarge(_) => Hip76FailureReason::RequestTooLarge,
            _ => Hip76FailureReason::MalformedRequest,
        };
        self.fault_peer(reason)
    }

    fn local_response_error(&mut self, error: DnsRelayProtocolError) -> Hip76Error {
        let reason = match error {
            DnsRelayProtocolError::ResponseTooLarge(_) => Hip76FailureReason::ResponseTooLarge,
            _ => Hip76FailureReason::InvalidLocalResponse,
        };
        self.reject(reason)
    }

    fn fault_remote_response(&mut self, error: DnsRelayProtocolError) -> Hip76Error {
        let reason = match error {
            DnsRelayProtocolError::ResponseTooLarge(_) => Hip76FailureReason::ResponseTooLarge,
            _ => Hip76FailureReason::MalformedResponse,
        };
        self.fault_peer(reason)
    }

    fn fault_peer(&mut self, reason: Hip76FailureReason) -> Hip76Error {
        let _ = self.fault_protocol(reason);
        Hip76Error { reason }
    }

    pub(crate) fn reject(&mut self, reason: Hip76FailureReason) -> Hip76Error {
        self.last_failure = Some(reason);
        self.process.rejected_operations = self.process.rejected_operations.saturating_add(1);
        Hip76Error { reason }
    }
}

pub const fn is_hip76_packet_type(packet_type: PacketType) -> bool {
    matches!(
        packet_type,
        PacketType::Unknown(value)
            if value == DNS_RELAY_REQUEST_PACKET.value()
                || value == DNS_RELAY_RESPONSE_PACKET.value()
    )
}

fn services_advertise_provider(services: u64) -> bool {
    services & DENUO_EXTENSION_SERVICE.value() != 0 && services & DNS_RELAY_SERVICE.value() != 0
}

fn hip76_packet(packet_type: u8, payload: Vec<u8>) -> Packet {
    Packet::Unknown {
        packet_type: PacketType::Unknown(packet_type),
        payload,
    }
}

const DNS_HEADER_SIZE: usize = 12;
const DNS_TYPE_OPT: u16 = 41;
const DNS_CLASS_IN: u16 = 1;
const DNS_OPTION_ECS: u16 = 8;
const DNS_FLAG_RESPONSE: u16 = 0x8000;
const DNS_EDNS_DO: u32 = 0x0000_8000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DnsShapeError;

fn validate_dns_query(message: &[u8]) -> Result<DnsCorrelation, DnsShapeError> {
    if message.len() < DNS_HEADER_SIZE {
        return Err(DnsShapeError);
    }
    let flags = read_dns_u16(message, 2)?;
    if flags != 0
        || read_dns_u16(message, 4)? != 1
        || read_dns_u16(message, 6)? != 0
        || read_dns_u16(message, 8)? != 0
        || read_dns_u16(message, 10)? != 1
    {
        return Err(DnsShapeError);
    }

    let (correlation, offset) = parse_dns_question(message, DNS_HEADER_SIZE, false)?;
    let mut cursor = offset;
    if message.get(cursor).copied() != Some(0) {
        return Err(DnsShapeError);
    }
    cursor = cursor.checked_add(1).ok_or(DnsShapeError)?;
    if read_dns_u16(message, cursor)? != DNS_TYPE_OPT {
        return Err(DnsShapeError);
    }
    cursor = cursor.checked_add(2).ok_or(DnsShapeError)?;
    let udp_payload = read_dns_u16(message, cursor)?;
    if !(512..=4096).contains(&udp_payload) {
        return Err(DnsShapeError);
    }
    cursor = cursor.checked_add(2).ok_or(DnsShapeError)?;
    let ttl = read_dns_u32(message, cursor)?;
    if ttl != DNS_EDNS_DO {
        return Err(DnsShapeError);
    }
    cursor = cursor.checked_add(4).ok_or(DnsShapeError)?;
    let option_length = usize::from(read_dns_u16(message, cursor)?);
    cursor = cursor.checked_add(2).ok_or(DnsShapeError)?;
    let options_end = cursor.checked_add(option_length).ok_or(DnsShapeError)?;
    if options_end != message.len() {
        return Err(DnsShapeError);
    }
    while cursor < options_end {
        let option_code = read_dns_u16(message, cursor)?;
        let length = usize::from(read_dns_u16(message, cursor + 2)?);
        cursor = cursor.checked_add(4).ok_or(DnsShapeError)?;
        let end = cursor.checked_add(length).ok_or(DnsShapeError)?;
        if option_code == DNS_OPTION_ECS || end > options_end {
            return Err(DnsShapeError);
        }
        cursor = end;
    }
    Ok(correlation)
}

fn validate_dns_response(message: &[u8]) -> Result<DnsCorrelation, DnsShapeError> {
    if message.len() < DNS_HEADER_SIZE {
        return Err(DnsShapeError);
    }
    let flags = read_dns_u16(message, 2)?;
    if flags & DNS_FLAG_RESPONSE == 0
        || flags & 0x7800 != 0
        || flags & 0x0200 != 0
        || flags & 0x0040 != 0
        || read_dns_u16(message, 4)? != 1
    {
        return Err(DnsShapeError);
    }
    let answer_count = usize::from(read_dns_u16(message, 6)?);
    let authority_count = usize::from(read_dns_u16(message, 8)?);
    let additional_count = usize::from(read_dns_u16(message, 10)?);
    let (correlation, mut cursor) = parse_dns_question(message, DNS_HEADER_SIZE, true)?;
    let record_count = answer_count
        .checked_add(authority_count)
        .and_then(|count| count.checked_add(additional_count))
        .ok_or(DnsShapeError)?;
    for _ in 0..record_count {
        cursor = skip_dns_record(message, cursor)?;
    }
    if cursor != message.len() {
        return Err(DnsShapeError);
    }
    Ok(correlation)
}

fn skip_dns_record(message: &[u8], offset: usize) -> Result<usize, DnsShapeError> {
    let (_, name_end, _) = parse_dns_name(message, offset, true)?;
    let fixed_end = name_end.checked_add(10).ok_or(DnsShapeError)?;
    if fixed_end > message.len() {
        return Err(DnsShapeError);
    }
    let rdata_length = usize::from(read_dns_u16(message, name_end + 8)?);
    let record_end = fixed_end.checked_add(rdata_length).ok_or(DnsShapeError)?;
    if record_end > message.len() {
        return Err(DnsShapeError);
    }
    Ok(record_end)
}

fn parse_dns_question(
    message: &[u8],
    offset: usize,
    allow_compression: bool,
) -> Result<(DnsCorrelation, usize), DnsShapeError> {
    let (mut canonical_name, next_offset, rightmost_label) =
        parse_dns_name(message, offset, allow_compression)?;
    let qtype = read_dns_u16(message, next_offset)?;
    let qclass = read_dns_u16(message, next_offset + 2)?;
    if qclass != DNS_CLASS_IN || !allowed_dns_query_type(qtype) {
        return Err(DnsShapeError);
    }
    let root = std::str::from_utf8(&rightmost_label).map_err(|_| DnsShapeError)?;
    if !verify_name(root) {
        return Err(DnsShapeError);
    }
    canonical_name.extend_from_slice(&qtype.to_be_bytes());
    canonical_name.extend_from_slice(&qclass.to_be_bytes());
    Ok((
        DnsCorrelation {
            transaction_id: read_dns_u16(message, 0)?,
            question_hash: blake2b_256(&canonical_name),
        },
        next_offset.checked_add(4).ok_or(DnsShapeError)?,
    ))
}

fn parse_dns_name(
    message: &[u8],
    offset: usize,
    allow_compression: bool,
) -> Result<(Vec<u8>, usize, Vec<u8>), DnsShapeError> {
    let mut canonical = Vec::with_capacity(64);
    let mut rightmost = Vec::new();
    let mut cursor = offset;
    let mut next_offset = None;
    let mut jumps = 0_u8;
    loop {
        let length = *message.get(cursor).ok_or(DnsShapeError)?;
        if length & 0xc0 == 0xc0 {
            if !allow_compression {
                return Err(DnsShapeError);
            }
            let low = *message.get(cursor + 1).ok_or(DnsShapeError)?;
            let pointer = usize::from(u16::from(length & 0x3f) << 8 | u16::from(low));
            if pointer >= cursor || pointer >= message.len() || jumps >= 32 {
                return Err(DnsShapeError);
            }
            next_offset.get_or_insert(cursor + 2);
            cursor = pointer;
            jumps = jumps.saturating_add(1);
            continue;
        }
        if length & 0xc0 != 0 || length > 63 {
            return Err(DnsShapeError);
        }
        cursor = cursor.checked_add(1).ok_or(DnsShapeError)?;
        if length == 0 {
            canonical.push(0);
            if canonical.len() > 255 {
                return Err(DnsShapeError);
            }
            return Ok((canonical, next_offset.unwrap_or(cursor), rightmost));
        }
        let label_end = cursor
            .checked_add(usize::from(length))
            .ok_or(DnsShapeError)?;
        let label = message.get(cursor..label_end).ok_or(DnsShapeError)?;
        canonical.push(length);
        canonical.extend(label.iter().map(u8::to_ascii_lowercase));
        rightmost.clear();
        rightmost.extend(label.iter().map(u8::to_ascii_lowercase));
        if canonical.len() > 254 {
            return Err(DnsShapeError);
        }
        cursor = label_end;
    }
}

const fn allowed_dns_query_type(qtype: u16) -> bool {
    matches!(
        qtype,
        1 | 2 | 5 | 6 | 15 | 16 | 28 | 33 | 39 | 43 | 46 | 47 | 48 | 50 | 51 | 52 | 64 | 65 | 257
    )
}

fn read_dns_u16(message: &[u8], offset: usize) -> Result<u16, DnsShapeError> {
    let bytes = message
        .get(offset..offset.checked_add(2).ok_or(DnsShapeError)?)
        .ok_or(DnsShapeError)?;
    Ok(u16::from_be_bytes([bytes[0], bytes[1]]))
}

fn read_dns_u32(message: &[u8], offset: usize) -> Result<u32, DnsShapeError> {
    let bytes = message
        .get(offset..offset.checked_add(4).ok_or(DnsShapeError)?)
        .ok_or(DnsShapeError)?;
    Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn saturating_usize_to_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SERVICE_NETWORK;
    use hns_dns_relay_protocol::{MAX_DNS_RELAY_QUERY_SIZE, MAX_DNS_RELAY_RESPONSE_SIZE};

    const DENUO_SERVICES: u64 = SERVICE_NETWORK | DENUO_EXTENSION_SERVICE.value();
    const PROVIDER_SERVICES: u64 = DENUO_SERVICES | DNS_RELAY_SERVICE.value();

    fn config(
        requester_policy: DnsRelayRequesterPolicy,
        provider_policy: Hip76ProviderPolicy,
    ) -> Hip76SessionConfig {
        Hip76SessionConfig {
            requester_policy,
            provider_policy,
            request_timeout: Duration::from_secs(1),
            first_request_id: 7,
            ..Hip76SessionConfig::default()
        }
    }

    fn requester(direction: PeerDirection) -> Hip76Session {
        Hip76Session::new(
            direction,
            DENUO_SERVICES,
            PROVIDER_SERVICES,
            true,
            config(
                DnsRelayRequesterPolicy::Auto,
                Hip76ProviderPolicy::disabled(),
            ),
        )
        .expect("requester session")
    }

    fn provider(direction: PeerDirection, backend_ready: bool) -> Hip76Session {
        Hip76Session::new(
            direction,
            PROVIDER_SERVICES,
            DENUO_SERVICES,
            true,
            config(
                DnsRelayRequesterPolicy::Disabled,
                Hip76ProviderPolicy::opted_in(backend_ready),
            ),
        )
        .expect("provider session")
    }

    fn packet_parts(packet: &Packet) -> (PacketType, &[u8]) {
        match packet {
            Packet::Unknown {
                packet_type,
                payload,
            } => (*packet_type, payload),
            _ => panic!("HIP-76 uses a private packet"),
        }
    }

    fn dns_query(transaction_id: u16, labels: &[&str], qtype: u16) -> Vec<u8> {
        dns_query_with_size(transaction_id, labels, qtype, None)
    }

    fn dns_query_with_size(
        transaction_id: u16,
        labels: &[&str],
        qtype: u16,
        exact_size: Option<usize>,
    ) -> Vec<u8> {
        let mut query = Vec::new();
        query.extend_from_slice(&transaction_id.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        query.extend_from_slice(&0_u16.to_be_bytes());
        query.extend_from_slice(&1_u16.to_be_bytes());
        for label in labels {
            query.push(u8::try_from(label.len()).expect("test label length"));
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&qtype.to_be_bytes());
        query.extend_from_slice(&DNS_CLASS_IN.to_be_bytes());
        query.push(0);
        query.extend_from_slice(&DNS_TYPE_OPT.to_be_bytes());
        query.extend_from_slice(&4096_u16.to_be_bytes());
        query.extend_from_slice(&DNS_EDNS_DO.to_be_bytes());

        let option_body = exact_size
            .map(|size| {
                size.checked_sub(query.len() + 2 + 4)
                    .expect("requested test query size")
            })
            .unwrap_or(0);
        let option_length = if exact_size.is_some() {
            option_body + 4
        } else {
            0
        };
        query.extend_from_slice(
            &u16::try_from(option_length)
                .expect("test EDNS option length")
                .to_be_bytes(),
        );
        if exact_size.is_some() {
            query.extend_from_slice(&12_u16.to_be_bytes());
            query.extend_from_slice(
                &u16::try_from(option_body)
                    .expect("test padding length")
                    .to_be_bytes(),
            );
            query.resize(query.len() + option_body, 0);
        }
        assert_eq!(exact_size.unwrap_or(query.len()), query.len());
        query
    }

    fn dns_response(query: &[u8]) -> Vec<u8> {
        let (_, question_end) =
            parse_dns_question(query, DNS_HEADER_SIZE, false).expect("test DNS query");
        let mut response = query[..question_end].to_vec();
        response[2..4].copy_from_slice(&0x8180_u16.to_be_bytes());
        response[6..12].fill(0);
        response
    }

    fn provider_request(disposition: Hip76ProviderDisposition) -> Hip76ProviderRequest {
        match disposition {
            Hip76ProviderDisposition::Request(request) => request,
            Hip76ProviderDisposition::Rejection(rejection) => {
                panic!("unexpected provider rejection: {rejection:?}")
            }
        }
    }

    fn provider_rejection(disposition: Hip76ProviderDisposition) -> Hip76ProviderRejection {
        match disposition {
            Hip76ProviderDisposition::Rejection(rejection) => rejection,
            Hip76ProviderDisposition::Request(request) => {
                panic!("unexpected provider work: {request:?}")
            }
        }
    }

    #[test]
    fn requester_policy_snapshot_preserves_opt_out_and_allows_explicit_reenable() {
        let magic = 0x1122_3344;
        let mut policy =
            Hip76RequesterPolicyRuntime::fresh(magic, DnsRelayRequesterPolicy::Auto, 1)
                .expect("fresh requester policy");
        assert!(policy.status().durable_state_dirty);
        let initial = policy.snapshot();
        policy.acknowledge_persisted(initial.floor);
        assert!(!policy.status().durable_state_dirty);

        let disabled = policy
            .replace(1, DnsRelayRequesterPolicy::Disabled, 2)
            .expect("persist requester opt-out");
        assert_eq!(disabled.requester_policy, DnsRelayRequesterPolicy::Disabled);
        let snapshot = policy.snapshot();
        let floor = Hip76RequesterPolicyFloor::decode(&snapshot.floor.encode())
            .expect("decode requester floor");
        let restored = Hip76RequesterPolicyRuntime::restore(magic, None, &snapshot.bytes, floor)
            .expect("restore requester opt-out");
        assert_eq!(
            restored.status().requester_policy,
            DnsRelayRequesterPolicy::Disabled
        );
        assert!(!restored.status().durable_state_dirty);

        let reenabled = Hip76RequesterPolicyRuntime::restore(
            magic,
            Some(DnsRelayRequesterPolicy::Auto),
            &snapshot.bytes,
            floor,
        )
        .expect("explicitly re-enable requester");
        assert_eq!(
            reenabled.status().requester_policy,
            DnsRelayRequesterPolicy::Auto
        );
        assert_eq!(reenabled.status().generation, 3);
        assert!(reenabled.status().durable_state_dirty);
    }

    #[test]
    fn requester_policy_snapshot_rejects_corruption_network_mismatch_and_rollback() {
        let magic = 0x1122_3344;
        let policy =
            Hip76RequesterPolicyRuntime::fresh(magic, DnsRelayRequesterPolicy::Disabled, 7)
                .expect("fresh requester policy");
        let snapshot = policy.snapshot();

        let mut corrupt = snapshot.bytes.clone();
        corrupt[22] ^= 1;
        assert_eq!(
            Hip76RequesterPolicyRuntime::restore(magic, None, &corrupt, snapshot.floor),
            Err(Hip76RequesterPolicyError::CorruptSnapshot)
        );
        assert_eq!(
            Hip76RequesterPolicyRuntime::restore(magic ^ 1, None, &snapshot.bytes, snapshot.floor,),
            Err(Hip76RequesterPolicyError::NetworkMismatch)
        );
        assert_eq!(
            Hip76RequesterPolicyRuntime::restore(
                magic,
                None,
                &snapshot.bytes,
                Hip76RequesterPolicyFloor {
                    generation: 8,
                    network_magic: magic,
                },
            ),
            Err(Hip76RequesterPolicyError::GenerationRollback)
        );

        let mut corrupt_floor = snapshot.floor.encode();
        corrupt_floor[14] ^= 1;
        assert_eq!(
            Hip76RequesterPolicyFloor::decode(&corrupt_floor),
            Err(Hip76RequesterPolicyError::CorruptSnapshot)
        );
    }

    #[test]
    fn provider_advertisement_requires_opt_in_backend_and_denuo() {
        let unsafe_base = SERVICE_NETWORK | DNS_RELAY_SERVICE.value();
        assert_eq!(
            hip76_advertised_services(unsafe_base, Hip76ProviderPolicy::opted_in(true)),
            SERVICE_NETWORK
        );
        assert_eq!(
            hip76_advertised_services(PROVIDER_SERVICES, Hip76ProviderPolicy::disabled()),
            DENUO_SERVICES
        );
        assert_eq!(
            hip76_advertised_services(PROVIDER_SERVICES, Hip76ProviderPolicy::opted_in(false)),
            DENUO_SERVICES
        );
        assert_eq!(
            hip76_advertised_services(DENUO_SERVICES, Hip76ProviderPolicy::opted_in(true)),
            PROVIDER_SERVICES
        );
    }

    #[test]
    fn requester_and_provider_roles_are_independent_of_connection_direction() {
        let now = Instant::now();
        // The requester accepted the connection and advertises no provider
        // service. The provider initiated it and the remote requester also
        // advertises no provider service. Neither fact reverses local roles.
        let mut requester = requester(PeerDirection::Inbound);
        let mut provider = provider(PeerDirection::Outbound, true);

        let query = dns_query(0x1234, &["www", "alpha"], 52);
        let outbound = requester
            .begin_request(query.clone(), now)
            .expect("requester does not need provider advertisement");
        let (packet_type, payload) = packet_parts(&outbound.packet);
        let inbound = provider
            .receive_packet(packet_type, payload, now)
            .expect("remote request uses local provider role");
        let Hip76Inbound::ProviderRequest(inbound) = inbound else {
            panic!("provider request");
        };
        assert_eq!(inbound.query(), query);

        let answer = dns_response(inbound.query());
        let (work, retained_query) = inbound.into_parts();
        assert_eq!(retained_query, query);
        let response = provider
            .prepare_provider_response(&work, DnsRelayStatus::Ok, answer.clone(), now)
            .expect("codec-valid test backend result");
        let response_work_token = response.work_token();
        provider
            .commit_provider_response(work, now)
            .expect("writer queue admission");
        let (packet_type, payload) = packet_parts(&response.packet);
        let received = requester
            .receive_packet(packet_type, payload, now)
            .expect("correlated response");
        let Hip76Inbound::RequesterResponse(received) = received else {
            panic!("requester response");
        };
        assert_eq!(received.response.as_bytes(), answer);
        provider
            .outbound_socket_written(response_work_token)
            .expect("response socket write");

        assert_eq!(
            provider.begin_request(dns_query(1, &["alpha"], 1), now),
            Err(Hip76Error {
                reason: Hip76FailureReason::RequesterDisabled
            })
        );
        assert!(requester.diagnostics().requester_eligible);
        assert!(!requester.diagnostics().provider_opted_in);
        assert!(provider.diagnostics().provider_available);
    }

    #[test]
    fn provider_requires_consent_and_ready_backend_even_if_bit_is_present() {
        let now = Instant::now();
        let request = GetDnsRelay::new(11, dns_query(11, &["alpha"], 1))
            .expect("request")
            .encode()
            .expect("encode");
        let mut opted_out = Hip76Session::new(
            PeerDirection::Inbound,
            PROVIDER_SERVICES,
            DENUO_SERVICES,
            true,
            config(
                DnsRelayRequesterPolicy::Auto,
                Hip76ProviderPolicy::disabled(),
            ),
        )
        .expect("session");
        assert_eq!(
            opted_out.receive_request(&request, now),
            Err(Hip76Error {
                reason: Hip76FailureReason::ProviderNotOptedIn
            })
        );

        let mut not_ready = provider(PeerDirection::Inbound, false);
        let rejection = provider_rejection(
            not_ready
                .receive_request(&request, now)
                .expect("canonical request receives a status"),
        );
        assert_eq!(rejection.status, DnsRelayStatus::ResolverUnavailable);
        let (_, payload) = packet_parts(&rejection.packet);
        let response = DnsRelay::decode(payload).expect("canonical status response");
        assert_eq!(response.request_id, 11);
        assert_eq!(response.status, DnsRelayStatus::ResolverUnavailable);
        assert!(response.response.is_empty());
    }

    #[test]
    fn well_framed_provider_rejections_are_correlated_status_packets() {
        let now = Instant::now();
        let mut invalid_provider = provider(PeerDirection::Inbound, true);
        let invalid_envelope = GetDnsRelay::new(21, vec![0xff])
            .expect("non-empty bounded request")
            .encode()
            .expect("encode");
        let invalid = provider_rejection(
            invalid_provider
                .receive_request(&invalid_envelope, now)
                .expect("invalid DNS shape has a correlated status"),
        );
        assert_eq!(invalid.status, DnsRelayStatus::InvalidQuery);
        let invalid_token = invalid.work_token();
        let (_, invalid_payload) = packet_parts(&invalid.packet);
        assert_eq!(
            DnsRelay::decode(invalid_payload).expect("status response"),
            DnsRelay::new(21, DnsRelayStatus::InvalidQuery, Vec::new()).expect("expected status")
        );
        invalid_provider
            .provider_rejection_queue_admitted(invalid_token)
            .expect("queue admission");
        invalid_provider
            .outbound_socket_written(invalid_token)
            .expect("socket write");
        assert_eq!(
            invalid_provider
                .diagnostics()
                .process
                .provider_responses_socket_written,
            1
        );
        assert_eq!(
            invalid_provider.diagnostics().phase,
            Hip76ConnectionPhase::Active
        );

        let mut busy_config = config(
            DnsRelayRequesterPolicy::Disabled,
            Hip76ProviderPolicy::opted_in(true),
        );
        busy_config.maximum_live_requests = 1;
        let mut busy_provider = Hip76Session::new(
            PeerDirection::Inbound,
            PROVIDER_SERVICES,
            DENUO_SERVICES,
            true,
            busy_config,
        )
        .expect("busy provider");
        let first = GetDnsRelay::new(31, dns_query(31, &["alpha"], 1))
            .expect("request")
            .encode()
            .expect("encode");
        let _ = provider_request(
            busy_provider
                .receive_request(&first, now)
                .expect("first request enters backend"),
        );
        let second = GetDnsRelay::new(32, dns_query(32, &["beta"], 1))
            .expect("request")
            .encode()
            .expect("encode");
        let busy = provider_rejection(
            busy_provider
                .receive_request(&second, now)
                .expect("capacity pressure has a correlated status"),
        );
        assert_eq!(busy.status, DnsRelayStatus::Busy);
        let (_, busy_payload) = packet_parts(&busy.packet);
        let busy_wire = DnsRelay::decode(busy_payload).expect("busy response");
        assert_eq!(busy_wire.request_id, 32);
        assert_eq!(busy_wire.status, DnsRelayStatus::Busy);
        assert!(busy_wire.response.is_empty());
        assert_eq!(
            busy_provider.diagnostics().phase,
            Hip76ConnectionPhase::Active
        );
    }

    #[test]
    fn provider_response_queue_failure_does_not_complete_live_work() {
        let now = Instant::now();
        let mut provider = provider(PeerDirection::Inbound, true);
        let query = dns_query(41, &["alpha"], 1);
        let envelope = GetDnsRelay::new(41, query.clone())
            .expect("request")
            .encode()
            .expect("encode");
        let request = provider_request(
            provider
                .receive_request(&envelope, now)
                .expect("provider request"),
        );
        let (work, _) = request.into_parts();
        let first = provider
            .prepare_provider_response(&work, DnsRelayStatus::Ok, dns_response(&query), now)
            .expect("first preparation");
        provider
            .outbound_queue_rejected(first.work_token())
            .expect("queue rejection");
        assert_eq!(provider.diagnostics().inbound_live_requests, 1);
        assert_eq!(
            provider
                .diagnostics()
                .process
                .provider_responses_queue_admitted,
            0
        );

        let retry = provider
            .prepare_provider_response(&work, DnsRelayStatus::Ok, dns_response(&query), now)
            .expect("work remains live for another preparation");
        let retry_token = retry.work_token();
        provider
            .commit_provider_response(work, now)
            .expect("commit after queue admission");
        assert_eq!(provider.diagnostics().inbound_live_requests, 0);
        provider
            .outbound_socket_written(retry_token)
            .expect("socket write");
        let totals = provider.diagnostics().process;
        assert_eq!(totals.provider_responses_created, 2);
        assert_eq!(totals.provider_responses_queue_admitted, 1);
        assert_eq!(totals.provider_responses_socket_written, 1);
    }

    #[test]
    fn request_write_counters_distinguish_creation_queue_and_socket() {
        let now = Instant::now();
        let mut requester = requester(PeerDirection::Outbound);
        let outbound = requester
            .begin_request(dns_query(1, &["alpha"], 1), now)
            .expect("request");
        let token = outbound.work_token();
        let created = requester.diagnostics().process;
        assert_eq!(created.outbound_requests_created, 1);
        assert_eq!(created.outbound_requests_queue_admitted, 0);
        assert_eq!(created.outbound_requests_socket_written, 0);
        requester
            .outbound_request_queue_admitted(token)
            .expect("queue admission");
        requester
            .outbound_socket_written(token)
            .expect("socket completion");
        let written = requester.diagnostics().process;
        assert_eq!(written.outbound_requests_created, 1);
        assert_eq!(written.outbound_requests_queue_admitted, 1);
        assert_eq!(written.outbound_requests_socket_written, 1);
    }

    #[test]
    fn canonical_full_payload_bounds_and_live_capacity_are_enforced() {
        assert_eq!(
            MAX_DNS_RELAY_REQUEST_PAYLOAD_SIZE,
            8 + 2 + MAX_DNS_RELAY_QUERY_SIZE
        );
        assert_eq!(
            MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE,
            8 + 1 + 2 + MAX_DNS_RELAY_RESPONSE_SIZE
        );

        let now = Instant::now();
        let mut config = config(
            DnsRelayRequesterPolicy::Auto,
            Hip76ProviderPolicy::disabled(),
        );
        config.maximum_live_requests = 1;
        let mut requester = Hip76Session::new(
            PeerDirection::Outbound,
            DENUO_SERVICES,
            PROVIDER_SERVICES,
            true,
            config,
        )
        .expect("session");
        let maximum_query = dns_query_with_size(1, &["alpha"], 1, Some(MAX_DNS_RELAY_QUERY_SIZE));
        let maximum = requester
            .begin_request(maximum_query, now)
            .expect("maximum body");
        let (_, payload) = packet_parts(&maximum.packet);
        assert_eq!(payload.len(), MAX_DNS_RELAY_REQUEST_PAYLOAD_SIZE);
        assert_eq!(
            requester.begin_request(dns_query(2, &["alpha"], 1), now),
            Err(Hip76Error {
                reason: Hip76FailureReason::CapacityExceeded
            })
        );

        let mut provider = provider(PeerDirection::Inbound, true);
        let oversized_request = Frame::new(
            PacketType::Unknown(DNS_RELAY_REQUEST_PACKET.value()),
            vec![0; MAX_DNS_RELAY_REQUEST_PAYLOAD_SIZE + 1],
        )
        .expect("well below generic frame limit");
        assert_eq!(
            provider.receive_frame(&oversized_request, now),
            Err(Hip76Error {
                reason: Hip76FailureReason::RequestTooLarge
            })
        );
        let oversized_response = Frame::new(
            PacketType::Unknown(DNS_RELAY_RESPONSE_PACKET.value()),
            vec![0; MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE + 1],
        )
        .expect("well below generic frame limit");
        assert_eq!(
            requester.receive_frame(&oversized_response, now),
            Err(Hip76Error {
                reason: Hip76FailureReason::ResponseTooLarge
            })
        );
    }

    #[test]
    fn responses_are_correlated_and_protocol_faults_stay_scoped_to_hip76() {
        let now = Instant::now();
        let query = dns_query(1, &["alpha"], 1);
        let mut uncorrelated_requester = requester(PeerDirection::Outbound);
        uncorrelated_requester
            .begin_request(query.clone(), now)
            .expect("outbound");
        let uncorrelated = DnsRelay::new(99, DnsRelayStatus::Ok, dns_response(&query))
            .expect("response")
            .encode()
            .expect("encode");
        assert_eq!(
            uncorrelated_requester.receive_response(&uncorrelated, now),
            Err(Hip76Error {
                reason: Hip76FailureReason::UncorrelatedResponse
            })
        );
        assert_eq!(
            uncorrelated_requester.diagnostics().phase,
            Hip76ConnectionPhase::Faulted
        );
        assert!(uncorrelated_requester.ordinary_peer_remains_available());

        let mut requester = requester(PeerDirection::Outbound);
        let outbound = requester
            .begin_request(query.clone(), now)
            .expect("outbound");
        let response = DnsRelay::new(
            outbound.request_id,
            DnsRelayStatus::Ok,
            dns_response(&query),
        )
        .expect("response")
        .encode()
        .expect("encode");
        requester
            .receive_response(&response, now)
            .expect("correlated");
        assert_eq!(
            requester.receive_response(&response, now),
            Err(Hip76Error {
                reason: Hip76FailureReason::DuplicateOrLateResponse
            })
        );
        assert!(requester.ordinary_peer_remains_available());
        assert_eq!(requester.diagnostics().phase, Hip76ConnectionPhase::Faulted);
    }

    #[test]
    fn generation_deadline_revocation_and_disconnect_cancel_bounded_work() {
        let now = Instant::now();
        let mut expiring_requester = requester(PeerDirection::Outbound);
        let expiring = expiring_requester
            .begin_request(dns_query(1, &["alpha"], 1), now)
            .expect("expiring request");
        let expiration = expiring_requester.expire(expiring.deadline);
        assert_eq!(expiration.requester_request_ids, vec![expiring.request_id]);
        let late = DnsRelay::new(
            expiring.request_id,
            DnsRelayStatus::Ok,
            dns_response(&dns_query(1, &["alpha"], 1)),
        )
        .expect("late response")
        .encode()
        .expect("encode");
        assert_eq!(
            expiring_requester.receive_response(&late, expiring.deadline),
            Err(Hip76Error {
                reason: Hip76FailureReason::DeadlineExpired
            })
        );

        let mut requester = requester(PeerDirection::Outbound);
        let live = requester
            .begin_request(dns_query(2, &["alpha"], 1), now)
            .expect("next request");
        let revoked = requester
            .replace_policy(
                DnsRelayRequesterPolicy::Disabled,
                Hip76ProviderPolicy::disabled(),
                2,
            )
            .expect("generation advances");
        assert_eq!(revoked.requester_request_ids, vec![live.request_id]);
        assert_eq!(
            requester.cancel_outbound_request(live.work_token()),
            Err(Hip76Error {
                reason: Hip76FailureReason::StaleGeneration
            })
        );

        requester
            .replace_policy(
                DnsRelayRequesterPolicy::Auto,
                Hip76ProviderPolicy::disabled(),
                3,
            )
            .expect("requester re-enabled");
        let disconnected = requester
            .begin_request(dns_query(3, &["alpha"], 1), now)
            .expect("live before disconnect");
        let revoked = requester.disconnect();
        assert_eq!(revoked.requester_request_ids, vec![disconnected.request_id]);
        assert_eq!(
            requester.begin_request(dns_query(4, &["alpha"], 1), now),
            Err(Hip76Error {
                reason: Hip76FailureReason::Disconnected
            })
        );
        assert_eq!(
            requester.diagnostics().phase,
            Hip76ConnectionPhase::Disconnected
        );
    }

    #[test]
    fn stale_provider_result_is_rejected_after_policy_generation_change() {
        let now = Instant::now();
        let mut provider = provider(PeerDirection::Inbound, true);
        let query = dns_query(41, &["alpha"], 1);
        let payload = GetDnsRelay::new(41, query.clone())
            .expect("request")
            .encode()
            .expect("encode");
        let request = provider_request(
            provider
                .receive_request(&payload, now)
                .expect("provider request"),
        );
        let request_id = request.request_id;
        let (work, _) = request.into_parts();
        let revoked = provider
            .replace_policy(
                DnsRelayRequesterPolicy::Disabled,
                Hip76ProviderPolicy::opted_in(true),
                2,
            )
            .expect("generation advances");
        assert_eq!(revoked.provider_request_ids, vec![request_id]);
        assert_eq!(
            provider.prepare_provider_response(
                &work,
                DnsRelayStatus::Ok,
                dns_response(&query),
                now,
            ),
            Err(Hip76Error {
                reason: Hip76FailureReason::StaleGeneration
            })
        );
    }

    #[test]
    fn stale_provider_work_cannot_complete_reused_request_id() {
        let now = Instant::now();
        let mut provider_config = config(
            DnsRelayRequesterPolicy::Disabled,
            Hip76ProviderPolicy::opted_in(true),
        );
        provider_config.maximum_live_requests = 1;
        let mut provider = Hip76Session::new(
            PeerDirection::Inbound,
            PROVIDER_SERVICES,
            DENUO_SERVICES,
            true,
            provider_config,
        )
        .expect("provider");

        let first_query = dns_query(41, &["first"], 1);
        let first_envelope = GetDnsRelay::new(41, first_query.clone())
            .expect("request")
            .encode()
            .expect("encode");
        let first = provider_request(
            provider
                .receive_request(&first_envelope, now)
                .expect("first request"),
        );
        let (stale_work, _) = first.into_parts();
        let second_time = now + Duration::from_secs(1);
        assert_eq!(provider.expire(second_time).provider_request_ids, vec![41]);

        let eviction_envelope = GetDnsRelay::new(42, dns_query(42, &["evict"], 1))
            .expect("request")
            .encode()
            .expect("encode");
        let _ = provider_request(
            provider
                .receive_request(&eviction_envelope, second_time)
                .expect("eviction request"),
        );
        let third_time = second_time + Duration::from_secs(1);
        assert_eq!(provider.expire(third_time).provider_request_ids, vec![42]);

        let replacement_query = dns_query(43, &["replacement"], 1);
        let replacement_envelope = GetDnsRelay::new(41, replacement_query.clone())
            .expect("request")
            .encode()
            .expect("encode");
        let replacement = provider_request(
            provider
                .receive_request(&replacement_envelope, third_time)
                .expect("request ID may be reused after bounded tombstone eviction"),
        );
        let replacement_token = replacement.work_token;
        assert_ne!(stale_work.work_token, replacement_token);
        assert_eq!(
            provider.prepare_provider_response(
                &stale_work,
                DnsRelayStatus::Ok,
                dns_response(&first_query),
                third_time,
            ),
            Err(Hip76Error {
                reason: Hip76FailureReason::StaleGeneration
            })
        );
        assert_eq!(provider.diagnostics().inbound_live_requests, 1);
        assert_eq!(
            provider
                .inbound
                .live(41)
                .expect("replacement live")
                .work_token,
            replacement_token
        );
    }

    #[test]
    fn negotiated_limits_are_atomic_and_clamped_to_local_configuration() {
        let mut configured = config(
            DnsRelayRequesterPolicy::Auto,
            Hip76ProviderPolicy::disabled(),
        );
        configured.maximum_live_requests = 8;
        configured.maximum_send_size = 100;
        let mut session = Hip76Session::new(
            PeerDirection::Outbound,
            DENUO_SERVICES,
            PROVIDER_SERVICES,
            true,
            configured,
        )
        .expect("session");
        session
            .set_negotiated_resource_limits(80, 4)
            .expect("first agreement");
        assert_eq!(session.diagnostics().maximum_send_size, 80);
        assert_eq!(session.diagnostics().maximum_live_requests, 4);

        assert_eq!(
            session.set_negotiated_resource_limits(50, 0),
            Err(Hip76Error {
                reason: Hip76FailureReason::CapacityExceeded
            })
        );
        assert_eq!(session.diagnostics().maximum_send_size, 80);
        assert_eq!(session.diagnostics().maximum_live_requests, 4);

        session
            .set_negotiated_resource_limits(200, 20)
            .expect("renegotiated agreement");
        assert_eq!(session.diagnostics().maximum_send_size, 100);
        assert_eq!(session.diagnostics().maximum_live_requests, 8);
    }

    #[test]
    fn malformed_packet_faults_only_hip76_and_policy_cannot_reset_it() {
        let now = Instant::now();
        let mut provider = provider(PeerDirection::Inbound, true);
        assert_eq!(
            provider.receive_request(&[0xff], now),
            Err(Hip76Error {
                reason: Hip76FailureReason::MalformedRequest
            })
        );
        let valid = GetDnsRelay::new(9, dns_query(9, &["alpha"], 1))
            .expect("request")
            .encode()
            .expect("encode");
        provider
            .replace_policy(
                DnsRelayRequesterPolicy::Disabled,
                Hip76ProviderPolicy::opted_in(true),
                2,
            )
            .expect("policy generation can advance");
        assert_eq!(
            provider.receive_request(&valid, now),
            Err(Hip76Error {
                reason: Hip76FailureReason::PeerFaulted
            })
        );
        assert_eq!(provider.diagnostics().phase, Hip76ConnectionPhase::Faulted);
        assert!(provider.diagnostics().peer_faulted);
        assert!(provider.ordinary_peer_remains_available());
    }

    #[test]
    fn outer_frame_fault_is_irreversible_for_the_connection() {
        let mut session = provider(PeerDirection::Inbound, true);
        let revoked = session.fault_protocol(Hip76FailureReason::RequestTooLarge);
        assert!(revoked.is_empty());
        session
            .replace_policy(
                DnsRelayRequesterPolicy::Disabled,
                Hip76ProviderPolicy::opted_in(true),
                2,
            )
            .expect("policy generation can advance");
        assert_eq!(session.diagnostics().phase, Hip76ConnectionPhase::Faulted);
        assert!(session.diagnostics().peer_faulted);
        assert!(session.ordinary_peer_remains_available());
    }

    #[test]
    fn structured_diagnostics_never_retain_dns_names_or_wire_messages() {
        let now = Instant::now();
        let mut provider = provider(PeerDirection::Inbound, true);
        let secret = dns_query(77, &["private-qname", "secret"], 52);
        let request = GetDnsRelay::new(77, secret.clone())
            .expect("request")
            .encode()
            .expect("encode");
        let event = provider_request(
            provider
                .receive_request(&request, now)
                .expect("provider event"),
        );
        assert_eq!(event.query(), secret);
        assert!(!format!("{event:?}").contains("private-qname"));

        let diagnostics =
            serde_json::to_string(&provider.diagnostics()).expect("serialize diagnostics");
        assert!(!diagnostics.contains("private-qname"));
        assert!(!diagnostics.contains("\"query\":"));
        assert!(!diagnostics.contains("\"response\":"));
        assert!(!diagnostics.contains("\"request_id\":"));
        assert!(diagnostics.contains("\"inbound_live_requests\":1"));

        let identity = Hip76ProtocolIdentity::default();
        assert_eq!(identity.semantic_version, 1);
        assert_eq!(identity.service_bit, DNS_RELAY_SERVICE.value());
        assert_eq!(identity.request_packet_type, 0xf0);
        assert_eq!(identity.response_packet_type, 0xf1);
        assert_eq!(
            identity.maximum_request_payload_size,
            u32::try_from(MAX_DNS_RELAY_REQUEST_PAYLOAD_SIZE).expect("request cap")
        );
        assert_eq!(
            identity.maximum_response_payload_size,
            u32::try_from(MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE).expect("response cap")
        );

        let mut summary = Hip76Summary::default();
        summary.observe(&provider.diagnostics());
        let summary = serde_json::to_string(&summary).expect("serialize summary");
        assert!(!summary.contains("private-qname"));
        assert!(!summary.contains("\"request_id\":"));
        assert!(summary.contains("\"semantic_version\":1"));
        assert!(summary.contains("\"provider_opted_in_peers\":1"));
    }

    #[test]
    fn registry_loss_revokes_only_hip76_work() {
        let now = Instant::now();
        let mut requester = requester(PeerDirection::Outbound);
        let request = requester
            .begin_request(dns_query(1, &["alpha"], 1), now)
            .expect("request");
        let revoked = requester.set_registry_negotiated(false);
        assert_eq!(revoked.requester_request_ids, vec![request.request_id]);
        assert_eq!(
            requester.begin_request(dns_query(2, &["alpha"], 1), now),
            Err(Hip76Error {
                reason: Hip76FailureReason::RegistryNotNegotiated
            })
        );
        assert_eq!(
            requester.diagnostics().phase,
            Hip76ConnectionPhase::AwaitingRegistry
        );
        assert!(requester.ordinary_peer_remains_available());
    }
}
