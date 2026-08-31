//! Runtime coordination and bounded diagnostics for Shakescape Experimental V1.
//!
//! The coordinator is deliberately isolated from the ordinary Handshake peer
//! state machine. An experimental negotiation failure disables Shakescape for that
//! peer; it never becomes a peer error, score increase, ban, or disconnect.

use std::{
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};

use hns_consensus::Network as ConsensusNetwork;
use hns_dns_relay_protocol::MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE;
use hns_marketplace_protocol::{
    NameMarketHello, NameMarketMessage, ShakescapeRegistryVersion, MAX_SHAKESCAPE_MARKET_PAYLOAD,
};
use hns_p2p_experimental::{
    EnvelopeError, ExperimentalWireProfile, KnownMessage, NegotiatedRegistry, NegotiationError,
    Network, ProtocolDisposition, ProtocolRange, RegistryEnvelopeError, RegistryHello,
    ShakescapeExtensionEnvelope, ATOMIC_MARKET_PROTOCOL_ID, ATOMIC_MARKET_PROTOCOL_VERSION,
    EXPERIMENTAL_STATUS_LABEL, REGISTRY_NEGOTIATION_MAX_PAYLOAD,
    SHAKESCAPE_EXTENSION_MAX_NESTED_PAYLOAD, SHAKESCAPE_EXTENSION_MAX_PACKET_PAYLOAD,
    SHAKESCAPE_EXTENSION_PACKET, SHAKESCAPE_EXTENSION_SERVICE, SHAKESCAPE_V1_REGISTRY_FINGERPRINT,
    SHAKESCAPE_V1_REGISTRY_ID, SHAKESCAPE_V1_REGISTRY_NAME,
    SHAKESCAPE_V1_REGISTRY_PROTOCOL_VERSION, SHAKESCAPE_V1_REGISTRY_VERSION,
    SHAKESCAPE_V1_WIRE_PROFILE,
};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

use crate::{
    handshake::PeerDirection,
    wire::{Packet, PacketType},
};

pub const SHAKESCAPE_DEFAULT_MAXIMUM_LIVE_REQUESTS: u16 = 64;

#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum ShakescapePeerPhase {
    #[default]
    AwaitingVersion,
    NotAdvertised,
    LocalDisabled,
    Eligible,
    HelloAdmitted,
    Negotiated,
    Disabled,
}

impl ShakescapePeerPhase {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AwaitingVersion => "awaiting-version",
            Self::NotAdvertised => "not-advertised",
            Self::LocalDisabled => "local-disabled",
            Self::Eligible => "eligible",
            Self::HelloAdmitted => "hello-admitted",
            Self::Negotiated => "negotiated",
            Self::Disabled => "disabled",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShakescapeDisableReason {
    LocalServiceDisabled,
    PeerMissingService,
    PacketTooLarge,
    PayloadTooLarge,
    MalformedEnvelope,
    MalformedHello,
    UnexpectedMessage,
    CorrelationMismatch,
    DuplicateOrReplay,
    WrongFingerprint,
    WrongNetwork,
    WrongGenesis,
    IncompatibleVersion,
    InvalidResourceLimit,
    UnsupportedProtocol,
    NegotiationTimeout,
    LocalEncodingFailure,
    LocalSendUnavailable,
}

impl ShakescapeDisableReason {
    pub const ALL: [Self; 18] = [
        Self::LocalServiceDisabled,
        Self::PeerMissingService,
        Self::PacketTooLarge,
        Self::PayloadTooLarge,
        Self::MalformedEnvelope,
        Self::MalformedHello,
        Self::UnexpectedMessage,
        Self::CorrelationMismatch,
        Self::DuplicateOrReplay,
        Self::WrongFingerprint,
        Self::WrongNetwork,
        Self::WrongGenesis,
        Self::IncompatibleVersion,
        Self::InvalidResourceLimit,
        Self::UnsupportedProtocol,
        Self::NegotiationTimeout,
        Self::LocalEncodingFailure,
        Self::LocalSendUnavailable,
    ];

    pub const fn index(self) -> usize {
        match self {
            Self::LocalServiceDisabled => 0,
            Self::PeerMissingService => 1,
            Self::PacketTooLarge => 2,
            Self::PayloadTooLarge => 3,
            Self::MalformedEnvelope => 4,
            Self::MalformedHello => 5,
            Self::UnexpectedMessage => 6,
            Self::CorrelationMismatch => 7,
            Self::DuplicateOrReplay => 8,
            Self::WrongFingerprint => 9,
            Self::WrongNetwork => 10,
            Self::WrongGenesis => 11,
            Self::IncompatibleVersion => 12,
            Self::InvalidResourceLimit => 13,
            Self::UnsupportedProtocol => 14,
            Self::NegotiationTimeout => 15,
            Self::LocalEncodingFailure => 16,
            Self::LocalSendUnavailable => 17,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalServiceDisabled => "local-service-disabled",
            Self::PeerMissingService => "peer-missing-service",
            Self::PacketTooLarge => "packet-too-large",
            Self::PayloadTooLarge => "payload-too-large",
            Self::MalformedEnvelope => "malformed-envelope",
            Self::MalformedHello => "malformed-hello",
            Self::UnexpectedMessage => "unexpected-message",
            Self::CorrelationMismatch => "correlation-mismatch",
            Self::DuplicateOrReplay => "duplicate-or-replay",
            Self::WrongFingerprint => "wrong-fingerprint",
            Self::WrongNetwork => "wrong-network",
            Self::WrongGenesis => "wrong-genesis",
            Self::IncompatibleVersion => "incompatible-version",
            Self::InvalidResourceLimit => "invalid-resource-limit",
            Self::UnsupportedProtocol => "unsupported-protocol",
            Self::NegotiationTimeout => "negotiation-timeout",
            Self::LocalEncodingFailure => "local-encoding-failure",
            Self::LocalSendUnavailable => "local-send-unavailable",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ShakescapeNegotiatedProtocol {
    pub protocol_id: u16,
    pub protocol_version: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ShakescapeNegotiatedParameters {
    pub registry_version: u16,
    pub protocols: Vec<ShakescapeNegotiatedProtocol>,
    pub maximum_send_size: u32,
    pub maximum_live_requests: u16,
    pub feature_flags: u64,
}

impl From<&NegotiatedRegistry> for ShakescapeNegotiatedParameters {
    fn from(negotiated: &NegotiatedRegistry) -> Self {
        Self {
            registry_version: negotiated.registry_version,
            protocols: negotiated
                .protocols
                .iter()
                .map(
                    |(protocol_id, protocol_version)| ShakescapeNegotiatedProtocol {
                        protocol_id: *protocol_id,
                        protocol_version: *protocol_version,
                    },
                )
                .collect(),
            maximum_send_size: negotiated.maximum_send_size,
            maximum_live_requests: negotiated.maximum_live_requests,
            feature_flags: negotiated.feature_flags,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ShakescapePeerDiagnostics {
    pub phase: ShakescapePeerPhase,
    pub disable_reason: Option<ShakescapeDisableReason>,
    pub request_id: Option<u64>,
    pub negotiated: Option<ShakescapeNegotiatedParameters>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ShakescapeRegistryIdentity {
    pub name: String,
    pub registry_id: String,
    pub fingerprint: String,
    pub registry_version: u16,
    pub registry_protocol_version: u16,
    pub wire_profile: String,
    pub status: String,
    pub service_bit: u64,
    pub packet_type: u8,
    pub maximum_packet_payload: u32,
    pub maximum_nested_payload: u32,
    pub maximum_registry_negotiation_payload: u32,
}

impl Default for ShakescapeRegistryIdentity {
    fn default() -> Self {
        Self {
            name: SHAKESCAPE_V1_REGISTRY_NAME.to_owned(),
            registry_id: SHAKESCAPE_V1_REGISTRY_ID.to_string(),
            fingerprint: SHAKESCAPE_V1_REGISTRY_FINGERPRINT.to_string(),
            registry_version: SHAKESCAPE_V1_REGISTRY_VERSION,
            registry_protocol_version: SHAKESCAPE_V1_REGISTRY_PROTOCOL_VERSION,
            wire_profile: SHAKESCAPE_V1_WIRE_PROFILE.to_owned(),
            status: EXPERIMENTAL_STATUS_LABEL.to_owned(),
            service_bit: SHAKESCAPE_EXTENSION_SERVICE.value(),
            packet_type: SHAKESCAPE_EXTENSION_PACKET.value(),
            maximum_packet_payload: SHAKESCAPE_EXTENSION_MAX_PACKET_PAYLOAD as u32,
            maximum_nested_payload: SHAKESCAPE_EXTENSION_MAX_NESTED_PAYLOAD as u32,
            maximum_registry_negotiation_payload: REGISTRY_NEGOTIATION_MAX_PAYLOAD as u32,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ShakescapeLiveCounts {
    pub awaiting_version: u64,
    pub not_advertised: u64,
    pub local_disabled: u64,
    pub eligible: u64,
    pub pending: u64,
    pub negotiated: u64,
    pub disabled: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ShakescapeProcessTotals {
    pub hello_admitted: u64,
    pub hello_received: u64,
    pub hello_ack_admitted: u64,
    pub hello_ack_received: u64,
    pub agreements_computed: u64,
    pub rejected: u64,
    pub disabled: u64,
}

impl ShakescapeProcessTotals {
    pub const fn admitted(&self) -> u64 {
        self.hello_admitted.saturating_add(self.hello_ack_admitted)
    }

    pub const fn received(&self) -> u64 {
        self.hello_received.saturating_add(self.hello_ack_received)
    }

    pub const fn rejected(&self) -> u64 {
        self.rejected
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ShakescapeReasonCount {
    pub reason: ShakescapeDisableReason,
    pub count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ShakescapeSummary {
    pub identity: ShakescapeRegistryIdentity,
    pub local_service_mask: u64,
    pub advertised: bool,
    pub live: ShakescapeLiveCounts,
    pub process: ShakescapeProcessTotals,
    pub rejection_reasons: Vec<ShakescapeReasonCount>,
}

impl Default for ShakescapeSummary {
    fn default() -> Self {
        Self {
            identity: ShakescapeRegistryIdentity::default(),
            local_service_mask: 0,
            advertised: false,
            live: ShakescapeLiveCounts::default(),
            process: ShakescapeProcessTotals::default(),
            rejection_reasons: ShakescapeDisableReason::ALL
                .into_iter()
                .map(|reason| ShakescapeReasonCount { reason, count: 0 })
                .collect(),
        }
    }
}

impl ShakescapeSummary {
    pub const fn advertised(&self) -> bool {
        self.advertised
    }
}

#[derive(Debug, Default)]
struct ShakescapeRuntimeMetricsInner {
    hello_admitted: AtomicU64,
    hello_received: AtomicU64,
    hello_ack_admitted: AtomicU64,
    hello_ack_received: AtomicU64,
    agreements_computed: AtomicU64,
    rejected: AtomicU64,
    disabled: AtomicU64,
    rejection_reasons: [AtomicU64; ShakescapeDisableReason::ALL.len()],
}

#[derive(Clone, Debug, Default)]
pub(crate) struct ShakescapeRuntimeMetrics {
    inner: Arc<ShakescapeRuntimeMetricsInner>,
}

impl ShakescapeRuntimeMetrics {
    fn record_hello_admitted(&self) {
        saturating_increment(&self.inner.hello_admitted);
    }

    fn record_hello_received(&self) {
        saturating_increment(&self.inner.hello_received);
    }

    fn record_hello_ack_admitted(&self) {
        saturating_increment(&self.inner.hello_ack_admitted);
    }

    fn record_hello_ack_received(&self) {
        saturating_increment(&self.inner.hello_ack_received);
    }

    fn record_agreement_computed(&self) {
        saturating_increment(&self.inner.agreements_computed);
    }

    fn record_disabled(&self, reason: ShakescapeDisableReason) {
        saturating_increment(&self.inner.disabled);
        self.record_rejected(reason);
    }

    fn record_rejected(&self, reason: ShakescapeDisableReason) {
        saturating_increment(&self.inner.rejected);
        saturating_increment(&self.inner.rejection_reasons[reason.index()]);
    }

    pub(crate) fn summary(
        &self,
        local_service_mask: u64,
        peers: &[ShakescapePeerDiagnostics],
    ) -> ShakescapeSummary {
        let mut live = ShakescapeLiveCounts::default();
        for peer in peers {
            let target = match peer.phase {
                ShakescapePeerPhase::AwaitingVersion => &mut live.awaiting_version,
                ShakescapePeerPhase::NotAdvertised => &mut live.not_advertised,
                ShakescapePeerPhase::LocalDisabled => &mut live.local_disabled,
                ShakescapePeerPhase::Eligible => &mut live.eligible,
                ShakescapePeerPhase::HelloAdmitted => &mut live.pending,
                ShakescapePeerPhase::Negotiated => &mut live.negotiated,
                ShakescapePeerPhase::Disabled => &mut live.disabled,
            };
            *target = target.saturating_add(1);
        }

        ShakescapeSummary {
            identity: ShakescapeRegistryIdentity::default(),
            local_service_mask,
            advertised: local_service_mask & SHAKESCAPE_EXTENSION_SERVICE.value() != 0,
            live,
            process: ShakescapeProcessTotals {
                hello_admitted: self.inner.hello_admitted.load(Ordering::Acquire),
                hello_received: self.inner.hello_received.load(Ordering::Acquire),
                hello_ack_admitted: self.inner.hello_ack_admitted.load(Ordering::Acquire),
                hello_ack_received: self.inner.hello_ack_received.load(Ordering::Acquire),
                agreements_computed: self.inner.agreements_computed.load(Ordering::Acquire),
                rejected: self.inner.rejected.load(Ordering::Acquire),
                disabled: self.inner.disabled.load(Ordering::Acquire),
            },
            rejection_reasons: ShakescapeDisableReason::ALL
                .into_iter()
                .map(|reason| ShakescapeReasonCount {
                    reason,
                    count: self.inner.rejection_reasons[reason.index()].load(Ordering::Acquire),
                })
                .collect(),
        }
    }
}

fn saturating_increment(counter: &AtomicU64) {
    let _ = counter.fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
        Some(value.saturating_add(1))
    });
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ShakescapeOutboundMessage {
    Hello,
    HelloAck,
    NameMarket,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct ShakescapeAction {
    pub response_payload: Option<Vec<u8>>,
    pub outbound_message: Option<ShakescapeOutboundMessage>,
    pub name_market: Option<ShakescapeNameMarketInbound>,
}

/// One canonical name-market message admitted under the exact V2 registry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ShakescapeNameMarketInbound {
    pub request_id: u64,
    pub message: NameMarketMessage,
}

#[derive(Debug)]
pub(crate) struct ShakescapeCoordinator {
    direction: PeerDirection,
    local_enabled: bool,
    local_hello: RegistryHello,
    name_market_hello: NameMarketHello,
    proposed_request_id: u64,
    negotiation_timeout: Duration,
    ready: bool,
    remote_advertises: Option<bool>,
    pending_deadline: Option<Instant>,
    negotiated: Option<NegotiatedRegistry>,
    diagnostics: ShakescapePeerDiagnostics,
    metrics: ShakescapeRuntimeMetrics,
}

impl ShakescapeCoordinator {
    pub(crate) fn new(
        direction: PeerDirection,
        network: ConsensusNetwork,
        local_services: u64,
        proposed_request_id: u64,
        negotiation_timeout: Duration,
        metrics: ShakescapeRuntimeMetrics,
    ) -> Result<Self, NegotiationError> {
        let experimental_network = match network {
            ConsensusNetwork::Mainnet => Network::Mainnet,
            ConsensusNetwork::Testnet => Network::Testnet,
            ConsensusNetwork::Regtest => Network::Regtest,
            ConsensusNetwork::Simnet => Network::Simnet,
        };
        let local_hello = RegistryHello::shakescape_v1(
            experimental_network,
            network.params().genesis_hash.into_inner(),
            vec![ProtocolRange {
                protocol_id: ATOMIC_MARKET_PROTOCOL_ID,
                minimum_version: ATOMIC_MARKET_PROTOCOL_VERSION,
                maximum_version: ATOMIC_MARKET_PROTOCOL_VERSION,
            }],
            u32::try_from(
                SHAKESCAPE_EXTENSION_MAX_PACKET_PAYLOAD.max(MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE),
            )
            .expect("canonical Shakescape packet ceilings fit u32"),
            SHAKESCAPE_DEFAULT_MAXIMUM_LIVE_REQUESTS,
            0,
        )?;
        let name_market_hello = NameMarketHello {
            hns_magic: network.params().packet_magic,
            hns_genesis: network.params().genesis_hash.into_inner().into(),
            maximum_payload: u32::try_from(MAX_SHAKESCAPE_MARKET_PAYLOAD)
                .expect("canonical Shakescape marketplace payload ceiling fits u32"),
            feature_flags: 0,
        };
        let diagnostics = ShakescapePeerDiagnostics {
            phase: if local_services & SHAKESCAPE_EXTENSION_SERVICE.value() != 0 {
                ShakescapePeerPhase::AwaitingVersion
            } else {
                ShakescapePeerPhase::LocalDisabled
            },
            ..ShakescapePeerDiagnostics::default()
        };
        Ok(Self {
            direction,
            local_enabled: local_services & SHAKESCAPE_EXTENSION_SERVICE.value() != 0,
            local_hello,
            name_market_hello,
            proposed_request_id: proposed_request_id.max(1),
            negotiation_timeout,
            ready: false,
            remote_advertises: None,
            pending_deadline: None,
            negotiated: None,
            diagnostics,
            metrics,
        })
    }

    pub(crate) fn diagnostics(&self) -> ShakescapePeerDiagnostics {
        self.diagnostics.clone()
    }

    pub(crate) fn negotiated_evidence(
        &self,
    ) -> Option<(ExperimentalWireProfile, &NegotiatedRegistry)> {
        self.negotiated
            .as_ref()
            .map(|negotiated| (ExperimentalWireProfile::ShakescapeV1, negotiated))
    }

    pub(crate) fn observe_remote_services(&mut self, services: u64) {
        let advertised = services & SHAKESCAPE_EXTENSION_SERVICE.value() != 0;
        self.remote_advertises = Some(advertised);
        if self.diagnostics.phase == ShakescapePeerPhase::AwaitingVersion && self.local_enabled {
            self.diagnostics.phase = if advertised {
                ShakescapePeerPhase::Eligible
            } else {
                ShakescapePeerPhase::NotAdvertised
            };
        }
    }

    pub(crate) fn on_ready(&mut self, _now: Instant) -> ShakescapeAction {
        self.ready = true;
        if self.direction != PeerDirection::Outbound
            || self.diagnostics.phase != ShakescapePeerPhase::Eligible
        {
            return ShakescapeAction::default();
        }

        let request_id = self.proposed_request_id;
        let response_payload = match encode_hello(request_id, &self.local_hello, false) {
            Ok(payload) => payload,
            Err(()) => {
                self.disable(ShakescapeDisableReason::LocalEncodingFailure);
                return ShakescapeAction::default();
            }
        };
        ShakescapeAction {
            response_payload: Some(response_payload),
            outbound_message: Some(ShakescapeOutboundMessage::Hello),
            name_market: None,
        }
    }

    pub(crate) fn pending_deadline(&self) -> Option<Instant> {
        self.pending_deadline
    }

    pub(crate) fn expire(&mut self, now: Instant) -> bool {
        if self.diagnostics.phase == ShakescapePeerPhase::HelloAdmitted
            && self
                .pending_deadline
                .is_some_and(|deadline| now >= deadline)
        {
            self.disable(ShakescapeDisableReason::NegotiationTimeout);
            return true;
        }
        false
    }

    pub(crate) fn receive_extension(&mut self, payload: &[u8]) -> ShakescapeAction {
        if payload.len() > SHAKESCAPE_EXTENSION_MAX_PACKET_PAYLOAD {
            if self.diagnostics.phase == ShakescapePeerPhase::Disabled {
                self.metrics
                    .record_rejected(ShakescapeDisableReason::PacketTooLarge);
            } else {
                self.disable(ShakescapeDisableReason::PacketTooLarge);
            }
            return ShakescapeAction::default();
        }
        if self.diagnostics.phase == ShakescapePeerPhase::Disabled {
            return ShakescapeAction::default();
        }
        if !self.local_enabled {
            self.metrics
                .record_rejected(ShakescapeDisableReason::LocalServiceDisabled);
            return ShakescapeAction::default();
        }
        match self.remote_advertises {
            Some(true) => {}
            Some(false) => {
                self.disable(ShakescapeDisableReason::PeerMissingService);
                return ShakescapeAction::default();
            }
            None => {
                self.disable(ShakescapeDisableReason::UnexpectedMessage);
                return ShakescapeAction::default();
            }
        }
        if !self.ready {
            self.disable(ShakescapeDisableReason::UnexpectedMessage);
            return ShakescapeAction::default();
        }
        let envelope = match ShakescapeExtensionEnvelope::decode_canonical(payload) {
            Ok(envelope) => envelope,
            Err(error) => {
                self.disable(map_envelope_error(&error));
                return ShakescapeAction::default();
            }
        };
        let disposition = match envelope.classify() {
            Ok(disposition) => disposition,
            Err(error) => {
                self.disable(map_envelope_error(&error));
                return ShakescapeAction::default();
            }
        };
        match disposition {
            ProtocolDisposition::Known(KnownMessage::RegistryHello) => self.receive_hello(payload),
            ProtocolDisposition::Known(KnownMessage::RegistryHelloAck) => {
                self.receive_hello_ack(payload)
            }
            ProtocolDisposition::Known(KnownMessage::RegistryReject) => {
                self.disable(ShakescapeDisableReason::UnexpectedMessage);
                ShakescapeAction::default()
            }
            ProtocolDisposition::Known(message) if is_name_market_message(message) => {
                self.receive_name_market(payload)
            }
            ProtocolDisposition::Known(_) => {
                self.reject_subprotocol(ShakescapeDisableReason::UnsupportedProtocol);
                ShakescapeAction::default()
            }
            ProtocolDisposition::UnknownProtocol { .. } => {
                // Subprotocol support is isolated from registry negotiation.
                // Once the canonical registry is installed, a bounded packet
                // for an unknown protocol is ignored without destroying that
                // successful peer-level agreement.
                self.reject_subprotocol(ShakescapeDisableReason::UnsupportedProtocol);
                ShakescapeAction::default()
            }
        }
    }

    fn receive_name_market(&mut self, payload: &[u8]) -> ShakescapeAction {
        let Some(negotiated) = self.negotiated.as_ref() else {
            self.disable(ShakescapeDisableReason::UnexpectedMessage);
            return ShakescapeAction::default();
        };
        if self.diagnostics.phase != ShakescapePeerPhase::Negotiated
            || negotiated.registry_version != SHAKESCAPE_V1_REGISTRY_VERSION
            || negotiated.fingerprint != SHAKESCAPE_V1_REGISTRY_FINGERPRINT
            || !negotiated
                .protocols
                .contains(&(ATOMIC_MARKET_PROTOCOL_ID, ATOMIC_MARKET_PROTOCOL_VERSION))
            || payload.len() > usize::try_from(self.local_hello.maximum_receive_size).unwrap_or(0)
        {
            self.reject_subprotocol(ShakescapeDisableReason::UnsupportedProtocol);
            return ShakescapeAction::default();
        }
        let (registry, request_id, message) = match NameMarketMessage::decode_envelope(payload) {
            Ok(decoded) => decoded,
            Err(_) => {
                self.reject_subprotocol(ShakescapeDisableReason::MalformedEnvelope);
                return ShakescapeAction::default();
            }
        };
        if registry != ShakescapeRegistryVersion::V1 {
            self.reject_subprotocol(ShakescapeDisableReason::IncompatibleVersion);
            return ShakescapeAction::default();
        }
        ShakescapeAction {
            name_market: Some(ShakescapeNameMarketInbound {
                request_id,
                message,
            }),
            ..ShakescapeAction::default()
        }
    }

    fn receive_hello(&mut self, payload: &[u8]) -> ShakescapeAction {
        if self.direction != PeerDirection::Inbound {
            self.disable(
                if self.diagnostics.phase == ShakescapePeerPhase::Negotiated {
                    ShakescapeDisableReason::DuplicateOrReplay
                } else {
                    ShakescapeDisableReason::UnexpectedMessage
                },
            );
            return ShakescapeAction::default();
        }
        if self.diagnostics.phase != ShakescapePeerPhase::Eligible {
            self.disable(
                if self.diagnostics.request_id.is_some()
                    || self.diagnostics.phase == ShakescapePeerPhase::Negotiated
                {
                    ShakescapeDisableReason::DuplicateOrReplay
                } else {
                    ShakescapeDisableReason::UnexpectedMessage
                },
            );
            return ShakescapeAction::default();
        }

        let (request_id, remote_hello) =
            match ShakescapeExtensionEnvelope::decode_registry_hello(payload) {
                Ok(message) => message,
                Err(error) => {
                    self.disable(map_registry_error(&error));
                    return ShakescapeAction::default();
                }
            };
        self.metrics.record_hello_received();
        self.diagnostics.request_id = Some(request_id);

        // A structurally valid HELLO always receives our canonical identity,
        // even when semantic negotiation will fail. This lets both sides
        // converge on the same mismatch diagnosis without a disconnect.
        let response_payload = match encode_hello(request_id, &self.local_hello, true) {
            Ok(payload) => payload,
            Err(()) => {
                self.disable(ShakescapeDisableReason::LocalEncodingFailure);
                return ShakescapeAction::default();
            }
        };
        match NegotiatedRegistry::negotiate(&self.local_hello, &remote_hello) {
            Ok(negotiated) => self.install(negotiated),
            Err(error) => self.disable(map_negotiation_error(&error)),
        }
        ShakescapeAction {
            response_payload: Some(response_payload),
            outbound_message: Some(ShakescapeOutboundMessage::HelloAck),
            name_market: None,
        }
    }

    fn receive_hello_ack(&mut self, payload: &[u8]) -> ShakescapeAction {
        if self.direction != PeerDirection::Outbound {
            self.disable(ShakescapeDisableReason::UnexpectedMessage);
            return ShakescapeAction::default();
        }
        if self.diagnostics.phase != ShakescapePeerPhase::HelloAdmitted {
            self.disable(
                if self.diagnostics.request_id.is_some()
                    || self.diagnostics.phase == ShakescapePeerPhase::Negotiated
                {
                    ShakescapeDisableReason::DuplicateOrReplay
                } else {
                    ShakescapeDisableReason::UnexpectedMessage
                },
            );
            return ShakescapeAction::default();
        }

        let (request_id, remote_hello) =
            match ShakescapeExtensionEnvelope::decode_registry_hello_ack(payload) {
                Ok(message) => message,
                Err(error) => {
                    self.disable(map_registry_error(&error));
                    return ShakescapeAction::default();
                }
            };
        self.metrics.record_hello_ack_received();
        if self.diagnostics.request_id != Some(request_id) {
            self.disable(ShakescapeDisableReason::CorrelationMismatch);
            return ShakescapeAction::default();
        }
        match NegotiatedRegistry::negotiate(&self.local_hello, &remote_hello) {
            Ok(negotiated) => {
                self.install(negotiated);
                let request_id = self.proposed_request_id.checked_add(1).unwrap_or(1);
                match NameMarketMessage::Hello(self.name_market_hello)
                    .encode_envelope(ShakescapeRegistryVersion::V1, request_id)
                {
                    Ok(payload) => ShakescapeAction {
                        response_payload: Some(payload),
                        outbound_message: Some(ShakescapeOutboundMessage::NameMarket),
                        name_market: None,
                    },
                    Err(_) => {
                        self.disable(ShakescapeDisableReason::LocalEncodingFailure);
                        ShakescapeAction::default()
                    }
                }
            }
            Err(error) => {
                self.disable(map_negotiation_error(&error));
                ShakescapeAction::default()
            }
        }
    }

    fn install(&mut self, negotiated: NegotiatedRegistry) {
        self.pending_deadline = None;
        self.diagnostics.phase = ShakescapePeerPhase::Negotiated;
        self.diagnostics.disable_reason = None;
        self.diagnostics.negotiated = Some(ShakescapeNegotiatedParameters::from(&negotiated));
        self.negotiated = Some(negotiated);
        self.metrics.record_agreement_computed();
    }

    fn disable(&mut self, reason: ShakescapeDisableReason) {
        if self.diagnostics.phase == ShakescapePeerPhase::Disabled {
            return;
        }
        self.pending_deadline = None;
        self.negotiated = None;
        self.diagnostics.phase = ShakescapePeerPhase::Disabled;
        self.diagnostics.disable_reason = Some(reason);
        self.diagnostics.negotiated = None;
        self.metrics.record_disabled(reason);
    }

    fn reject_subprotocol(&mut self, reason: ShakescapeDisableReason) {
        if self.diagnostics.phase == ShakescapePeerPhase::Negotiated {
            self.metrics.record_rejected(reason);
        } else {
            self.disable(reason);
        }
    }

    pub(crate) fn outbound_admitted(&mut self, message: ShakescapeOutboundMessage, now: Instant) {
        match message {
            ShakescapeOutboundMessage::Hello => {
                self.diagnostics.phase = ShakescapePeerPhase::HelloAdmitted;
                self.diagnostics.request_id = Some(self.proposed_request_id);
                self.pending_deadline = Some(now + self.negotiation_timeout);
                self.metrics.record_hello_admitted();
            }
            ShakescapeOutboundMessage::HelloAck => self.metrics.record_hello_ack_admitted(),
            ShakescapeOutboundMessage::NameMarket => {}
        }
    }

    pub(crate) fn outbound_rejected(&mut self) {
        if self.diagnostics.phase == ShakescapePeerPhase::Disabled {
            self.metrics
                .record_rejected(ShakescapeDisableReason::LocalSendUnavailable);
        } else {
            self.disable(ShakescapeDisableReason::LocalSendUnavailable);
        }
    }
}

fn is_name_market_message(message: KnownMessage) -> bool {
    matches!(
        message,
        KnownMessage::MarketHello
            | KnownMessage::GetOfferInventory
            | KnownMessage::OfferInventory
            | KnownMessage::GetOffers
            | KnownMessage::Offers
            | KnownMessage::GetOffer
            | KnownMessage::Offer
            | KnownMessage::OfferTombstone
    )
}

fn encode_hello(request_id: u64, hello: &RegistryHello, ack: bool) -> Result<Vec<u8>, ()> {
    let envelope = if ack {
        ShakescapeExtensionEnvelope::registry_hello_ack(request_id, hello)
    } else {
        ShakescapeExtensionEnvelope::registry_hello(request_id, hello)
    }
    .map_err(|_| ())?;
    envelope.encode_canonical().map_err(|_| ())
}

fn map_registry_error(error: &RegistryEnvelopeError) -> ShakescapeDisableReason {
    match error {
        RegistryEnvelopeError::Envelope(error) => map_envelope_error(error),
        RegistryEnvelopeError::Negotiation(error) => map_negotiation_error(error),
        RegistryEnvelopeError::WrongRegistryVersion(_) => {
            ShakescapeDisableReason::IncompatibleVersion
        }
        RegistryEnvelopeError::RegistryIdentityMismatch { .. } => {
            ShakescapeDisableReason::WrongFingerprint
        }
        RegistryEnvelopeError::WrongProtocol { .. } => ShakescapeDisableReason::UnsupportedProtocol,
        RegistryEnvelopeError::UnsupportedFlags(_) => ShakescapeDisableReason::UnsupportedProtocol,
        RegistryEnvelopeError::UnexpectedMessage { .. } => {
            ShakescapeDisableReason::UnexpectedMessage
        }
    }
}

fn map_envelope_error(error: &EnvelopeError) -> ShakescapeDisableReason {
    match error {
        EnvelopeError::PacketTooLarge { .. } => ShakescapeDisableReason::PacketTooLarge,
        EnvelopeError::PayloadTooLarge { .. } => ShakescapeDisableReason::PayloadTooLarge,
        EnvelopeError::UnknownMessage { .. } => ShakescapeDisableReason::UnexpectedMessage,
        EnvelopeError::ProtocolUnavailable { .. } | EnvelopeError::UnsupportedFlags { .. } => {
            ShakescapeDisableReason::UnsupportedProtocol
        }
        EnvelopeError::ZeroRequestId { .. }
        | EnvelopeError::Decode(_)
        | EnvelopeError::WrongMagic(_)
        | EnvelopeError::LengthMismatch { .. } => ShakescapeDisableReason::MalformedEnvelope,
    }
}

fn map_negotiation_error(error: &NegotiationError) -> ShakescapeDisableReason {
    match error {
        NegotiationError::WrongFingerprint { .. } => ShakescapeDisableReason::WrongFingerprint,
        NegotiationError::WrongNetwork { .. } | NegotiationError::UnknownNetwork(_) => {
            ShakescapeDisableReason::WrongNetwork
        }
        NegotiationError::WrongGenesis | NegotiationError::ZeroGenesis => {
            ShakescapeDisableReason::WrongGenesis
        }
        NegotiationError::UnknownFormatVersion(_) | NegotiationError::NoCommonRegistry => {
            ShakescapeDisableReason::IncompatibleVersion
        }
        NegotiationError::ZeroResourceLimit => ShakescapeDisableReason::InvalidResourceLimit,
        NegotiationError::MissingRegistryProtocol
        | NegotiationError::UnsupportedRegistryProtocolRange(_)
        | NegotiationError::RegistryProtocolNotNegotiated => {
            ShakescapeDisableReason::UnsupportedProtocol
        }
        NegotiationError::Decode(_)
        | NegotiationError::WrongMagic(_)
        | NegotiationError::RegistryVersionCount(_)
        | NegotiationError::ProtocolCount(_)
        | NegotiationError::DuplicateOrZeroRegistryVersion
        | NegotiationError::DuplicateProtocol
        | NegotiationError::ManagedRegistryProtocol
        | NegotiationError::InvalidProtocolRange(_) => ShakescapeDisableReason::MalformedHello,
    }
}

pub(crate) const fn is_extension_packet_type(packet_type: PacketType) -> bool {
    matches!(
        packet_type,
        PacketType::Unknown(value) if value == SHAKESCAPE_EXTENSION_PACKET.value()
    )
}

pub(crate) fn is_registry_hello_packet(packet: &Packet) -> bool {
    match packet {
        Packet::Unknown {
            packet_type,
            payload,
        } if is_extension_packet_type(*packet_type) => {
            ShakescapeExtensionEnvelope::decode_registry_hello(payload).is_ok()
        }
        _ => false,
    }
}

pub(crate) fn extension_packet(payload: Vec<u8>) -> Packet {
    Packet::Unknown {
        packet_type: PacketType::Unknown(SHAKESCAPE_EXTENSION_PACKET.value()),
        payload,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_p2p_experimental::SHAKESCAPE_ENVELOPE_OVERHEAD;

    const SERVICES: u64 = crate::SERVICE_NETWORK | SHAKESCAPE_EXTENSION_SERVICE.value();

    fn coordinator(
        direction: PeerDirection,
        network: ConsensusNetwork,
        metrics: ShakescapeRuntimeMetrics,
    ) -> ShakescapeCoordinator {
        let mut coordinator = ShakescapeCoordinator::new(
            direction,
            network,
            SERVICES,
            7,
            Duration::from_secs(1),
            metrics,
        )
        .expect("canonical coordinator");
        coordinator.observe_remote_services(SERVICES);
        coordinator
    }

    fn admit(coordinator: &mut ShakescapeCoordinator, action: ShakescapeAction) -> Vec<u8> {
        let message = action.outbound_message.expect("outbound message kind");
        let payload = action.response_payload.expect("outbound payload");
        coordinator.outbound_admitted(message, Instant::now());
        payload
    }

    #[test]
    fn public_reason_order_and_labels_are_stable() {
        let summary = ShakescapeSummary::default();
        assert_eq!(
            summary.rejection_reasons.len(),
            ShakescapeDisableReason::ALL.len()
        );
        for (index, reason) in ShakescapeDisableReason::ALL.into_iter().enumerate() {
            assert_eq!(reason.index(), index);
            assert_eq!(
                serde_json::to_string(&reason).expect("serialize reason"),
                format!("\"{}\"", reason.as_str())
            );
            assert_eq!(summary.rejection_reasons[index].reason, reason);
        }
    }

    #[test]
    fn pinned_registry_errors_map_to_fail_closed_disable_reasons() {
        assert_eq!(
            map_registry_error(&RegistryEnvelopeError::RegistryIdentityMismatch {
                registry_version: 1,
            }),
            ShakescapeDisableReason::WrongFingerprint
        );
        assert_eq!(
            map_envelope_error(&EnvelopeError::ProtocolUnavailable {
                registry_version: 1,
                protocol_id: 1,
            }),
            ShakescapeDisableReason::UnsupportedProtocol
        );
        assert_eq!(
            map_envelope_error(&EnvelopeError::UnsupportedFlags {
                protocol_id: 1,
                protocol_version: 1,
                flags: 1,
            }),
            ShakescapeDisableReason::UnsupportedProtocol
        );
        assert_eq!(
            map_negotiation_error(&NegotiationError::ZeroGenesis),
            ShakescapeDisableReason::WrongGenesis
        );
    }

    #[test]
    fn advertisement_phase_is_unknown_until_version_is_observed() {
        let metrics = ShakescapeRuntimeMetrics::default();
        let mut enabled = ShakescapeCoordinator::new(
            PeerDirection::Inbound,
            ConsensusNetwork::Regtest,
            SERVICES,
            7,
            Duration::from_secs(1),
            metrics.clone(),
        )
        .expect("enabled coordinator");
        assert_eq!(
            enabled.diagnostics.phase,
            ShakescapePeerPhase::AwaitingVersion
        );
        enabled.observe_remote_services(crate::SERVICE_NETWORK);
        assert_eq!(
            enabled.diagnostics.phase,
            ShakescapePeerPhase::NotAdvertised
        );

        let disabled = ShakescapeCoordinator::new(
            PeerDirection::Inbound,
            ConsensusNetwork::Regtest,
            crate::SERVICE_NETWORK,
            8,
            Duration::from_secs(1),
            metrics,
        )
        .expect("locally disabled coordinator");
        assert_eq!(
            disabled.diagnostics.phase,
            ShakescapePeerPhase::LocalDisabled
        );
    }

    #[test]
    fn stock_peer_becomes_ready_without_admitting_a_shakescape_hello() {
        let metrics = ShakescapeRuntimeMetrics::default();
        let mut coordinator = ShakescapeCoordinator::new(
            PeerDirection::Outbound,
            ConsensusNetwork::Regtest,
            SERVICES,
            7,
            Duration::from_secs(1),
            metrics.clone(),
        )
        .expect("canonical coordinator");
        coordinator.observe_remote_services(crate::SERVICE_NETWORK);

        let action = coordinator.on_ready(Instant::now());

        assert_eq!(
            coordinator.diagnostics.phase,
            ShakescapePeerPhase::NotAdvertised
        );
        assert_eq!(action, ShakescapeAction::default());
        let diagnostics = [coordinator.diagnostics()];
        let summary = metrics.summary(SERVICES, &diagnostics);
        assert_eq!(summary.live.not_advertised, 1);
        assert_eq!(summary.process.admitted(), 0);
        assert_eq!(summary.process.agreements_computed, 0);
    }

    #[test]
    fn coordinators_negotiate_canonical_registry() {
        let outbound_metrics = ShakescapeRuntimeMetrics::default();
        let inbound_metrics = ShakescapeRuntimeMetrics::default();
        let now = Instant::now();
        let mut outbound = coordinator(
            PeerDirection::Outbound,
            ConsensusNetwork::Regtest,
            outbound_metrics.clone(),
        );
        let mut inbound = coordinator(
            PeerDirection::Inbound,
            ConsensusNetwork::Regtest,
            inbound_metrics.clone(),
        );

        inbound.on_ready(now);
        let outbound_action = outbound.on_ready(now);
        let hello = admit(&mut outbound, outbound_action);
        let inbound_action = inbound.receive_extension(&hello);
        let ack = admit(&mut inbound, inbound_action);
        outbound.receive_extension(&ack);

        assert_eq!(outbound.diagnostics.phase, ShakescapePeerPhase::Negotiated);
        assert_eq!(inbound.diagnostics.phase, ShakescapePeerPhase::Negotiated);
        assert_eq!(
            outbound
                .diagnostics
                .negotiated
                .as_ref()
                .expect("parameters")
                .maximum_send_size,
            SHAKESCAPE_EXTENSION_MAX_PACKET_PAYLOAD as u32
        );
        assert_eq!(
            outbound_metrics.summary(SERVICES, &[]).process,
            ShakescapeProcessTotals {
                hello_admitted: 1,
                hello_ack_received: 1,
                agreements_computed: 1,
                ..ShakescapeProcessTotals::default()
            }
        );
        assert_eq!(
            inbound_metrics.summary(SERVICES, &[]).process,
            ShakescapeProcessTotals {
                hello_received: 1,
                hello_ack_admitted: 1,
                agreements_computed: 1,
                ..ShakescapeProcessTotals::default()
            }
        );

        let unknown_subprotocol = ShakescapeExtensionEnvelope {
            registry_version: SHAKESCAPE_V1_REGISTRY_VERSION,
            protocol_id: 0x7fff,
            protocol_version: 1,
            message_type: 1,
            flags: 0,
            request_id: 9,
            payload: Vec::new(),
        }
        .encode_canonical()
        .expect("bounded unknown protocol");
        outbound.receive_extension(&unknown_subprotocol);
        assert_eq!(outbound.diagnostics.phase, ShakescapePeerPhase::Negotiated);
        assert_eq!(outbound_metrics.summary(SERVICES, &[]).process.rejected, 1);
    }

    #[test]
    fn responder_acks_semantic_mismatch_then_disables_extension_only() {
        let now = Instant::now();
        let mut outbound = coordinator(
            PeerDirection::Outbound,
            ConsensusNetwork::Testnet,
            ShakescapeRuntimeMetrics::default(),
        );
        let mut inbound = coordinator(
            PeerDirection::Inbound,
            ConsensusNetwork::Regtest,
            ShakescapeRuntimeMetrics::default(),
        );
        inbound.on_ready(now);
        let outbound_action = outbound.on_ready(now);
        let hello = admit(&mut outbound, outbound_action);
        let action = inbound.receive_extension(&hello);

        assert!(action.response_payload.is_some());
        assert_eq!(inbound.diagnostics.phase, ShakescapePeerPhase::Disabled);
        assert_eq!(
            inbound.diagnostics.disable_reason,
            Some(ShakescapeDisableReason::WrongNetwork)
        );
    }

    #[test]
    fn coordinator_maps_mismatch_malformed_and_replay_failures() {
        let now = Instant::now();

        let mut fingerprint_sender = coordinator(
            PeerDirection::Outbound,
            ConsensusNetwork::Regtest,
            ShakescapeRuntimeMetrics::default(),
        );
        let mut fingerprint_hello = fingerprint_sender
            .on_ready(now)
            .response_payload
            .expect("fingerprint hello");
        fingerprint_hello[SHAKESCAPE_ENVELOPE_OVERHEAD + 6] ^= 0x01;
        let mut fingerprint_receiver = coordinator(
            PeerDirection::Inbound,
            ConsensusNetwork::Regtest,
            ShakescapeRuntimeMetrics::default(),
        );
        fingerprint_receiver.on_ready(now);
        let action = fingerprint_receiver.receive_extension(&fingerprint_hello);
        assert_eq!(action.response_payload, None);
        assert_eq!(
            fingerprint_receiver.diagnostics.disable_reason,
            Some(ShakescapeDisableReason::WrongFingerprint)
        );

        let genesis_sender = coordinator(
            PeerDirection::Outbound,
            ConsensusNetwork::Regtest,
            ShakescapeRuntimeMetrics::default(),
        );
        let mut wrong_genesis = genesis_sender.local_hello.clone();
        wrong_genesis.genesis_hash[0] ^= 0x01;
        let genesis_hello = encode_hello(11, &wrong_genesis, false).expect("genesis hello");
        let mut genesis_receiver = coordinator(
            PeerDirection::Inbound,
            ConsensusNetwork::Regtest,
            ShakescapeRuntimeMetrics::default(),
        );
        genesis_receiver.on_ready(now);
        let action = genesis_receiver.receive_extension(&genesis_hello);
        assert!(action.response_payload.is_some());
        assert_eq!(
            genesis_receiver.diagnostics.disable_reason,
            Some(ShakescapeDisableReason::WrongGenesis)
        );

        let malformed_hello = ShakescapeExtensionEnvelope {
            registry_version: SHAKESCAPE_V1_REGISTRY_VERSION,
            protocol_id: 0,
            protocol_version: 1,
            message_type: 1,
            flags: 0,
            request_id: 12,
            payload: vec![0x00],
        }
        .encode_canonical()
        .expect("structurally valid envelope");
        let mut malformed_receiver = coordinator(
            PeerDirection::Inbound,
            ConsensusNetwork::Regtest,
            ShakescapeRuntimeMetrics::default(),
        );
        malformed_receiver.on_ready(now);
        assert_eq!(
            malformed_receiver
                .receive_extension(&malformed_hello)
                .response_payload,
            None
        );
        assert_eq!(
            malformed_receiver.diagnostics.disable_reason,
            Some(ShakescapeDisableReason::MalformedHello)
        );

        let mut replay_sender = coordinator(
            PeerDirection::Outbound,
            ConsensusNetwork::Regtest,
            ShakescapeRuntimeMetrics::default(),
        );
        let replay_action = replay_sender.on_ready(now);
        let hello = admit(&mut replay_sender, replay_action);
        let mut replay_receiver = coordinator(
            PeerDirection::Inbound,
            ConsensusNetwork::Regtest,
            ShakescapeRuntimeMetrics::default(),
        );
        replay_receiver.on_ready(now);
        let ack_action = replay_receiver.receive_extension(&hello);
        let _ack = admit(&mut replay_receiver, ack_action);
        assert_eq!(
            replay_receiver.diagnostics.phase,
            ShakescapePeerPhase::Negotiated
        );
        replay_receiver.receive_extension(&hello);
        assert_eq!(
            replay_receiver.diagnostics.disable_reason,
            Some(ShakescapeDisableReason::DuplicateOrReplay)
        );
    }

    #[test]
    fn full_packet_bound_and_timeout_are_scoped_diagnostics() {
        let now = Instant::now();
        let inbound_metrics = ShakescapeRuntimeMetrics::default();
        let mut inbound = coordinator(
            PeerDirection::Inbound,
            ConsensusNetwork::Regtest,
            inbound_metrics.clone(),
        );
        inbound.on_ready(now);
        let oversized = vec![0; SHAKESCAPE_EXTENSION_MAX_PACKET_PAYLOAD + 1];
        assert_eq!(inbound.receive_extension(&oversized).response_payload, None);
        assert_eq!(inbound.receive_extension(&oversized).response_payload, None);
        assert_eq!(
            inbound.diagnostics.disable_reason,
            Some(ShakescapeDisableReason::PacketTooLarge)
        );
        let oversized_summary = inbound_metrics.summary(SERVICES, &[inbound.diagnostics()]);
        assert_eq!(oversized_summary.process.disabled, 1);
        assert_eq!(oversized_summary.process.rejected, 2);
        assert_eq!(
            oversized_summary.rejection_reasons[ShakescapeDisableReason::PacketTooLarge.index()]
                .count,
            2
        );

        let metrics = ShakescapeRuntimeMetrics::default();
        let mut outbound = coordinator(
            PeerDirection::Outbound,
            ConsensusNetwork::Regtest,
            metrics.clone(),
        );
        outbound.negotiation_timeout = Duration::from_millis(1);
        let action = outbound.on_ready(now);
        let hello = admit(&mut outbound, action);
        let mut responder = coordinator(
            PeerDirection::Inbound,
            ConsensusNetwork::Regtest,
            ShakescapeRuntimeMetrics::default(),
        );
        responder.on_ready(now);
        let response = responder.receive_extension(&hello);
        let late_ack = admit(&mut responder, response);
        let deadline = outbound.pending_deadline().expect("admitted deadline");
        assert!(outbound.expire(deadline));
        outbound.receive_extension(&late_ack);
        assert_eq!(
            outbound.diagnostics.disable_reason,
            Some(ShakescapeDisableReason::NegotiationTimeout)
        );
        assert_eq!(metrics.summary(SERVICES, &[]).process.hello_ack_received, 0);
        assert_eq!(metrics.summary(SERVICES, &[]).process.disabled, 1);
    }
}
