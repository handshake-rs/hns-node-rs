//! Runtime coordination and bounded diagnostics for Denuo Experimental V1.
//!
//! The coordinator is deliberately isolated from the ordinary Handshake peer
//! state machine. An experimental negotiation failure disables Denuo for that
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
use hns_p2p_experimental::{
    DenuoExtensionEnvelope, EnvelopeError, ExperimentalWireProfile, KnownMessage,
    NegotiatedRegistry, NegotiationError, Network, ProtocolDisposition, RegistryEnvelopeError,
    RegistryHello, DENUO_EXTENSION_MAX_NESTED_PAYLOAD, DENUO_EXTENSION_MAX_PACKET_PAYLOAD,
    DENUO_EXTENSION_PACKET, DENUO_EXTENSION_SERVICE, DENUO_V1_REGISTRY_FINGERPRINT,
    DENUO_V1_REGISTRY_ID, DENUO_V1_REGISTRY_NAME, DENUO_V1_REGISTRY_PROTOCOL_VERSION,
    DENUO_V1_REGISTRY_VERSION, DENUO_V1_WIRE_PROFILE, EXPERIMENTAL_STATUS_LABEL,
    REGISTRY_NEGOTIATION_MAX_PAYLOAD,
};
use serde::{Deserialize, Serialize};
use tokio::time::Instant;

use crate::{
    handshake::PeerDirection,
    wire::{Packet, PacketType},
};

pub const DENUO_DEFAULT_MAXIMUM_LIVE_REQUESTS: u16 = 64;

#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum DenuoPeerPhase {
    #[default]
    AwaitingVersion,
    NotAdvertised,
    LocalDisabled,
    Eligible,
    HelloAdmitted,
    Negotiated,
    Disabled,
}

impl DenuoPeerPhase {
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
pub enum DenuoDisableReason {
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

impl DenuoDisableReason {
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
pub struct DenuoNegotiatedProtocol {
    pub protocol_id: u16,
    pub protocol_version: u16,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DenuoNegotiatedParameters {
    pub registry_version: u16,
    pub protocols: Vec<DenuoNegotiatedProtocol>,
    pub maximum_send_size: u32,
    pub maximum_live_requests: u16,
    pub feature_flags: u64,
}

impl From<&NegotiatedRegistry> for DenuoNegotiatedParameters {
    fn from(negotiated: &NegotiatedRegistry) -> Self {
        Self {
            registry_version: negotiated.registry_version,
            protocols: negotiated
                .protocols
                .iter()
                .map(|(protocol_id, protocol_version)| DenuoNegotiatedProtocol {
                    protocol_id: *protocol_id,
                    protocol_version: *protocol_version,
                })
                .collect(),
            maximum_send_size: negotiated.maximum_send_size,
            maximum_live_requests: negotiated.maximum_live_requests,
            feature_flags: negotiated.feature_flags,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DenuoPeerDiagnostics {
    pub phase: DenuoPeerPhase,
    pub disable_reason: Option<DenuoDisableReason>,
    pub request_id: Option<u64>,
    pub negotiated: Option<DenuoNegotiatedParameters>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DenuoRegistryIdentity {
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

impl Default for DenuoRegistryIdentity {
    fn default() -> Self {
        Self {
            name: DENUO_V1_REGISTRY_NAME.to_owned(),
            registry_id: DENUO_V1_REGISTRY_ID.to_string(),
            fingerprint: DENUO_V1_REGISTRY_FINGERPRINT.to_string(),
            registry_version: DENUO_V1_REGISTRY_VERSION,
            registry_protocol_version: DENUO_V1_REGISTRY_PROTOCOL_VERSION,
            wire_profile: DENUO_V1_WIRE_PROFILE.to_owned(),
            status: EXPERIMENTAL_STATUS_LABEL.to_owned(),
            service_bit: DENUO_EXTENSION_SERVICE.value(),
            packet_type: DENUO_EXTENSION_PACKET.value(),
            maximum_packet_payload: DENUO_EXTENSION_MAX_PACKET_PAYLOAD as u32,
            maximum_nested_payload: DENUO_EXTENSION_MAX_NESTED_PAYLOAD as u32,
            maximum_registry_negotiation_payload: REGISTRY_NEGOTIATION_MAX_PAYLOAD as u32,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DenuoLiveCounts {
    pub awaiting_version: u64,
    pub not_advertised: u64,
    pub local_disabled: u64,
    pub eligible: u64,
    pub pending: u64,
    pub negotiated: u64,
    pub disabled: u64,
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct DenuoProcessTotals {
    pub hello_admitted: u64,
    pub hello_received: u64,
    pub hello_ack_admitted: u64,
    pub hello_ack_received: u64,
    pub agreements_computed: u64,
    pub rejected: u64,
    pub disabled: u64,
}

impl DenuoProcessTotals {
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
pub struct DenuoReasonCount {
    pub reason: DenuoDisableReason,
    pub count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct DenuoSummary {
    pub identity: DenuoRegistryIdentity,
    pub local_service_mask: u64,
    pub advertised: bool,
    pub live: DenuoLiveCounts,
    pub process: DenuoProcessTotals,
    pub rejection_reasons: Vec<DenuoReasonCount>,
}

impl Default for DenuoSummary {
    fn default() -> Self {
        Self {
            identity: DenuoRegistryIdentity::default(),
            local_service_mask: 0,
            advertised: false,
            live: DenuoLiveCounts::default(),
            process: DenuoProcessTotals::default(),
            rejection_reasons: DenuoDisableReason::ALL
                .into_iter()
                .map(|reason| DenuoReasonCount { reason, count: 0 })
                .collect(),
        }
    }
}

impl DenuoSummary {
    pub const fn advertised(&self) -> bool {
        self.advertised
    }
}

#[derive(Debug, Default)]
struct DenuoRuntimeMetricsInner {
    hello_admitted: AtomicU64,
    hello_received: AtomicU64,
    hello_ack_admitted: AtomicU64,
    hello_ack_received: AtomicU64,
    agreements_computed: AtomicU64,
    rejected: AtomicU64,
    disabled: AtomicU64,
    rejection_reasons: [AtomicU64; DenuoDisableReason::ALL.len()],
}

#[derive(Clone, Debug, Default)]
pub(crate) struct DenuoRuntimeMetrics {
    inner: Arc<DenuoRuntimeMetricsInner>,
}

impl DenuoRuntimeMetrics {
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

    fn record_disabled(&self, reason: DenuoDisableReason) {
        saturating_increment(&self.inner.disabled);
        self.record_rejected(reason);
    }

    fn record_rejected(&self, reason: DenuoDisableReason) {
        saturating_increment(&self.inner.rejected);
        saturating_increment(&self.inner.rejection_reasons[reason.index()]);
    }

    pub(crate) fn summary(
        &self,
        local_service_mask: u64,
        peers: &[DenuoPeerDiagnostics],
    ) -> DenuoSummary {
        let mut live = DenuoLiveCounts::default();
        for peer in peers {
            let target = match peer.phase {
                DenuoPeerPhase::AwaitingVersion => &mut live.awaiting_version,
                DenuoPeerPhase::NotAdvertised => &mut live.not_advertised,
                DenuoPeerPhase::LocalDisabled => &mut live.local_disabled,
                DenuoPeerPhase::Eligible => &mut live.eligible,
                DenuoPeerPhase::HelloAdmitted => &mut live.pending,
                DenuoPeerPhase::Negotiated => &mut live.negotiated,
                DenuoPeerPhase::Disabled => &mut live.disabled,
            };
            *target = target.saturating_add(1);
        }

        DenuoSummary {
            identity: DenuoRegistryIdentity::default(),
            local_service_mask,
            advertised: local_service_mask & DENUO_EXTENSION_SERVICE.value() != 0,
            live,
            process: DenuoProcessTotals {
                hello_admitted: self.inner.hello_admitted.load(Ordering::Acquire),
                hello_received: self.inner.hello_received.load(Ordering::Acquire),
                hello_ack_admitted: self.inner.hello_ack_admitted.load(Ordering::Acquire),
                hello_ack_received: self.inner.hello_ack_received.load(Ordering::Acquire),
                agreements_computed: self.inner.agreements_computed.load(Ordering::Acquire),
                rejected: self.inner.rejected.load(Ordering::Acquire),
                disabled: self.inner.disabled.load(Ordering::Acquire),
            },
            rejection_reasons: DenuoDisableReason::ALL
                .into_iter()
                .map(|reason| DenuoReasonCount {
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
pub(crate) enum DenuoOutboundMessage {
    Hello,
    HelloAck,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct DenuoAction {
    pub response_payload: Option<Vec<u8>>,
    pub outbound_message: Option<DenuoOutboundMessage>,
}

#[derive(Debug)]
pub(crate) struct DenuoCoordinator {
    direction: PeerDirection,
    local_enabled: bool,
    local_hello: RegistryHello,
    proposed_request_id: u64,
    negotiation_timeout: Duration,
    ready: bool,
    remote_advertises: Option<bool>,
    pending_deadline: Option<Instant>,
    negotiated: Option<NegotiatedRegistry>,
    diagnostics: DenuoPeerDiagnostics,
    metrics: DenuoRuntimeMetrics,
}

impl DenuoCoordinator {
    pub(crate) fn new(
        direction: PeerDirection,
        network: ConsensusNetwork,
        local_services: u64,
        proposed_request_id: u64,
        negotiation_timeout: Duration,
        metrics: DenuoRuntimeMetrics,
    ) -> Result<Self, NegotiationError> {
        let experimental_network = match network {
            ConsensusNetwork::Mainnet => Network::Mainnet,
            ConsensusNetwork::Testnet => Network::Testnet,
            ConsensusNetwork::Regtest => Network::Regtest,
            ConsensusNetwork::Simnet => Network::Simnet,
        };
        let local_hello = RegistryHello::denuo_v1(
            experimental_network,
            network.params().genesis_hash.into_inner(),
            Vec::new(),
            u32::try_from(
                DENUO_EXTENSION_MAX_PACKET_PAYLOAD.max(MAX_DNS_RELAY_RESPONSE_PAYLOAD_SIZE),
            )
            .expect("canonical Denuo packet ceilings fit u32"),
            DENUO_DEFAULT_MAXIMUM_LIVE_REQUESTS,
            0,
        )?;
        let diagnostics = DenuoPeerDiagnostics {
            phase: if local_services & DENUO_EXTENSION_SERVICE.value() != 0 {
                DenuoPeerPhase::AwaitingVersion
            } else {
                DenuoPeerPhase::LocalDisabled
            },
            ..DenuoPeerDiagnostics::default()
        };
        Ok(Self {
            direction,
            local_enabled: local_services & DENUO_EXTENSION_SERVICE.value() != 0,
            local_hello,
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

    pub(crate) fn diagnostics(&self) -> DenuoPeerDiagnostics {
        self.diagnostics.clone()
    }

    pub(crate) fn negotiated_evidence(
        &self,
    ) -> Option<(ExperimentalWireProfile, &NegotiatedRegistry)> {
        self.negotiated
            .as_ref()
            .map(|negotiated| (ExperimentalWireProfile::DenuoV1, negotiated))
    }

    pub(crate) fn observe_remote_services(&mut self, services: u64) {
        let advertised = services & DENUO_EXTENSION_SERVICE.value() != 0;
        self.remote_advertises = Some(advertised);
        if self.diagnostics.phase == DenuoPeerPhase::AwaitingVersion && self.local_enabled {
            self.diagnostics.phase = if advertised {
                DenuoPeerPhase::Eligible
            } else {
                DenuoPeerPhase::NotAdvertised
            };
        }
    }

    pub(crate) fn on_ready(&mut self, _now: Instant) -> DenuoAction {
        self.ready = true;
        if self.direction != PeerDirection::Outbound
            || self.diagnostics.phase != DenuoPeerPhase::Eligible
        {
            return DenuoAction::default();
        }

        let request_id = self.proposed_request_id;
        let response_payload = match encode_hello(request_id, &self.local_hello, false) {
            Ok(payload) => payload,
            Err(()) => {
                self.disable(DenuoDisableReason::LocalEncodingFailure);
                return DenuoAction::default();
            }
        };
        DenuoAction {
            response_payload: Some(response_payload),
            outbound_message: Some(DenuoOutboundMessage::Hello),
        }
    }

    pub(crate) fn pending_deadline(&self) -> Option<Instant> {
        self.pending_deadline
    }

    pub(crate) fn expire(&mut self, now: Instant) -> bool {
        if self.diagnostics.phase == DenuoPeerPhase::HelloAdmitted
            && self
                .pending_deadline
                .is_some_and(|deadline| now >= deadline)
        {
            self.disable(DenuoDisableReason::NegotiationTimeout);
            return true;
        }
        false
    }

    pub(crate) fn receive_extension(&mut self, payload: &[u8]) -> DenuoAction {
        if payload.len() > DENUO_EXTENSION_MAX_PACKET_PAYLOAD {
            if self.diagnostics.phase == DenuoPeerPhase::Disabled {
                self.metrics
                    .record_rejected(DenuoDisableReason::PacketTooLarge);
            } else {
                self.disable(DenuoDisableReason::PacketTooLarge);
            }
            return DenuoAction::default();
        }
        if self.diagnostics.phase == DenuoPeerPhase::Disabled {
            return DenuoAction::default();
        }
        if !self.local_enabled {
            self.metrics
                .record_rejected(DenuoDisableReason::LocalServiceDisabled);
            return DenuoAction::default();
        }
        match self.remote_advertises {
            Some(true) => {}
            Some(false) => {
                self.disable(DenuoDisableReason::PeerMissingService);
                return DenuoAction::default();
            }
            None => {
                self.disable(DenuoDisableReason::UnexpectedMessage);
                return DenuoAction::default();
            }
        }
        if !self.ready {
            self.disable(DenuoDisableReason::UnexpectedMessage);
            return DenuoAction::default();
        }
        let envelope = match DenuoExtensionEnvelope::decode_canonical(payload) {
            Ok(envelope) => envelope,
            Err(error) => {
                self.disable(map_envelope_error(&error));
                return DenuoAction::default();
            }
        };
        let disposition = match envelope.classify() {
            Ok(disposition) => disposition,
            Err(error) => {
                self.disable(map_envelope_error(&error));
                return DenuoAction::default();
            }
        };
        match disposition {
            ProtocolDisposition::Known(KnownMessage::RegistryHello) => self.receive_hello(payload),
            ProtocolDisposition::Known(KnownMessage::RegistryHelloAck) => {
                self.receive_hello_ack(payload)
            }
            ProtocolDisposition::Known(KnownMessage::RegistryReject) => {
                self.disable(DenuoDisableReason::UnexpectedMessage);
                DenuoAction::default()
            }
            ProtocolDisposition::Known(_) => {
                self.reject_subprotocol(DenuoDisableReason::UnsupportedProtocol);
                DenuoAction::default()
            }
            ProtocolDisposition::UnknownProtocol { .. } => {
                // Subprotocol support is isolated from registry negotiation.
                // Once the canonical registry is installed, a bounded packet
                // for an unknown protocol is ignored without destroying that
                // successful peer-level agreement.
                self.reject_subprotocol(DenuoDisableReason::UnsupportedProtocol);
                DenuoAction::default()
            }
        }
    }

    fn receive_hello(&mut self, payload: &[u8]) -> DenuoAction {
        if self.direction != PeerDirection::Inbound {
            self.disable(if self.diagnostics.phase == DenuoPeerPhase::Negotiated {
                DenuoDisableReason::DuplicateOrReplay
            } else {
                DenuoDisableReason::UnexpectedMessage
            });
            return DenuoAction::default();
        }
        if self.diagnostics.phase != DenuoPeerPhase::Eligible {
            self.disable(
                if self.diagnostics.request_id.is_some()
                    || self.diagnostics.phase == DenuoPeerPhase::Negotiated
                {
                    DenuoDisableReason::DuplicateOrReplay
                } else {
                    DenuoDisableReason::UnexpectedMessage
                },
            );
            return DenuoAction::default();
        }

        let (request_id, remote_hello) =
            match DenuoExtensionEnvelope::decode_registry_hello(payload) {
                Ok(message) => message,
                Err(error) => {
                    self.disable(map_registry_error(&error));
                    return DenuoAction::default();
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
                self.disable(DenuoDisableReason::LocalEncodingFailure);
                return DenuoAction::default();
            }
        };
        match NegotiatedRegistry::negotiate(&self.local_hello, &remote_hello) {
            Ok(negotiated) => self.install(negotiated),
            Err(error) => self.disable(map_negotiation_error(&error)),
        }
        DenuoAction {
            response_payload: Some(response_payload),
            outbound_message: Some(DenuoOutboundMessage::HelloAck),
        }
    }

    fn receive_hello_ack(&mut self, payload: &[u8]) -> DenuoAction {
        if self.direction != PeerDirection::Outbound {
            self.disable(DenuoDisableReason::UnexpectedMessage);
            return DenuoAction::default();
        }
        if self.diagnostics.phase != DenuoPeerPhase::HelloAdmitted {
            self.disable(
                if self.diagnostics.request_id.is_some()
                    || self.diagnostics.phase == DenuoPeerPhase::Negotiated
                {
                    DenuoDisableReason::DuplicateOrReplay
                } else {
                    DenuoDisableReason::UnexpectedMessage
                },
            );
            return DenuoAction::default();
        }

        let (request_id, remote_hello) =
            match DenuoExtensionEnvelope::decode_registry_hello_ack(payload) {
                Ok(message) => message,
                Err(error) => {
                    self.disable(map_registry_error(&error));
                    return DenuoAction::default();
                }
            };
        self.metrics.record_hello_ack_received();
        if self.diagnostics.request_id != Some(request_id) {
            self.disable(DenuoDisableReason::CorrelationMismatch);
            return DenuoAction::default();
        }
        match NegotiatedRegistry::negotiate(&self.local_hello, &remote_hello) {
            Ok(negotiated) => self.install(negotiated),
            Err(error) => self.disable(map_negotiation_error(&error)),
        }
        DenuoAction::default()
    }

    fn install(&mut self, negotiated: NegotiatedRegistry) {
        self.pending_deadline = None;
        self.diagnostics.phase = DenuoPeerPhase::Negotiated;
        self.diagnostics.disable_reason = None;
        self.diagnostics.negotiated = Some(DenuoNegotiatedParameters::from(&negotiated));
        self.negotiated = Some(negotiated);
        self.metrics.record_agreement_computed();
    }

    fn disable(&mut self, reason: DenuoDisableReason) {
        if self.diagnostics.phase == DenuoPeerPhase::Disabled {
            return;
        }
        self.pending_deadline = None;
        self.negotiated = None;
        self.diagnostics.phase = DenuoPeerPhase::Disabled;
        self.diagnostics.disable_reason = Some(reason);
        self.diagnostics.negotiated = None;
        self.metrics.record_disabled(reason);
    }

    fn reject_subprotocol(&mut self, reason: DenuoDisableReason) {
        if self.diagnostics.phase == DenuoPeerPhase::Negotiated {
            self.metrics.record_rejected(reason);
        } else {
            self.disable(reason);
        }
    }

    pub(crate) fn outbound_admitted(&mut self, message: DenuoOutboundMessage, now: Instant) {
        match message {
            DenuoOutboundMessage::Hello => {
                self.diagnostics.phase = DenuoPeerPhase::HelloAdmitted;
                self.diagnostics.request_id = Some(self.proposed_request_id);
                self.pending_deadline = Some(now + self.negotiation_timeout);
                self.metrics.record_hello_admitted();
            }
            DenuoOutboundMessage::HelloAck => self.metrics.record_hello_ack_admitted(),
        }
    }

    pub(crate) fn outbound_rejected(&mut self) {
        if self.diagnostics.phase == DenuoPeerPhase::Disabled {
            self.metrics
                .record_rejected(DenuoDisableReason::LocalSendUnavailable);
        } else {
            self.disable(DenuoDisableReason::LocalSendUnavailable);
        }
    }
}

fn encode_hello(request_id: u64, hello: &RegistryHello, ack: bool) -> Result<Vec<u8>, ()> {
    let envelope = if ack {
        DenuoExtensionEnvelope::registry_hello_ack(request_id, hello)
    } else {
        DenuoExtensionEnvelope::registry_hello(request_id, hello)
    }
    .map_err(|_| ())?;
    envelope.encode_canonical().map_err(|_| ())
}

fn map_registry_error(error: &RegistryEnvelopeError) -> DenuoDisableReason {
    match error {
        RegistryEnvelopeError::Envelope(error) => map_envelope_error(error),
        RegistryEnvelopeError::Negotiation(error) => map_negotiation_error(error),
        RegistryEnvelopeError::WrongRegistryVersion(_) => DenuoDisableReason::IncompatibleVersion,
        RegistryEnvelopeError::RegistryIdentityMismatch { .. } => {
            DenuoDisableReason::WrongFingerprint
        }
        RegistryEnvelopeError::WrongProtocol { .. } => DenuoDisableReason::UnsupportedProtocol,
        RegistryEnvelopeError::UnsupportedFlags(_) => DenuoDisableReason::UnsupportedProtocol,
        RegistryEnvelopeError::UnexpectedMessage { .. } => DenuoDisableReason::UnexpectedMessage,
    }
}

fn map_envelope_error(error: &EnvelopeError) -> DenuoDisableReason {
    match error {
        EnvelopeError::PacketTooLarge { .. } => DenuoDisableReason::PacketTooLarge,
        EnvelopeError::PayloadTooLarge { .. } => DenuoDisableReason::PayloadTooLarge,
        EnvelopeError::UnknownMessage { .. } => DenuoDisableReason::UnexpectedMessage,
        EnvelopeError::ProtocolUnavailable { .. } | EnvelopeError::UnsupportedFlags { .. } => {
            DenuoDisableReason::UnsupportedProtocol
        }
        EnvelopeError::ZeroRequestId { .. }
        | EnvelopeError::Decode(_)
        | EnvelopeError::WrongMagic(_)
        | EnvelopeError::LengthMismatch { .. } => DenuoDisableReason::MalformedEnvelope,
    }
}

fn map_negotiation_error(error: &NegotiationError) -> DenuoDisableReason {
    match error {
        NegotiationError::WrongFingerprint { .. } => DenuoDisableReason::WrongFingerprint,
        NegotiationError::WrongNetwork { .. } | NegotiationError::UnknownNetwork(_) => {
            DenuoDisableReason::WrongNetwork
        }
        NegotiationError::WrongGenesis | NegotiationError::ZeroGenesis => {
            DenuoDisableReason::WrongGenesis
        }
        NegotiationError::UnknownFormatVersion(_) | NegotiationError::NoCommonRegistry => {
            DenuoDisableReason::IncompatibleVersion
        }
        NegotiationError::ZeroResourceLimit => DenuoDisableReason::InvalidResourceLimit,
        NegotiationError::MissingRegistryProtocol
        | NegotiationError::UnsupportedRegistryProtocolRange(_)
        | NegotiationError::RegistryProtocolNotNegotiated => {
            DenuoDisableReason::UnsupportedProtocol
        }
        NegotiationError::Decode(_)
        | NegotiationError::WrongMagic(_)
        | NegotiationError::RegistryVersionCount(_)
        | NegotiationError::ProtocolCount(_)
        | NegotiationError::DuplicateOrZeroRegistryVersion
        | NegotiationError::DuplicateProtocol
        | NegotiationError::ManagedRegistryProtocol
        | NegotiationError::InvalidProtocolRange(_) => DenuoDisableReason::MalformedHello,
    }
}

pub(crate) const fn is_extension_packet_type(packet_type: PacketType) -> bool {
    matches!(
        packet_type,
        PacketType::Unknown(value) if value == DENUO_EXTENSION_PACKET.value()
    )
}

pub(crate) fn is_registry_hello_packet(packet: &Packet) -> bool {
    match packet {
        Packet::Unknown {
            packet_type,
            payload,
        } if is_extension_packet_type(*packet_type) => {
            DenuoExtensionEnvelope::decode_registry_hello(payload).is_ok()
        }
        _ => false,
    }
}

pub(crate) fn extension_packet(payload: Vec<u8>) -> Packet {
    Packet::Unknown {
        packet_type: PacketType::Unknown(DENUO_EXTENSION_PACKET.value()),
        payload,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_p2p_experimental::DENUO_ENVELOPE_OVERHEAD;

    const SERVICES: u64 = crate::SERVICE_NETWORK | DENUO_EXTENSION_SERVICE.value();

    fn coordinator(
        direction: PeerDirection,
        network: ConsensusNetwork,
        metrics: DenuoRuntimeMetrics,
    ) -> DenuoCoordinator {
        let mut coordinator = DenuoCoordinator::new(
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

    fn admit(coordinator: &mut DenuoCoordinator, action: DenuoAction) -> Vec<u8> {
        let message = action.outbound_message.expect("outbound message kind");
        let payload = action.response_payload.expect("outbound payload");
        coordinator.outbound_admitted(message, Instant::now());
        payload
    }

    #[test]
    fn public_reason_order_and_labels_are_stable() {
        let summary = DenuoSummary::default();
        assert_eq!(
            summary.rejection_reasons.len(),
            DenuoDisableReason::ALL.len()
        );
        for (index, reason) in DenuoDisableReason::ALL.into_iter().enumerate() {
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
            DenuoDisableReason::WrongFingerprint
        );
        assert_eq!(
            map_envelope_error(&EnvelopeError::ProtocolUnavailable {
                registry_version: 1,
                protocol_id: 1,
            }),
            DenuoDisableReason::UnsupportedProtocol
        );
        assert_eq!(
            map_envelope_error(&EnvelopeError::UnsupportedFlags {
                protocol_id: 1,
                protocol_version: 1,
                flags: 1,
            }),
            DenuoDisableReason::UnsupportedProtocol
        );
        assert_eq!(
            map_negotiation_error(&NegotiationError::ZeroGenesis),
            DenuoDisableReason::WrongGenesis
        );
    }

    #[test]
    fn advertisement_phase_is_unknown_until_version_is_observed() {
        let metrics = DenuoRuntimeMetrics::default();
        let mut enabled = DenuoCoordinator::new(
            PeerDirection::Inbound,
            ConsensusNetwork::Regtest,
            SERVICES,
            7,
            Duration::from_secs(1),
            metrics.clone(),
        )
        .expect("enabled coordinator");
        assert_eq!(enabled.diagnostics.phase, DenuoPeerPhase::AwaitingVersion);
        enabled.observe_remote_services(crate::SERVICE_NETWORK);
        assert_eq!(enabled.diagnostics.phase, DenuoPeerPhase::NotAdvertised);

        let disabled = DenuoCoordinator::new(
            PeerDirection::Inbound,
            ConsensusNetwork::Regtest,
            crate::SERVICE_NETWORK,
            8,
            Duration::from_secs(1),
            metrics,
        )
        .expect("locally disabled coordinator");
        assert_eq!(disabled.diagnostics.phase, DenuoPeerPhase::LocalDisabled);
    }

    #[test]
    fn stock_peer_becomes_ready_without_admitting_a_denuo_hello() {
        let metrics = DenuoRuntimeMetrics::default();
        let mut coordinator = DenuoCoordinator::new(
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

        assert_eq!(coordinator.diagnostics.phase, DenuoPeerPhase::NotAdvertised);
        assert_eq!(action, DenuoAction::default());
        let diagnostics = [coordinator.diagnostics()];
        let summary = metrics.summary(SERVICES, &diagnostics);
        assert_eq!(summary.live.not_advertised, 1);
        assert_eq!(summary.process.admitted(), 0);
        assert_eq!(summary.process.agreements_computed, 0);
    }

    #[test]
    fn coordinators_negotiate_canonical_registry() {
        let outbound_metrics = DenuoRuntimeMetrics::default();
        let inbound_metrics = DenuoRuntimeMetrics::default();
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

        assert_eq!(outbound.diagnostics.phase, DenuoPeerPhase::Negotiated);
        assert_eq!(inbound.diagnostics.phase, DenuoPeerPhase::Negotiated);
        assert_eq!(
            outbound
                .diagnostics
                .negotiated
                .as_ref()
                .expect("parameters")
                .maximum_send_size,
            DENUO_EXTENSION_MAX_PACKET_PAYLOAD as u32
        );
        assert_eq!(
            outbound_metrics.summary(SERVICES, &[]).process,
            DenuoProcessTotals {
                hello_admitted: 1,
                hello_ack_received: 1,
                agreements_computed: 1,
                ..DenuoProcessTotals::default()
            }
        );
        assert_eq!(
            inbound_metrics.summary(SERVICES, &[]).process,
            DenuoProcessTotals {
                hello_received: 1,
                hello_ack_admitted: 1,
                agreements_computed: 1,
                ..DenuoProcessTotals::default()
            }
        );

        let unknown_subprotocol = DenuoExtensionEnvelope {
            registry_version: DENUO_V1_REGISTRY_VERSION,
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
        assert_eq!(outbound.diagnostics.phase, DenuoPeerPhase::Negotiated);
        assert_eq!(outbound_metrics.summary(SERVICES, &[]).process.rejected, 1);
    }

    #[test]
    fn responder_acks_semantic_mismatch_then_disables_extension_only() {
        let now = Instant::now();
        let mut outbound = coordinator(
            PeerDirection::Outbound,
            ConsensusNetwork::Testnet,
            DenuoRuntimeMetrics::default(),
        );
        let mut inbound = coordinator(
            PeerDirection::Inbound,
            ConsensusNetwork::Regtest,
            DenuoRuntimeMetrics::default(),
        );
        inbound.on_ready(now);
        let outbound_action = outbound.on_ready(now);
        let hello = admit(&mut outbound, outbound_action);
        let action = inbound.receive_extension(&hello);

        assert!(action.response_payload.is_some());
        assert_eq!(inbound.diagnostics.phase, DenuoPeerPhase::Disabled);
        assert_eq!(
            inbound.diagnostics.disable_reason,
            Some(DenuoDisableReason::WrongNetwork)
        );
    }

    #[test]
    fn coordinator_maps_mismatch_malformed_and_replay_failures() {
        let now = Instant::now();

        let mut fingerprint_sender = coordinator(
            PeerDirection::Outbound,
            ConsensusNetwork::Regtest,
            DenuoRuntimeMetrics::default(),
        );
        let mut fingerprint_hello = fingerprint_sender
            .on_ready(now)
            .response_payload
            .expect("fingerprint hello");
        fingerprint_hello[DENUO_ENVELOPE_OVERHEAD + 6] ^= 0x01;
        let mut fingerprint_receiver = coordinator(
            PeerDirection::Inbound,
            ConsensusNetwork::Regtest,
            DenuoRuntimeMetrics::default(),
        );
        fingerprint_receiver.on_ready(now);
        let action = fingerprint_receiver.receive_extension(&fingerprint_hello);
        assert_eq!(action.response_payload, None);
        assert_eq!(
            fingerprint_receiver.diagnostics.disable_reason,
            Some(DenuoDisableReason::WrongFingerprint)
        );

        let genesis_sender = coordinator(
            PeerDirection::Outbound,
            ConsensusNetwork::Regtest,
            DenuoRuntimeMetrics::default(),
        );
        let mut wrong_genesis = genesis_sender.local_hello.clone();
        wrong_genesis.genesis_hash[0] ^= 0x01;
        let genesis_hello = encode_hello(11, &wrong_genesis, false).expect("genesis hello");
        let mut genesis_receiver = coordinator(
            PeerDirection::Inbound,
            ConsensusNetwork::Regtest,
            DenuoRuntimeMetrics::default(),
        );
        genesis_receiver.on_ready(now);
        let action = genesis_receiver.receive_extension(&genesis_hello);
        assert!(action.response_payload.is_some());
        assert_eq!(
            genesis_receiver.diagnostics.disable_reason,
            Some(DenuoDisableReason::WrongGenesis)
        );

        let malformed_hello = DenuoExtensionEnvelope {
            registry_version: DENUO_V1_REGISTRY_VERSION,
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
            DenuoRuntimeMetrics::default(),
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
            Some(DenuoDisableReason::MalformedHello)
        );

        let mut replay_sender = coordinator(
            PeerDirection::Outbound,
            ConsensusNetwork::Regtest,
            DenuoRuntimeMetrics::default(),
        );
        let replay_action = replay_sender.on_ready(now);
        let hello = admit(&mut replay_sender, replay_action);
        let mut replay_receiver = coordinator(
            PeerDirection::Inbound,
            ConsensusNetwork::Regtest,
            DenuoRuntimeMetrics::default(),
        );
        replay_receiver.on_ready(now);
        let ack_action = replay_receiver.receive_extension(&hello);
        let _ack = admit(&mut replay_receiver, ack_action);
        assert_eq!(
            replay_receiver.diagnostics.phase,
            DenuoPeerPhase::Negotiated
        );
        replay_receiver.receive_extension(&hello);
        assert_eq!(
            replay_receiver.diagnostics.disable_reason,
            Some(DenuoDisableReason::DuplicateOrReplay)
        );
    }

    #[test]
    fn full_packet_bound_and_timeout_are_scoped_diagnostics() {
        let now = Instant::now();
        let inbound_metrics = DenuoRuntimeMetrics::default();
        let mut inbound = coordinator(
            PeerDirection::Inbound,
            ConsensusNetwork::Regtest,
            inbound_metrics.clone(),
        );
        inbound.on_ready(now);
        let oversized = vec![0; DENUO_EXTENSION_MAX_PACKET_PAYLOAD + 1];
        assert_eq!(inbound.receive_extension(&oversized).response_payload, None);
        assert_eq!(inbound.receive_extension(&oversized).response_payload, None);
        assert_eq!(
            inbound.diagnostics.disable_reason,
            Some(DenuoDisableReason::PacketTooLarge)
        );
        let oversized_summary = inbound_metrics.summary(SERVICES, &[inbound.diagnostics()]);
        assert_eq!(oversized_summary.process.disabled, 1);
        assert_eq!(oversized_summary.process.rejected, 2);
        assert_eq!(
            oversized_summary.rejection_reasons[DenuoDisableReason::PacketTooLarge.index()].count,
            2
        );

        let metrics = DenuoRuntimeMetrics::default();
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
            DenuoRuntimeMetrics::default(),
        );
        responder.on_ready(now);
        let response = responder.receive_extension(&hello);
        let late_ack = admit(&mut responder, response);
        let deadline = outbound.pending_deadline().expect("admitted deadline");
        assert!(outbound.expire(deadline));
        outbound.receive_extension(&late_ack);
        assert_eq!(
            outbound.diagnostics.disable_reason,
            Some(DenuoDisableReason::NegotiationTimeout)
        );
        assert_eq!(metrics.summary(SERVICES, &[]).process.hello_ack_received, 0);
        assert_eq!(metrics.summary(SERVICES, &[]).process.disabled, 1);
    }
}
