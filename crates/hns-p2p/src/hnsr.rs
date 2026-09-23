//! Production adapter boundary for HIP-78 requester and opaque relay state.

use std::{
    collections::{BTreeSet, HashMap, HashSet},
    net::{IpAddr, SocketAddr},
};

use hns_hnsr_protocol::{
    HnsrActionId, HnsrOpcode, HnsrPacket, HnsrPeerId, HnsrRequester, HnsrRequesterConfig,
    HnsrRequesterEvent, HnsrRequesterSnapshot, HnsrRoute, HnsrRuntimeError, HnsrRuntimeStatus,
    HnsrService, OpaqueRelayConfig, OpaqueRelayRuntime, OpaqueRelaySnapshot, QueuedHnsrRoute,
    RelayConfig, RelayLimits, RelayService, RelayTicket, DEFAULT_WINDOW, HNSR_PACKET_TYPE,
    HNSR_RELAY_SERVICE, HNS_CHAT_V1, HNS_NODE_V1, HNS_WEB_V1, MAX_CIRCUITS, MAX_CIRCUIT_QUEUE,
    MAX_PACKET_SIZE,
};
use hns_p2p_experimental::{
    ExperimentalWireProfile, HnsrPolicy, NegotiatedRegistry, Network as ExperimentalNetwork,
    HNSR_PROFILE_REGISTRY_FINGERPRINT, HNSR_PROFILE_REGISTRY_PROTOCOL_VERSION,
    HNSR_PROFILE_REGISTRY_VERSION, HNSR_PROFILE_WIRE_PROFILE, REGISTRY_NEGOTIATION_PROTOCOL_ID,
    SHAKESCAPE_EXTENSION_SERVICE, SHAKESCAPE_V1_REGISTRY_FINGERPRINT,
    SHAKESCAPE_V1_REGISTRY_PROTOCOL_VERSION, SHAKESCAPE_V1_REGISTRY_VERSION,
};
use hns_primitives::blake2b_256;

use crate::{AuthenticatedPeerKey, Packet, PacketType, PeerDirection, PeerId, PeerTransportKind};

const STATE_MAGIC: &[u8; 8] = b"HNSHRS1\0";
const FLOOR_MAGIC: &[u8; 8] = b"HNSHRF1\0";
const STATE_SCHEMA: u16 = 1;
const FLOOR_SCHEMA: u16 = 1;
const CHECKSUM_SIZE: usize = 32;
const MAXIMUM_STATE_BYTES: usize = 4_096;

/// Canonical experimental HNSR profile for opaque Shakescape swap sessions.
pub const HNS_SHAKESCAPE_SWAP_V1: u16 = 4;

pub const fn is_hnsr_packet_type(packet_type: PacketType) -> bool {
    matches!(packet_type, PacketType::Unknown(value) if value == HNSR_PACKET_TYPE)
}

pub const fn is_supported_hnsr_profile(profile: u16) -> bool {
    matches!(profile, HNS_NODE_V1 | HNS_WEB_V1 | HNS_SHAKESCAPE_SWAP_V1)
}

pub fn hnsr_peer_id(peer: PeerId) -> Result<HnsrPeerId, HnsrCoordinatorError> {
    if peer.0 == 0 {
        return Err(HnsrCoordinatorError::InvalidPeer);
    }
    HnsrPeerId::new(peer.0.to_le_bytes().to_vec()).map_err(HnsrCoordinatorError::Runtime)
}

pub fn peer_id_from_hnsr(peer: &HnsrPeerId) -> Result<PeerId, HnsrCoordinatorError> {
    let bytes: [u8; 8] = peer
        .as_bytes()
        .try_into()
        .map_err(|_| HnsrCoordinatorError::InvalidPeer)?;
    let peer = PeerId(u64::from_le_bytes(bytes));
    if peer.0 == 0 {
        return Err(HnsrCoordinatorError::InvalidPeer);
    }
    Ok(peer)
}

pub fn hnsr_packet(packet: HnsrPacket) -> Result<Packet, HnsrCoordinatorError> {
    Ok(Packet::Unknown {
        packet_type: PacketType::Unknown(HNSR_PACKET_TYPE),
        payload: packet.encode().map_err(HnsrCoordinatorError::Protocol)?,
    })
}

pub fn decode_hnsr_packet(packet: &Packet) -> Result<HnsrPacket, HnsrCoordinatorError> {
    let Packet::Unknown {
        packet_type: PacketType::Unknown(HNSR_PACKET_TYPE),
        payload,
    } = packet
    else {
        return Err(HnsrCoordinatorError::WrongPacketType);
    };
    HnsrPacket::decode(payload).map_err(HnsrCoordinatorError::Protocol)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HnsrNetworkBinding {
    pub magic: u32,
    pub network: ExperimentalNetwork,
    pub genesis_hash: [u8; 32],
}

impl HnsrNetworkBinding {
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

    const fn allows_private(self) -> bool {
        matches!(
            self.network,
            ExperimentalNetwork::Regtest | ExperimentalNetwork::Simnet
        )
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HnsrRelayBackend {
    pub advertised_address: SocketAddr,
    pub private_key: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnsrCoordinatorConfig {
    pub binding: HnsrNetworkBinding,
    pub profile: u16,
    pub configuration_hash: [u8; 32],
    pub requester_enabled: bool,
    pub opaque_relay_enabled: bool,
    pub relay_backend: Option<HnsrRelayBackend>,
    pub relay_limits: RelayLimits,
}

impl HnsrCoordinatorConfig {
    pub fn for_network(network: hns_consensus::Network) -> Self {
        Self::for_network_with_profile(network, HNS_NODE_V1)
            .expect("the canonical HNS Node profile is supported")
    }

    pub fn for_network_with_profile(
        network: hns_consensus::Network,
        profile: u16,
    ) -> Result<Self, HnsrCoordinatorError> {
        if !is_supported_hnsr_profile(profile) {
            return Err(HnsrCoordinatorError::UnsupportedProfile(profile));
        }
        let binding = HnsrNetworkBinding::for_network(network);
        let mut bytes = Vec::with_capacity(40);
        bytes.extend_from_slice(&binding.magic.to_le_bytes());
        bytes.extend_from_slice(&binding.genesis_hash);
        bytes.extend_from_slice(&profile.to_le_bytes());
        Ok(Self {
            binding,
            profile,
            configuration_hash: blake2b_256(&bytes),
            requester_enabled: true,
            opaque_relay_enabled: true,
            relay_backend: None,
            relay_limits: RelayLimits::default(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnsrPeerAdmission {
    pub peer: PeerId,
    pub address: SocketAddr,
    pub direction: PeerDirection,
    pub transport: PeerTransportKind,
    pub authenticated_remote_static: Option<AuthenticatedPeerKey>,
    pub remote_services: u64,
    pub wire_profile: ExperimentalWireProfile,
    pub negotiated: NegotiatedRegistry,
}

impl HnsrPeerAdmission {
    pub fn authenticated_key(&self) -> Result<[u8; 33], HnsrCoordinatorError> {
        self.authenticated_remote_static
            .map(AuthenticatedPeerKey::into_bytes)
            .ok_or(HnsrCoordinatorError::UnauthenticatedPeer)
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct HnsrProcessTotals {
    pub socket_write_failures: u64,
    pub expired_work: u64,
    pub rejected_packets: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnsrCoordinatorStatus {
    pub schema_version: u16,
    pub state_generation: u64,
    pub requester: HnsrRuntimeStatus,
    pub relay: HnsrRuntimeStatus,
    pub requester_default_enabled: bool,
    pub opaque_relay_default_enabled: bool,
    pub relay_service_available: bool,
    pub relay_service_advertised: bool,
    pub endpoint_role_available: bool,
    pub rendezvous_role_available: bool,
    pub plaintext_transport_available: bool,
    pub service_bit: u64,
    pub packet_type: u8,
    pub profile: u16,
    pub profile_registry_fingerprint: String,
    pub profile_registry_version: u16,
    pub profile_registry_protocol_version: u16,
    pub profile_registry_wire_profile: String,
    pub eligible_authenticated_relays: usize,
    pub faulted_peers: usize,
    pub reservations: usize,
    pub durable_state_dirty: bool,
    pub trusted_time_high_water: u64,
    pub process: HnsrProcessTotals,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HnsrIncoming {
    pub requester_event: Option<HnsrRequesterEvent>,
    pub direct_routes: Vec<HnsrRoute>,
    pub relay_routes: Vec<QueuedHnsrRoute>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HnsrPolicyUpdate {
    pub direct_routes: Vec<HnsrRoute>,
    pub relay_routes: Vec<QueuedHnsrRoute>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HnsrStateSnapshot {
    pub bytes: Vec<u8>,
    pub floor: HnsrDurableFloor,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HnsrDurableFloor {
    pub state_generation: u64,
    pub requester_generation: u64,
    pub relay_generation: u64,
    pub trusted_time_high_water: u64,
    pub network_magic: u32,
    pub configuration_hash: [u8; 32],
}

impl HnsrDurableFloor {
    pub fn encode(self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(102);
        bytes.extend_from_slice(FLOOR_MAGIC);
        bytes.extend_from_slice(&FLOOR_SCHEMA.to_le_bytes());
        bytes.extend_from_slice(&self.network_magic.to_le_bytes());
        bytes.extend_from_slice(&self.configuration_hash);
        bytes.extend_from_slice(&self.state_generation.to_le_bytes());
        bytes.extend_from_slice(&self.requester_generation.to_le_bytes());
        bytes.extend_from_slice(&self.relay_generation.to_le_bytes());
        bytes.extend_from_slice(&self.trusted_time_high_water.to_le_bytes());
        append_checksum(&mut bytes);
        bytes
    }

    pub fn decode(input: &[u8]) -> Result<Self, HnsrCoordinatorError> {
        let payload = verified_payload(input, FLOOR_MAGIC, 78)?;
        let mut reader = SliceReader::new(payload);
        reader.skip(8)?;
        if reader.u16()? != FLOOR_SCHEMA {
            return Err(HnsrCoordinatorError::UnsupportedSchema);
        }
        let floor = Self {
            network_magic: reader.u32()?,
            configuration_hash: reader.array()?,
            state_generation: reader.u64()?,
            requester_generation: reader.u64()?,
            relay_generation: reader.u64()?,
            trusted_time_high_water: reader.u64()?,
        };
        reader.finish()?;
        Ok(floor)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ContextOwner {
    Requester,
    Relay,
}

pub struct HnsrCoordinator {
    config: HnsrCoordinatorConfig,
    policy: HnsrPolicy,
    state_generation: u64,
    requester: HnsrRequester,
    relay: OpaqueRelayRuntime,
    service: HnsrService,
    contexts: HashMap<[u8; 8], ContextOwner>,
    faulted_peers: HashSet<PeerId>,
    process: HnsrProcessTotals,
    durable_state_dirty: bool,
}

impl HnsrCoordinator {
    pub fn fresh(
        config: HnsrCoordinatorConfig,
        trusted_now: u64,
    ) -> Result<Self, HnsrCoordinatorError> {
        if !is_supported_hnsr_profile(config.profile) {
            return Err(HnsrCoordinatorError::UnsupportedProfile(config.profile));
        }
        let policy = HnsrPolicy::default()
            .with_client(config.requester_enabled)
            .with_relay(config.opaque_relay_enabled)
            .with_endpoint(false)
            .with_rendezvous(false);
        let requester =
            HnsrRequester::new(fresh_session(), 1, requester_config(&config), trusted_now)?;
        let relay = OpaqueRelayRuntime::new(
            fresh_session(),
            1,
            OpaqueRelayConfig::default(),
            trusted_now,
        )?;
        let service = HnsrService::new(build_relay_service(&config)?, None);
        let mut coordinator = Self {
            config,
            policy,
            state_generation: 1,
            requester,
            relay,
            service,
            contexts: HashMap::new(),
            faulted_peers: HashSet::new(),
            process: HnsrProcessTotals::default(),
            durable_state_dirty: true,
        };
        coordinator.apply_policy_ceilings()?;
        Ok(coordinator)
    }

    pub fn restore(
        config: HnsrCoordinatorConfig,
        state: &[u8],
        floor: HnsrDurableFloor,
        trusted_now: u64,
    ) -> Result<Self, HnsrCoordinatorError> {
        if !is_supported_hnsr_profile(config.profile) {
            return Err(HnsrCoordinatorError::UnsupportedProfile(config.profile));
        }
        if floor.network_magic != config.binding.magic
            || floor.configuration_hash != config.configuration_hash
            || trusted_now < floor.trusted_time_high_water
        {
            return Err(HnsrCoordinatorError::DurableFloorMismatch);
        }
        let decoded = decode_state(state, &config)?;
        if decoded.state_generation < floor.state_generation
            || decoded.trusted_time_high_water < floor.trusted_time_high_water
        {
            return Err(HnsrCoordinatorError::DurableFloorMismatch);
        }
        let requester_snapshot = HnsrRequesterSnapshot::decode(&decoded.requester)?;
        let relay_snapshot = OpaqueRelaySnapshot::decode(&decoded.relay)?;
        let requester = HnsrRequester::restore(
            requester_snapshot,
            fresh_session(),
            floor.requester_generation,
            trusted_now,
        )?;
        let relay = OpaqueRelayRuntime::restore(
            relay_snapshot,
            fresh_session(),
            floor.relay_generation,
            trusted_now,
        )?;
        let service = HnsrService::new(build_relay_service(&config)?, None);
        let policy = HnsrPolicy::disabled()
            .with_client(decoded.requester_enabled)
            .with_relay(decoded.relay_enabled);
        let mut coordinator = Self {
            config,
            policy,
            state_generation: decoded
                .state_generation
                .checked_add(1)
                .ok_or(HnsrCoordinatorError::GenerationExhausted)?,
            requester,
            relay,
            service,
            contexts: HashMap::new(),
            faulted_peers: HashSet::new(),
            process: decoded.process,
            durable_state_dirty: true,
        };
        coordinator.apply_policy_ceilings()?;
        Ok(coordinator)
    }

    pub fn policy(&self) -> HnsrPolicy {
        self.policy
    }

    pub fn relay_service_advertised(&self) -> bool {
        self.policy.has_relay() && self.service.relay().is_some()
    }

    pub fn status(&self, eligible_authenticated_relays: usize) -> HnsrCoordinatorStatus {
        let requester = self.requester.status();
        let relay = self.relay.status();
        HnsrCoordinatorStatus {
            schema_version: STATE_SCHEMA,
            state_generation: self.state_generation,
            requester,
            relay,
            requester_default_enabled: true,
            opaque_relay_default_enabled: true,
            relay_service_available: self.service.relay().is_some() && relay.enabled,
            relay_service_advertised: self.relay_service_advertised(),
            endpoint_role_available: false,
            rendezvous_role_available: false,
            plaintext_transport_available: false,
            service_bit: HNSR_RELAY_SERVICE,
            packet_type: HNSR_PACKET_TYPE,
            profile: self.config.profile,
            profile_registry_fingerprint: HNSR_PROFILE_REGISTRY_FINGERPRINT.to_string(),
            profile_registry_version: HNSR_PROFILE_REGISTRY_VERSION,
            profile_registry_protocol_version: HNSR_PROFILE_REGISTRY_PROTOCOL_VERSION,
            profile_registry_wire_profile: HNSR_PROFILE_WIRE_PROFILE.to_owned(),
            eligible_authenticated_relays,
            faulted_peers: self.faulted_peers.len(),
            reservations: self.service.relay().map_or(0, |service| service.len()),
            durable_state_dirty: self.durable_state_dirty,
            trusted_time_high_water: requester
                .trusted_time_high_water
                .max(relay.trusted_time_high_water),
            process: self.process,
        }
    }

    pub fn admit_requester_relay(
        &self,
        peer: &HnsrPeerAdmission,
    ) -> Result<(), HnsrCoordinatorError> {
        self.ensure_peer(peer, true)
    }

    pub fn admit_inbound_relay_peer(
        &self,
        peer: &HnsrPeerAdmission,
    ) -> Result<(), HnsrCoordinatorError> {
        self.ensure_peer(peer, false)
    }

    pub fn begin_open(
        &mut self,
        relay: &HnsrPeerAdmission,
        ticket: RelayTicket,
        now: u64,
        deadline: u64,
        initial_window: u32,
    ) -> Result<HnsrRoute, HnsrCoordinatorError> {
        self.ensure_peer(relay, true)?;
        let route = self.requester.begin_open(
            hnsr_peer_id(relay.peer)?,
            relay.authenticated_key()?,
            ticket,
            now,
            deadline,
            initial_window,
        )?;
        self.contexts
            .insert(route.packet.context_id, ContextOwner::Requester);
        self.mark_dirty();
        Ok(route)
    }

    pub fn begin_open_default_window(
        &mut self,
        relay: &HnsrPeerAdmission,
        ticket: RelayTicket,
        now: u64,
        deadline: u64,
    ) -> Result<HnsrRoute, HnsrCoordinatorError> {
        self.begin_open(relay, ticket, now, deadline, DEFAULT_WINDOW)
    }

    pub fn send_data(
        &mut self,
        circuit_id: [u8; 8],
        bytes: Vec<u8>,
    ) -> Result<HnsrRoute, HnsrCoordinatorError> {
        let route = self
            .requester
            .send_data(circuit_id, bytes)
            .map_err(HnsrCoordinatorError::Runtime)?;
        self.mark_dirty();
        Ok(route)
    }

    pub fn take_data(
        &mut self,
        circuit_id: [u8; 8],
    ) -> Result<(Vec<u8>, HnsrRoute), HnsrCoordinatorError> {
        let result = self
            .requester
            .take_data(circuit_id)
            .map_err(HnsrCoordinatorError::Runtime)?;
        self.mark_dirty();
        Ok(result)
    }

    pub fn close(
        &mut self,
        circuit_id: [u8; 8],
        reason: u16,
    ) -> Result<HnsrRoute, HnsrCoordinatorError> {
        self.contexts.remove(&circuit_id);
        let route = self
            .requester
            .close(circuit_id, reason, "local requester closed")
            .map_err(HnsrCoordinatorError::Runtime)?;
        self.mark_dirty();
        Ok(route)
    }

    pub fn cancel_open(&mut self, context_id: [u8; 8]) -> Result<HnsrRoute, HnsrCoordinatorError> {
        self.contexts.remove(&context_id);
        let route = self
            .requester
            .cancel_open(context_id, 0, "local requester cancelled")
            .map_err(HnsrCoordinatorError::Runtime)?;
        self.mark_dirty();
        Ok(route)
    }

    pub fn handle_encoded(
        &mut self,
        source: &HnsrPeerAdmission,
        payload: &[u8],
        now: u64,
    ) -> Result<HnsrIncoming, HnsrCoordinatorError> {
        if payload.len() > MAX_PACKET_SIZE {
            return Err(HnsrCoordinatorError::PacketTooLarge);
        }
        let packet = HnsrPacket::decode(payload)?;
        self.handle(source, &packet, now)
    }

    pub fn handle(
        &mut self,
        source: &HnsrPeerAdmission,
        packet: &HnsrPacket,
        now: u64,
    ) -> Result<HnsrIncoming, HnsrCoordinatorError> {
        let source_id = hnsr_peer_id(source.peer)?;
        let owner = self.contexts.get(&packet.context_id).copied();
        let result = match packet.opcode {
            HnsrOpcode::Reserve
            | HnsrOpcode::Renew
            | HnsrOpcode::Confirm
            | HnsrOpcode::Withdraw => {
                self.ensure_peer(source, false)?;
                if !self.policy.has_relay() {
                    return Err(HnsrCoordinatorError::RoleUnavailable);
                }
                let response = self
                    .service
                    .handle(packet, &peer_source(source.peer), now)?;
                HnsrIncoming {
                    direct_routes: response
                        .map(|packet| HnsrRoute {
                            destination: source_id,
                            packet,
                        })
                        .into_iter()
                        .collect(),
                    ..HnsrIncoming::default()
                }
            }
            HnsrOpcode::Open | HnsrOpcode::Accept => {
                self.ensure_peer(source, false)?;
                if !self.policy.has_relay() {
                    return Err(HnsrCoordinatorError::RoleUnavailable);
                }
                let reservations = self
                    .service
                    .relay()
                    .ok_or(HnsrCoordinatorError::RoleUnavailable)?;
                let routes = self.relay.handle(reservations, &source_id, packet, now)?;
                self.contexts.insert(packet.context_id, ContextOwner::Relay);
                for route in &routes {
                    self.contexts
                        .insert(route.route.packet.context_id, ContextOwner::Relay);
                }
                HnsrIncoming {
                    relay_routes: routes,
                    ..HnsrIncoming::default()
                }
            }
            HnsrOpcode::Opened => {
                self.ensure_peer(source, true)?;
                if owner != Some(ContextOwner::Requester) {
                    return Err(HnsrCoordinatorError::AmbiguousContext);
                }
                let event = self.requester.handle(&source_id, packet, now)?;
                self.contexts.remove(&packet.context_id);
                if let Some(HnsrRequesterEvent::Opened { circuit_id, .. }) = event.as_ref() {
                    self.contexts.insert(*circuit_id, ContextOwner::Requester);
                }
                HnsrIncoming {
                    requester_event: event,
                    ..HnsrIncoming::default()
                }
            }
            HnsrOpcode::Data | HnsrOpcode::Window | HnsrOpcode::Close | HnsrOpcode::Error => {
                match owner.ok_or(HnsrCoordinatorError::AmbiguousContext)? {
                    ContextOwner::Requester => {
                        self.ensure_peer(source, true)?;
                        let event = self.requester.handle(&source_id, packet, now)?;
                        if matches!(packet.opcode, HnsrOpcode::Close | HnsrOpcode::Error) {
                            self.contexts.remove(&packet.context_id);
                        }
                        HnsrIncoming {
                            requester_event: event,
                            ..HnsrIncoming::default()
                        }
                    }
                    ContextOwner::Relay => {
                        self.ensure_peer(source, false)?;
                        let reservations = self
                            .service
                            .relay()
                            .ok_or(HnsrCoordinatorError::RoleUnavailable)?;
                        let routes = self.relay.handle(reservations, &source_id, packet, now)?;
                        if matches!(packet.opcode, HnsrOpcode::Close | HnsrOpcode::Error) {
                            self.contexts.remove(&packet.context_id);
                        }
                        HnsrIncoming {
                            relay_routes: routes,
                            ..HnsrIncoming::default()
                        }
                    }
                }
            }
            HnsrOpcode::Incoming => return Err(HnsrCoordinatorError::RoleUnavailable),
            HnsrOpcode::Offer | HnsrOpcode::Confirmed => {
                return Err(HnsrCoordinatorError::RoleUnavailable)
            }
            _ => return Err(HnsrCoordinatorError::RendezvousUnavailable),
        };
        self.mark_dirty();
        Ok(result)
    }

    pub fn acknowledge_relay_action(
        &mut self,
        action_id: HnsrActionId,
        delivered: bool,
    ) -> Result<Vec<QueuedHnsrRoute>, HnsrCoordinatorError> {
        if !delivered {
            self.process.socket_write_failures =
                self.process.socket_write_failures.saturating_add(1);
        }
        let routes = self.relay.acknowledge(action_id, delivered)?;
        self.mark_dirty();
        Ok(routes)
    }

    pub fn disconnect(&mut self, peer: PeerId) -> Vec<QueuedHnsrRoute> {
        let routes = self.disconnect_work(peer);
        self.faulted_peers.remove(&peer);
        routes
    }

    fn disconnect_work(&mut self, peer: PeerId) -> Vec<QueuedHnsrRoute> {
        let Ok(peer_id) = hnsr_peer_id(peer) else {
            return Vec::new();
        };
        self.requester.disconnect(&peer_id);
        let reservations = self
            .service
            .relay_mut()
            .map(|service| service.disconnect(&peer_source(peer)))
            .unwrap_or_default();
        let mut routes = self.relay.disconnect(&peer_id);
        for reservation in reservations {
            routes.extend(self.relay.revoke_reservation(reservation));
        }
        // Context ownership is connection authority. A disconnect clears the
        // small bounded index globally rather than risk retaining an entry
        // whose upstream circuit was revoked during cross-peer cleanup.
        self.contexts.clear();
        self.mark_dirty();
        routes
    }

    pub fn fault_peer(&mut self, peer: PeerId) -> Vec<QueuedHnsrRoute> {
        self.faulted_peers.insert(peer);
        self.process.rejected_packets = self.process.rejected_packets.saturating_add(1);
        self.disconnect_work(peer)
    }

    pub fn expire(
        &mut self,
        trusted_now: u64,
    ) -> Result<Vec<QueuedHnsrRoute>, HnsrCoordinatorError> {
        let before = self.requester.status().pending_circuits
            + self.requester.status().active_circuits
            + self.relay.status().pending_circuits
            + self.relay.status().active_circuits;
        self.requester.expire(trusted_now)?;
        if let Some(service) = self.service.relay_mut() {
            service.prune(trusted_now);
        }
        let routes = self.relay.expire(trusted_now)?;
        let after = self.requester.status().pending_circuits
            + self.requester.status().active_circuits
            + self.relay.status().pending_circuits
            + self.relay.status().active_circuits;
        self.process.expired_work = self
            .process
            .expired_work
            .saturating_add(u64::try_from(before.saturating_sub(after)).unwrap_or(u64::MAX));
        if before != after || !routes.is_empty() {
            self.mark_dirty();
        }
        Ok(routes)
    }

    pub fn replace_policy(
        &mut self,
        expected_state_generation: u64,
        policy: HnsrPolicy,
    ) -> Result<HnsrPolicyUpdate, HnsrCoordinatorError> {
        if expected_state_generation != self.state_generation {
            return Err(HnsrCoordinatorError::StaleGeneration);
        }
        if policy.has_endpoint() || policy.has_rendezvous() {
            return Err(HnsrCoordinatorError::RoleUnavailable);
        }
        self.state_generation = self
            .state_generation
            .checked_add(1)
            .ok_or(HnsrCoordinatorError::GenerationExhausted)?;
        let requester_enabled = policy.has_client() && self.config.requester_enabled;
        let relay_enabled = policy.has_relay() && self.config.opaque_relay_enabled;
        let direct_routes = self
            .requester
            .replace_enabled(self.requester.status().generation, requester_enabled)?;
        let relay_routes = self
            .relay
            .replace_enabled(self.relay.status().generation, relay_enabled)?;
        self.policy = policy
            .with_client(requester_enabled)
            .with_relay(relay_enabled)
            .with_endpoint(false)
            .with_rendezvous(false);
        self.durable_state_dirty = true;
        Ok(HnsrPolicyUpdate {
            direct_routes,
            relay_routes,
        })
    }

    pub fn snapshot_bundle(
        &mut self,
        trusted_now: u64,
    ) -> Result<HnsrStateSnapshot, HnsrCoordinatorError> {
        self.requester.observe_time(trusted_now)?;
        self.relay.observe_time(trusted_now)?;
        let requester = self.requester.snapshot().encode();
        let relay = self.relay.snapshot().encode();
        let floor = HnsrDurableFloor {
            state_generation: self.state_generation,
            requester_generation: self.requester.status().generation,
            relay_generation: self.relay.status().generation,
            trusted_time_high_water: trusted_now,
            network_magic: self.config.binding.magic,
            configuration_hash: self.config.configuration_hash,
        };
        let bytes = encode_state(
            &self.config,
            self.state_generation,
            self.policy,
            trusted_now,
            self.process,
            &requester,
            &relay,
        )?;
        Ok(HnsrStateSnapshot { bytes, floor })
    }

    pub fn acknowledge_persisted(&mut self, floor: HnsrDurableFloor) {
        let status = self.status(0);
        if floor.state_generation == status.state_generation
            && floor.requester_generation == status.requester.generation
            && floor.relay_generation == status.relay.generation
            && floor.network_magic == self.config.binding.magic
            && floor.configuration_hash == self.config.configuration_hash
        {
            self.durable_state_dirty = false;
        }
    }

    fn ensure_peer(
        &self,
        peer: &HnsrPeerAdmission,
        require_relay_service: bool,
    ) -> Result<(), HnsrCoordinatorError> {
        if self.faulted_peers.contains(&peer.peer)
            || peer.transport != PeerTransportKind::Brontide
            || peer.authenticated_remote_static.is_none()
        {
            return Err(HnsrCoordinatorError::UnauthenticatedPeer);
        }
        if peer.remote_services & SHAKESCAPE_EXTENSION_SERVICE.value() == 0
            || (require_relay_service && peer.remote_services & HNSR_RELAY_SERVICE == 0)
            || peer.wire_profile != ExperimentalWireProfile::ShakescapeV1
            || peer.negotiated.fingerprint != SHAKESCAPE_V1_REGISTRY_FINGERPRINT
            || peer.negotiated.registry_version != SHAKESCAPE_V1_REGISTRY_VERSION
            || !peer.negotiated.protocols.contains(&(
                REGISTRY_NEGOTIATION_PROTOCOL_ID,
                SHAKESCAPE_V1_REGISTRY_PROTOCOL_VERSION,
            ))
            || peer.negotiated.network != self.config.binding.network
            || peer.negotiated.genesis_hash != self.config.binding.genesis_hash
            || peer.negotiated.maximum_send_size == 0
            || peer.negotiated.maximum_live_requests == 0
        {
            return Err(HnsrCoordinatorError::RegistryNotNegotiated);
        }
        Ok(())
    }

    fn apply_policy_ceilings(&mut self) -> Result<(), HnsrCoordinatorError> {
        let requester_enabled = self.policy.has_client() && self.config.requester_enabled;
        let relay_enabled = self.policy.has_relay() && self.config.opaque_relay_enabled;
        if self.requester.status().enabled != requester_enabled {
            let _ = self
                .requester
                .replace_enabled(self.requester.status().generation, requester_enabled)?;
        }
        if self.relay.status().enabled != relay_enabled {
            let _ = self
                .relay
                .replace_enabled(self.relay.status().generation, relay_enabled)?;
        }
        self.policy = HnsrPolicy::disabled()
            .with_client(requester_enabled)
            .with_relay(relay_enabled);
        Ok(())
    }

    fn mark_dirty(&mut self) {
        // A write that races durable publication must leave the coordinator
        // dirty. The generation is therefore a mutation sequence, not merely
        // a policy sequence.
        self.state_generation = self.state_generation.saturating_add(1);
        self.durable_state_dirty = true;
    }
}

fn requester_config(config: &HnsrCoordinatorConfig) -> HnsrRequesterConfig {
    HnsrRequesterConfig {
        network_magic: config.binding.magic,
        profile: config.profile,
        allow_private_relay: config.binding.allows_private(),
        maximum_circuits: MAX_CIRCUITS,
        maximum_queue_bytes: MAX_CIRCUIT_QUEUE,
        maximum_bytes_per_circuit: config.relay_limits.maximum_bytes_per_circuit,
    }
}

fn build_relay_service(
    config: &HnsrCoordinatorConfig,
) -> Result<Option<RelayService>, HnsrCoordinatorError> {
    let Some(backend) = config.relay_backend else {
        return Ok(None);
    };
    let (host_type, host) = match backend.advertised_address.ip() {
        IpAddr::V4(address) => {
            let mut host = [0_u8; 16];
            host[10] = 0xff;
            host[11] = 0xff;
            host[12..].copy_from_slice(&address.octets());
            (1, host)
        }
        IpAddr::V6(address) => (2, address.octets()),
    };
    let relay = RelayService::new(
        RelayConfig {
            network_magic: config.binding.magic,
            transport: 0,
            host_type,
            host,
            port: backend.advertised_address.port(),
            allow_private_address: config.binding.allows_private(),
            // The relay never interprets circuit payloads. Admit every
            // canonical profile independently from the node's own requester
            // profile so one ordinary relay can carry mobile swap and chat
            // sessions without assuming either endpoint role.
            supported_profiles: BTreeSet::from([
                HNS_NODE_V1,
                HNS_WEB_V1,
                HNS_CHAT_V1,
                HNS_SHAKESCAPE_SWAP_V1,
            ]),
            limits: config.relay_limits,
        },
        backend.private_key,
    )?;
    Ok(Some(relay))
}

/// Validate one operator-advertised HNSR relay socket against the exact
/// network address policy used when the live relay service is constructed.
///
/// This is intentionally available to embedding configuration validators so
/// `--check-config` can reject an unusable public relay address before any
/// listener, store, or peer runtime is opened.
pub fn validate_hnsr_relay_address(
    network: hns_consensus::Network,
    advertised_address: SocketAddr,
) -> Result<(), HnsrCoordinatorError> {
    let mut config = HnsrCoordinatorConfig::for_network(network);
    config.relay_backend = Some(HnsrRelayBackend {
        advertised_address,
        // `1` is a valid secp256k1 scalar. This key is validation-only and is
        // never retained, advertised, or used by a live relay.
        private_key: {
            let mut key = [0_u8; 32];
            key[31] = 1;
            key
        },
    });
    let _ = build_relay_service(&config)?;
    Ok(())
}

fn fresh_session() -> [u8; 16] {
    loop {
        let session = rand::random::<[u8; 16]>();
        if session != [0; 16] {
            return session;
        }
    }
}

fn peer_source(peer: PeerId) -> String {
    format!("{:016x}", peer.0)
}

struct DecodedState {
    state_generation: u64,
    requester_enabled: bool,
    relay_enabled: bool,
    trusted_time_high_water: u64,
    process: HnsrProcessTotals,
    requester: Vec<u8>,
    relay: Vec<u8>,
}

fn encode_state(
    config: &HnsrCoordinatorConfig,
    state_generation: u64,
    policy: HnsrPolicy,
    trusted_time: u64,
    process: HnsrProcessTotals,
    requester: &[u8],
    relay: &[u8],
) -> Result<Vec<u8>, HnsrCoordinatorError> {
    let mut bytes = Vec::with_capacity(160 + requester.len() + relay.len());
    bytes.extend_from_slice(STATE_MAGIC);
    bytes.extend_from_slice(&STATE_SCHEMA.to_le_bytes());
    bytes.extend_from_slice(&config.binding.magic.to_le_bytes());
    bytes.extend_from_slice(&config.configuration_hash);
    bytes.extend_from_slice(&state_generation.to_le_bytes());
    bytes.push(u8::from(policy.has_client()));
    bytes.push(u8::from(policy.has_relay()));
    bytes.extend_from_slice(&trusted_time.to_le_bytes());
    bytes.extend_from_slice(&process.socket_write_failures.to_le_bytes());
    bytes.extend_from_slice(&process.expired_work.to_le_bytes());
    bytes.extend_from_slice(&process.rejected_packets.to_le_bytes());
    bytes.extend_from_slice(
        &u32::try_from(requester.len())
            .map_err(|_| HnsrCoordinatorError::SnapshotTooLarge)?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(
        &u32::try_from(relay.len())
            .map_err(|_| HnsrCoordinatorError::SnapshotTooLarge)?
            .to_le_bytes(),
    );
    bytes.extend_from_slice(requester);
    bytes.extend_from_slice(relay);
    if bytes.len().saturating_add(CHECKSUM_SIZE) > MAXIMUM_STATE_BYTES {
        return Err(HnsrCoordinatorError::SnapshotTooLarge);
    }
    append_checksum(&mut bytes);
    Ok(bytes)
}

fn decode_state(
    input: &[u8],
    config: &HnsrCoordinatorConfig,
) -> Result<DecodedState, HnsrCoordinatorError> {
    if input.len() > MAXIMUM_STATE_BYTES {
        return Err(HnsrCoordinatorError::SnapshotTooLarge);
    }
    let payload = verified_payload(input, STATE_MAGIC, 102)?;
    let mut reader = SliceReader::new(payload);
    reader.skip(8)?;
    if reader.u16()? != STATE_SCHEMA {
        return Err(HnsrCoordinatorError::UnsupportedSchema);
    }
    if reader.u32()? != config.binding.magic || reader.array::<32>()? != config.configuration_hash {
        return Err(HnsrCoordinatorError::ConfigurationMismatch);
    }
    let state_generation = reader.u64()?;
    let requester_enabled = reader.boolean()?;
    let relay_enabled = reader.boolean()?;
    let trusted_time_high_water = reader.u64()?;
    let process = HnsrProcessTotals {
        socket_write_failures: reader.u64()?,
        expired_work: reader.u64()?,
        rejected_packets: reader.u64()?,
    };
    let requester_len =
        usize::try_from(reader.u32()?).map_err(|_| HnsrCoordinatorError::CorruptSnapshot)?;
    let relay_len =
        usize::try_from(reader.u32()?).map_err(|_| HnsrCoordinatorError::CorruptSnapshot)?;
    let requester = reader.bytes(requester_len)?.to_vec();
    let relay = reader.bytes(relay_len)?.to_vec();
    reader.finish()?;
    Ok(DecodedState {
        state_generation,
        requester_enabled,
        relay_enabled,
        trusted_time_high_water,
        process,
        requester,
        relay,
    })
}

fn append_checksum(bytes: &mut Vec<u8>) {
    let checksum = blake2b_256(bytes);
    bytes.extend_from_slice(&checksum);
}

fn verified_payload<'a>(
    input: &'a [u8],
    magic: &[u8; 8],
    minimum_payload: usize,
) -> Result<&'a [u8], HnsrCoordinatorError> {
    if input.len() < minimum_payload.saturating_add(CHECKSUM_SIZE) {
        return Err(HnsrCoordinatorError::CorruptSnapshot);
    }
    let split = input.len() - CHECKSUM_SIZE;
    let (payload, checksum) = input.split_at(split);
    if !payload.starts_with(magic) || blake2b_256(payload).as_slice() != checksum {
        return Err(HnsrCoordinatorError::CorruptSnapshot);
    }
    Ok(payload)
}

struct SliceReader<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> SliceReader<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn bytes(&mut self, count: usize) -> Result<&'a [u8], HnsrCoordinatorError> {
        let end = self
            .position
            .checked_add(count)
            .filter(|end| *end <= self.input.len())
            .ok_or(HnsrCoordinatorError::CorruptSnapshot)?;
        let bytes = &self.input[self.position..end];
        self.position = end;
        Ok(bytes)
    }

    fn skip(&mut self, count: usize) -> Result<(), HnsrCoordinatorError> {
        self.bytes(count).map(|_| ())
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], HnsrCoordinatorError> {
        self.bytes(N)?
            .try_into()
            .map_err(|_| HnsrCoordinatorError::CorruptSnapshot)
    }

    fn u16(&mut self) -> Result<u16, HnsrCoordinatorError> {
        Ok(u16::from_le_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, HnsrCoordinatorError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, HnsrCoordinatorError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    fn boolean(&mut self) -> Result<bool, HnsrCoordinatorError> {
        match self.bytes(1)?[0] {
            0 => Ok(false),
            1 => Ok(true),
            _ => Err(HnsrCoordinatorError::CorruptSnapshot),
        }
    }

    fn finish(self) -> Result<(), HnsrCoordinatorError> {
        if self.position == self.input.len() {
            Ok(())
        } else {
            Err(HnsrCoordinatorError::CorruptSnapshot)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HnsrCoordinatorError {
    #[error(transparent)]
    Protocol(#[from] hns_hnsr_protocol::HnsrProtocolError),
    #[error(transparent)]
    Runtime(#[from] HnsrRuntimeError),
    #[error("HNSR requires an authenticated Brontide peer")]
    UnauthenticatedPeer,
    #[error("HNSR requires exact canonical Shakescape V1 negotiation")]
    RegistryNotNegotiated,
    #[error(
        "unsupported HNSR profile {0}; expected HNS_NODE_V1, HNS_WEB_V1, or HNS_SHAKESCAPE_SWAP_V1"
    )]
    UnsupportedProfile(u16),
    #[error("HNSR role is unavailable")]
    RoleUnavailable,
    #[error("HNSR rendezvous role is unavailable")]
    RendezvousUnavailable,
    #[error("HNSR context ownership is absent or ambiguous")]
    AmbiguousContext,
    #[error("invalid HNSR peer identity")]
    InvalidPeer,
    #[error("wrong packet type for HNSR")]
    WrongPacketType,
    #[error("HNSR packet exceeds its exact bound")]
    PacketTooLarge,
    #[error("corrupt HNSR durable snapshot")]
    CorruptSnapshot,
    #[error("unsupported HNSR durable snapshot schema")]
    UnsupportedSchema,
    #[error("HNSR durable configuration or network mismatch")]
    ConfigurationMismatch,
    #[error("HNSR durable floor mismatch or rollback")]
    DurableFloorMismatch,
    #[error("HNSR durable snapshot exceeds its hard bound")]
    SnapshotTooLarge,
    #[error("stale HNSR coordinator generation")]
    StaleGeneration,
    #[error("HNSR coordinator generation exhausted")]
    GenerationExhausted,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use hns_consensus::Network;
    use hns_hnsr_protocol::{
        public_key, AcceptBody, DataBody, EndpointReservation, HnsrOpcode, HnsrPacket, HnsrPeerId,
        HnsrRequester, HnsrRequesterConfig, HnsrRequesterEvent, OpaqueRelayConfig,
        OpaqueRelayRuntime,
    };

    use super::*;

    #[test]
    fn ordinary_relay_accepts_the_canonical_mobile_swap_profile() {
        let relay_private = [7_u8; 32];
        let mut config = HnsrCoordinatorConfig::for_network(Network::Regtest);
        config.relay_backend = Some(HnsrRelayBackend {
            advertised_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 14_039),
            private_key: relay_private,
        });
        let relay = build_relay_service(&config)
            .expect("relay configuration")
            .expect("enabled relay");
        let mut relay = HnsrService::new(Some(relay), None);
        let relay_key = public_key(&relay_private).expect("relay public key");
        let endpoint =
            EndpointReservation::new(config.binding.magic, HNS_SHAKESCAPE_SWAP_V1, [9_u8; 32])
                .expect("swap endpoint");
        let reserve = endpoint
            .reserve(&relay_key, [1_u8; 8], 300, 1, 65_536, [2_u8; 16])
            .expect("signed reservation");
        let offer = relay
            .handle_encoded(
                &reserve.encode().expect("reservation encoding"),
                "phone-a",
                1_700_000_000,
            )
            .expect("relay admission")
            .expect("relay offer");
        let offer = HnsrPacket::decode(&offer).expect("relay offer encoding");
        assert_eq!(offer.opcode, HnsrOpcode::Offer);
    }

    #[test]
    fn mobile_swap_profile_routes_opaque_fixture_end_to_end() {
        const NOW: u64 = 1_700_000_000;
        const SWAP_CIPHERTEXT_FIXTURE: &[u8] = &[
            0x53, 0x68, 0x61, 0x6b, 0x65, 0x53, 0x63, 0x61, 0x70, 0x65, 0x00, 0x04, 0xa5, 0x7c,
            0x19, 0xe2, 0x41, 0x8b, 0x03, 0xff, 0x62, 0xd0, 0x9a, 0x11,
        ];

        let peer = |name: &str| HnsrPeerId::new(name.as_bytes().to_vec()).expect("peer ID");
        let relay_private = [7_u8; 32];
        let mut config = HnsrCoordinatorConfig::for_network(Network::Regtest);
        config.relay_backend = Some(HnsrRelayBackend {
            advertised_address: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 14_039),
            private_key: relay_private,
        });
        let relay_service = build_relay_service(&config)
            .expect("relay configuration")
            .expect("enabled relay");
        let relay_key = public_key(&relay_private).expect("relay public key");
        let endpoint =
            EndpointReservation::new(config.binding.magic, HNS_SHAKESCAPE_SWAP_V1, [9_u8; 32])
                .expect("swap endpoint");
        let reserve = endpoint
            .reserve(&relay_key, [1_u8; 8], 300, 1, 65_536, [2_u8; 16])
            .expect("signed reservation");
        let mut service = HnsrService::new(Some(relay_service), None);
        let offer = service
            .handle(&reserve, "endpoint", NOW)
            .expect("reservation admitted")
            .expect("relay offer");
        let (confirmation, ticket) = endpoint
            .confirm_offer(&offer, &relay_key, NOW, true)
            .expect("offer confirmation");
        let confirmed = service
            .handle(&confirmation, "endpoint", NOW)
            .expect("confirmation admitted")
            .expect("confirmed reservation");
        let ticket = endpoint
            .accept_confirmation(&confirmed, ticket)
            .expect("relay ticket");

        let relay_peer = peer("relay");
        let requester_peer = peer("requester");
        let endpoint_peer = peer("endpoint");
        let mut requester = HnsrRequester::new(
            [3_u8; 16],
            1,
            HnsrRequesterConfig {
                network_magic: config.binding.magic,
                profile: HNS_SHAKESCAPE_SWAP_V1,
                allow_private_relay: true,
                maximum_circuits: 4,
                maximum_queue_bytes: MAX_CIRCUIT_QUEUE,
                maximum_bytes_per_circuit: 65_536,
            },
            NOW,
        )
        .expect("swap requester");
        let open = requester
            .begin_open(
                relay_peer.clone(),
                ticket.relay_key,
                ticket,
                NOW,
                NOW + 5,
                DEFAULT_WINDOW,
            )
            .expect("open swap circuit");
        let mut relay = OpaqueRelayRuntime::new([4_u8; 16], 1, OpaqueRelayConfig::default(), NOW)
            .expect("opaque relay runtime");
        let incoming = relay
            .handle(
                service.relay().expect("relay reservation service"),
                &requester_peer,
                &open.packet,
                NOW,
            )
            .expect("route circuit open")
            .pop()
            .expect("incoming endpoint route");
        assert_eq!(incoming.route.destination, endpoint_peer);
        relay
            .acknowledge(incoming.action_id, true)
            .expect("incoming route delivered");

        let accept = HnsrPacket::new(
            HnsrOpcode::Accept,
            incoming.route.packet.context_id,
            AcceptBody {
                accepted_window: DEFAULT_WINDOW,
                endpoint_nonce: [5_u8; 16],
            }
            .encode()
            .expect("accept body"),
        )
        .expect("accept packet");
        let opened = relay
            .handle(
                service.relay().expect("relay reservation service"),
                &endpoint_peer,
                &accept,
                NOW + 1,
            )
            .expect("route circuit acceptance")
            .pop()
            .expect("opened requester route");
        assert_eq!(opened.route.destination, requester_peer);
        relay
            .acknowledge(opened.action_id, true)
            .expect("opened route delivered");
        let opened_event = requester
            .handle(&relay_peer, &opened.route.packet, NOW + 1)
            .expect("requester accepts opened circuit")
            .expect("opened requester event");
        let HnsrRequesterEvent::Opened { circuit_id, .. } = opened_event else {
            panic!("unexpected requester event");
        };

        let outbound = requester
            .send_data(circuit_id, SWAP_CIPHERTEXT_FIXTURE.to_vec())
            .expect("send opaque swap fixture");
        let forwarded = relay
            .handle(
                service.relay().expect("relay reservation service"),
                &requester_peer,
                &outbound.packet,
                NOW + 1,
            )
            .expect("forward opaque swap fixture")
            .pop()
            .expect("endpoint data route");
        assert_eq!(forwarded.route.destination, endpoint_peer);
        assert_eq!(
            DataBody::decode(&forwarded.route.packet.body)
                .expect("forwarded data body")
                .bytes,
            SWAP_CIPHERTEXT_FIXTURE
        );
        relay
            .acknowledge(forwarded.action_id, true)
            .expect("fixture delivered");

        let response_fixture = SWAP_CIPHERTEXT_FIXTURE
            .iter()
            .rev()
            .copied()
            .collect::<Vec<_>>();
        let response = HnsrPacket::new(
            HnsrOpcode::Data,
            circuit_id,
            DataBody {
                bytes: response_fixture.clone(),
            }
            .encode()
            .expect("response body"),
        )
        .expect("response packet");
        let returned = relay
            .handle(
                service.relay().expect("relay reservation service"),
                &endpoint_peer,
                &response,
                NOW + 1,
            )
            .expect("return opaque swap fixture")
            .pop()
            .expect("requester data route");
        relay
            .acknowledge(returned.action_id, true)
            .expect("response delivered");
        let event = requester
            .handle(&relay_peer, &returned.route.packet, NOW + 1)
            .expect("requester accepts returned data")
            .expect("returned data event");
        assert!(matches!(
            event,
            HnsrRequesterEvent::DataAvailable {
                circuit_id: observed,
                queued_bytes,
            } if observed == circuit_id && queued_bytes == response_fixture.len()
        ));
        let (received, _) = requester
            .take_data(circuit_id)
            .expect("consume returned fixture");
        assert_eq!(received, response_fixture);
    }
}
