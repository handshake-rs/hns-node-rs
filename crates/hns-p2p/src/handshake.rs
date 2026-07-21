//! VERSION/VERACK handshake state machine.

use serde::{Deserialize, Serialize};

use crate::{
    constants::{MIN_PROTOCOL_VERSION, SERVICE_NETWORK},
    wire::{Packet, VersionPacket},
    P2pError,
};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PeerDirection {
    Inbound,
    Outbound,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PeerState {
    Connecting,
    Handshaking,
    Ready,
    Closed,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct HandshakeUpdate {
    pub responses: Vec<Packet>,
    pub became_ready: bool,
}

#[derive(Clone, Debug)]
pub struct PeerHandshake {
    direction: PeerDirection,
    local_nonce: [u8; 8],
    local_version_sent: bool,
    remote_version: Option<VersionPacket>,
    verack_sent: bool,
    verack_received: bool,
    ready: bool,
}

impl PeerHandshake {
    pub fn new(direction: PeerDirection, local_nonce: [u8; 8]) -> Self {
        Self {
            direction,
            local_nonce,
            local_version_sent: false,
            remote_version: None,
            verack_sent: false,
            verack_received: false,
            ready: false,
        }
    }

    pub fn local_version(&mut self, version: VersionPacket) -> Result<Packet, P2pError> {
        if self.local_version_sent {
            return Err(P2pError::Protocol(
                "local VERSION was already sent".to_owned(),
            ));
        }
        if version.nonce != self.local_nonce {
            return Err(P2pError::Protocol(
                "local VERSION nonce differs from the registered self-connection nonce".to_owned(),
            ));
        }
        self.local_version_sent = true;
        Ok(Packet::Version(version))
    }

    pub fn local_version_sent(&self) -> bool {
        self.local_version_sent
    }

    pub fn remote_version(&self) -> Option<&VersionPacket> {
        self.remote_version.as_ref()
    }

    pub fn is_ready(&self) -> bool {
        self.ready
    }

    pub fn receive(&mut self, packet: &Packet) -> Result<HandshakeUpdate, P2pError> {
        let was_ready = self.ready;
        let mut responses = Vec::new();

        match packet {
            Packet::Version(version) => {
                if self.remote_version.is_some() {
                    return Err(P2pError::Protocol(
                        "peer sent a duplicate VERSION".to_owned(),
                    ));
                }
                if version.nonce == self.local_nonce {
                    return Err(P2pError::Protocol(
                        "self-connection nonce detected".to_owned(),
                    ));
                }
                if version.version < MIN_PROTOCOL_VERSION {
                    return Err(P2pError::Protocol(format!(
                        "peer protocol version {} is below minimum {}",
                        version.version, MIN_PROTOCOL_VERSION
                    )));
                }
                if self.direction == PeerDirection::Outbound
                    && version.services & SERVICE_NETWORK == 0
                {
                    return Err(P2pError::Protocol(
                        "outbound peer does not advertise network services".to_owned(),
                    ));
                }

                self.remote_version = Some(version.clone());
                if !self.verack_sent {
                    self.verack_sent = true;
                    responses.push(Packet::Verack);
                }
            }
            Packet::Verack => {
                // HSD treats duplicate VERACK packets as harmless. Preserve
                // that behavior while requiring VERSION before readiness.
                self.verack_received = true;
            }
            Packet::Ping(nonce) => responses.push(Packet::Pong(*nonce)),
            Packet::Pong(_) => {}
            _ if !self.ready => {
                return Err(P2pError::Protocol(
                    "peer sent a non-handshake packet before VERSION/VERACK completion".to_owned(),
                ));
            }
            _ => {}
        }

        self.ready = self.local_version_sent
            && self.remote_version.is_some()
            && self.verack_sent
            && self.verack_received;

        Ok(HandshakeUpdate {
            responses,
            became_ready: !was_ready && self.ready,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{constants::PROTOCOL_VERSION, wire::NetAddress};

    fn version(nonce: [u8; 8], services: u64) -> VersionPacket {
        VersionPacket {
            version: PROTOCOL_VERSION,
            services,
            time: 1,
            remote: NetAddress::default(),
            nonce,
            agent: "/test/".to_owned(),
            height: 1,
            no_relay: false,
        }
    }

    #[test]
    fn outbound_handshake_requires_network_service_and_becomes_ready() {
        let local_nonce = [1; 8];
        let mut handshake = PeerHandshake::new(PeerDirection::Outbound, local_nonce);
        assert!(matches!(
            handshake.local_version(version(local_nonce, SERVICE_NETWORK)),
            Ok(Packet::Version(_))
        ));
        let update = handshake
            .receive(&Packet::Version(version([2; 8], SERVICE_NETWORK)))
            .expect("remote version");
        assert_eq!(update.responses, vec![Packet::Verack]);
        assert!(!update.became_ready);
        let update = handshake.receive(&Packet::Verack).expect("verack");
        assert!(update.became_ready);
        assert!(handshake.is_ready());
    }

    #[test]
    fn handshake_rejects_self_connection_and_early_application_packet() {
        let local_nonce = [7; 8];
        let mut handshake = PeerHandshake::new(PeerDirection::Outbound, local_nonce);
        handshake
            .local_version(version(local_nonce, SERVICE_NETWORK))
            .expect("local version");
        assert!(matches!(
            handshake.receive(&Packet::Version(version(local_nonce, SERVICE_NETWORK))),
            Err(P2pError::Protocol(_))
        ));

        let mut inbound = PeerHandshake::new(PeerDirection::Inbound, [9; 8]);
        assert!(matches!(
            inbound.receive(&Packet::GetAddr),
            Err(P2pError::Protocol(_))
        ));
    }
}
