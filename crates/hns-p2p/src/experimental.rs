//! Adapter-ready authenticated transport for bounded extension exchanges.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use tokio::{sync::oneshot, time::Instant};

use crate::{AuthenticatedPeerKey, PacketType, PeerId};

pub const MAXIMUM_EXPERIMENTAL_EXCHANGES: usize = 64;

#[derive(Debug)]
pub struct ExperimentalExchange {
    pub peer_key: AuthenticatedPeerKey,
    pub packet_type: PacketType,
    pub payload: Vec<u8>,
    pub deadline: Instant,
    pub maximum_response_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ExperimentalExchangeResponse {
    pub peer: PeerId,
    pub peer_key: AuthenticatedPeerKey,
    pub packet_type: PacketType,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ExperimentalExchangeError {
    #[error("no ready authenticated peer has the requested static key")]
    PeerUnavailable,
    #[error("experimental exchange requires an unknown extension packet type")]
    InvalidPacketType,
    #[error("packet type is owned by a built-in live protocol runtime")]
    ManagedPacketType,
    #[error("experimental exchange deadline has expired")]
    DeadlineExpired,
    #[error("experimental exchange response bound must be nonzero")]
    InvalidResponseBound,
    #[error("an exchange is already active for this exact peer and packet type")]
    AlreadyPending,
    #[error("experimental exchange capacity reached")]
    Capacity,
    #[error("experimental response exceeded its caller-provided bound")]
    ResponseTooLarge,
    #[error("experimental peer disconnected")]
    Disconnected,
    #[error("authenticated Denuo V1 admission evidence is unavailable")]
    AdmissionRejected,
    #[error("experimental request socket write failed")]
    WriteFailed,
}

struct PendingExchange {
    peer_key: AuthenticatedPeerKey,
    deadline: Instant,
    maximum_response_bytes: usize,
    completion: oneshot::Sender<Result<ExperimentalExchangeResponse, ExperimentalExchangeError>>,
}

pub(crate) struct RegisteredExperimentalExchange {
    pub receiver:
        oneshot::Receiver<Result<ExperimentalExchangeResponse, ExperimentalExchangeError>>,
}

#[derive(Default)]
pub(crate) struct ExperimentalExchangeRuntime {
    pending: HashMap<(PeerId, u8), PendingExchange>,
}

impl ExperimentalExchangeRuntime {
    pub fn register(
        &mut self,
        peer: PeerId,
        exchange: &ExperimentalExchange,
    ) -> Result<RegisteredExperimentalExchange, ExperimentalExchangeError> {
        let PacketType::Unknown(packet_type) = exchange.packet_type else {
            return Err(ExperimentalExchangeError::InvalidPacketType);
        };
        if crate::denuo::is_extension_packet_type(exchange.packet_type)
            || crate::is_hip76_packet_type(exchange.packet_type)
            || crate::is_odoh_packet_type(exchange.packet_type)
            || crate::is_hnsr_packet_type(exchange.packet_type)
        {
            return Err(ExperimentalExchangeError::ManagedPacketType);
        }
        if exchange.deadline <= Instant::now() {
            return Err(ExperimentalExchangeError::DeadlineExpired);
        }
        if exchange.maximum_response_bytes == 0 {
            return Err(ExperimentalExchangeError::InvalidResponseBound);
        }
        if self.pending.len() >= MAXIMUM_EXPERIMENTAL_EXCHANGES {
            return Err(ExperimentalExchangeError::Capacity);
        }
        let key = (peer, packet_type);
        if self.pending.contains_key(&key) {
            return Err(ExperimentalExchangeError::AlreadyPending);
        }
        let (completion, receiver) = oneshot::channel();
        self.pending.insert(
            key,
            PendingExchange {
                peer_key: exchange.peer_key,
                deadline: exchange.deadline,
                maximum_response_bytes: exchange.maximum_response_bytes,
                completion,
            },
        );
        Ok(RegisteredExperimentalExchange { receiver })
    }

    pub fn receive(&mut self, peer: PeerId, packet_type: PacketType, payload: &[u8]) -> bool {
        let PacketType::Unknown(packet_type) = packet_type else {
            return false;
        };
        let Some(pending) = self.pending.remove(&(peer, packet_type)) else {
            return false;
        };
        let result = if pending.deadline <= Instant::now() {
            Err(ExperimentalExchangeError::DeadlineExpired)
        } else if payload.len() > pending.maximum_response_bytes {
            Err(ExperimentalExchangeError::ResponseTooLarge)
        } else {
            Ok(ExperimentalExchangeResponse {
                peer,
                peer_key: pending.peer_key,
                packet_type: PacketType::Unknown(packet_type),
                payload: payload.to_vec(),
            })
        };
        let _ = pending.completion.send(result);
        true
    }

    pub fn cancel(
        &mut self,
        peer: PeerId,
        packet_type: PacketType,
        reason: ExperimentalExchangeError,
    ) {
        let PacketType::Unknown(packet_type) = packet_type else {
            return;
        };
        if let Some(pending) = self.pending.remove(&(peer, packet_type)) {
            let _ = pending.completion.send(Err(reason));
        }
    }

    pub fn disconnect(&mut self, peer: PeerId) {
        let keys = self
            .pending
            .keys()
            .filter_map(|(candidate, packet_type)| {
                (*candidate == peer).then_some((*candidate, *packet_type))
            })
            .collect::<Vec<_>>();
        for key in keys {
            if let Some(pending) = self.pending.remove(&key) {
                let _ = pending
                    .completion
                    .send(Err(ExperimentalExchangeError::Disconnected));
            }
        }
    }
}
