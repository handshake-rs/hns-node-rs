//! Node-owned handle for the bounded Denuo marketplace relay core.

use std::sync::{Arc, Mutex};

use hns_denuo_market_relay::{
    Announcement, AnnouncementAdmission, ObjectAdmission, ObjectHash, PeerIdentity, RelayError,
    RelayKind, RelayLimits, RelayObject, RelayRoles, RelayStatus, RelayStore, SignerIdentity,
    SignerPolicy,
};
use thiserror::Error;

/// Shared bounded Denuo relay service for native runtime extensions.
///
/// The handle exposes only verified canonical object storage and abuse policy;
/// it has no signing, matching, pricing, or funds interface.
#[derive(Clone)]
pub struct DenuoRelayHandle {
    inner: Arc<Mutex<RelayStore>>,
}

impl std::fmt::Debug for DenuoRelayHandle {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DenuoRelayHandle")
            .finish_non_exhaustive()
    }
}

/// Node relay-handle failure.
#[derive(Debug, Error)]
pub enum DenuoRelayHandleError {
    /// Relay policy rejected the operation.
    #[error(transparent)]
    Relay(#[from] RelayError),
    /// A caller panic poisoned the process-local relay lock.
    #[error("Denuo relay lock poisoned")]
    LockPoisoned,
}

impl DenuoRelayHandle {
    pub(crate) fn new(roles: RelayRoles, limits: RelayLimits) -> Result<Self, RelayError> {
        Ok(Self {
            inner: Arc::new(Mutex::new(RelayStore::new(roles, limits)?)),
        })
    }

    /// Admit one hash-first announcement.
    pub fn announce(
        &self,
        peer: PeerIdentity,
        announcement: Announcement,
        now: u64,
    ) -> Result<AnnouncementAdmission, DenuoRelayHandleError> {
        self.inner
            .lock()
            .map_err(|_| DenuoRelayHandleError::LockPoisoned)?
            .announce(peer, announcement, now)
            .map_err(Into::into)
    }

    /// Admit one exact already-protocol-verified requested payload.
    pub fn put(
        &self,
        peer: PeerIdentity,
        object: RelayObject,
        now: u64,
    ) -> Result<ObjectAdmission, DenuoRelayHandleError> {
        self.inner
            .lock()
            .map_err(|_| DenuoRelayHandleError::LockPoisoned)?
            .put(peer, object, now)
            .map_err(Into::into)
    }

    /// Fetch one exact object by hash. Board enumeration is intentionally absent.
    pub fn get(
        &self,
        kind: RelayKind,
        hash: ObjectHash,
        now: u64,
    ) -> Result<Option<RelayObject>, DenuoRelayHandleError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| DenuoRelayHandleError::LockPoisoned)?
            .get(kind, hash, now)
            .cloned())
    }

    /// Set local per-signer relay policy.
    pub fn set_signer_policy(
        &self,
        signer: SignerIdentity,
        policy: SignerPolicy,
    ) -> Result<(), DenuoRelayHandleError> {
        self.inner
            .lock()
            .map_err(|_| DenuoRelayHandleError::LockPoisoned)?
            .set_signer_policy(signer, policy)
            .map_err(Into::into)
    }

    /// Apply a malformed-message penalty and progressive ban.
    pub fn penalize_malformed(
        &self,
        peer: PeerIdentity,
        now: u64,
    ) -> Result<(), DenuoRelayHandleError> {
        self.inner
            .lock()
            .map_err(|_| DenuoRelayHandleError::LockPoisoned)?
            .penalize_malformed(peer, now)
            .map_err(Into::into)
    }

    /// Read bounded name-free role/cache/abuse status.
    pub fn status(&self, now: u64) -> Result<RelayStatus, DenuoRelayHandleError> {
        Ok(self
            .inner
            .lock()
            .map_err(|_| DenuoRelayHandleError::LockPoisoned)?
            .status(now))
    }
}
