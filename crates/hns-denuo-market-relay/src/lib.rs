//! Bounded, content-addressed Denuo marketplace relay core.
//!
//! This crate deliberately owns no signing keys, matching policy, price
//! authority, wallet state, or funds. Canonical marketplace message decoders
//! remain in `hns-rs`; adapters verify those messages before admitting their
//! exact encoded bytes here.

#![forbid(unsafe_code)]
#![allow(
    clippy::missing_errors_doc,
    clippy::module_name_repetitions,
    reason = "relay API names intentionally retain protocol terminology"
)]

use std::collections::{BTreeMap, BTreeSet, HashMap};

use hns_primitives::{blake2b_256, Writer};
use thiserror::Error;

/// Stable marketplace relay role.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum RelayKind {
    /// Fixed-price Handshake name listings and cancellations.
    NameMarket = 1,
    /// Cross-chain market intents.
    CrossChainMarket = 2,
    /// Price observations and verified price rounds.
    Price = 3,
    /// Fill grants and match rendezvous messages.
    Rendezvous = 4,
    /// Bounded swap-session status messages.
    SwapStatus = 5,
}

impl RelayKind {
    const ALL: [Self; 5] = [
        Self::NameMarket,
        Self::CrossChainMarket,
        Self::Price,
        Self::Rendezvous,
        Self::SwapStatus,
    ];

    const fn bit(self) -> u8 {
        1 << ((self as u8) - 1)
    }
}

/// Separately configurable Denuo marketplace relay roles.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RelayRoles {
    bits: u8,
}

impl RelayRoles {
    /// No public relay roles (the requester/mobile-safe default).
    pub const NONE: Self = Self { bits: 0 };
    /// Every currently defined marketplace relay role.
    pub const ALL: Self = Self { bits: 0b1_1111 };

    /// Construct roles from explicit booleans.
    #[must_use]
    pub const fn new(
        name_market: bool,
        cross_chain_market: bool,
        price: bool,
        rendezvous: bool,
        swap_status: bool,
    ) -> Self {
        Self {
            bits: (if name_market { 1 } else { 0 })
                | (if cross_chain_market { 1 << 1 } else { 0 })
                | (if price { 1 << 2 } else { 0 })
                | (if rendezvous { 1 << 3 } else { 0 })
                | (if swap_status { 1 << 4 } else { 0 }),
        }
    }

    /// Whether one role is enabled.
    #[must_use]
    pub const fn contains(self, kind: RelayKind) -> bool {
        self.bits & kind.bit() != 0
    }

    /// Stable role mask for diagnostics/negotiation adapters.
    #[must_use]
    pub const fn bits(self) -> u8 {
        self.bits
    }
}

/// Content hash of one exact canonical marketplace object.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ObjectHash([u8; 32]);

impl ObjectHash {
    /// Construct from the hash announced on the wire.
    #[must_use]
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Raw hash bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Brontide-authenticated peer identity used only for abuse accounting.
pub type PeerIdentity = [u8; 32];
/// Marketplace signer identity after canonical-message verification.
pub type SignerIdentity = [u8; 32];

/// Hash-first object announcement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Announcement {
    /// Negotiated relay role.
    pub kind: RelayKind,
    /// Exact content hash.
    pub hash: ObjectHash,
    /// Canonical signer identity.
    pub signer: SignerIdentity,
    /// Signer-controlled sequence checked against retained in-memory high-water.
    pub sequence: u64,
    /// Canonical creation time.
    pub created_at: u64,
    /// Canonical exclusive expiry.
    pub expires_at: u64,
    /// Exact encoded payload length.
    pub payload_len: u32,
}

/// Exact verified object admitted after a hash-first request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayObject {
    /// Hash-first metadata.
    pub announcement: Announcement,
    /// Canonical, already protocol-verified encoded bytes.
    pub payload: Vec<u8>,
}

impl RelayObject {
    /// Derive the domain-separated content hash from metadata and payload.
    #[must_use]
    pub fn content_hash(
        kind: RelayKind,
        signer: SignerIdentity,
        sequence: u64,
        created_at: u64,
        expires_at: u64,
        payload: &[u8],
    ) -> ObjectHash {
        let mut writer = Writer::with_capacity(32 + payload.len());
        writer.write_bytes(b"hns-denuo-market-relay-v1");
        writer.write_u8(kind as u8);
        writer.write_bytes(&signer);
        writer.write_u64(sequence);
        writer.write_u64(created_at);
        writer.write_u64(expires_at);
        writer.write_varbytes(payload);
        ObjectHash(blake2b_256(&writer.finish()))
    }

    /// Construct an internally consistent object for already verified bytes.
    pub fn new(
        kind: RelayKind,
        signer: SignerIdentity,
        sequence: u64,
        created_at: u64,
        expires_at: u64,
        payload: Vec<u8>,
    ) -> Result<Self, RelayError> {
        let payload_len = u32::try_from(payload.len()).map_err(|_| RelayError::PayloadTooLarge)?;
        let hash = Self::content_hash(kind, signer, sequence, created_at, expires_at, &payload);
        Ok(Self {
            announcement: Announcement {
                kind,
                hash,
                signer,
                sequence,
                created_at,
                expires_at,
                payload_len,
            },
            payload,
        })
    }
}

/// Per-signer admission policy supplied by the node operator/adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SignerPolicy {
    /// Roles this signer may publish through this relay.
    pub roles: RelayRoles,
    /// Maximum unexpired objects retained for this signer across roles.
    pub maximum_active_objects: usize,
}

/// Hard resource and abuse limits for one relay store.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RelayLimits {
    /// Maximum bytes in one canonical object.
    pub maximum_payload_bytes: usize,
    /// Maximum objects retained per independently negotiated role.
    pub maximum_objects_per_role: usize,
    /// Maximum total retained payload bytes.
    pub maximum_total_payload_bytes: usize,
    /// Maximum unexpired objects retained per signer by default.
    pub maximum_objects_per_signer: usize,
    /// Maximum permitted object lifetime.
    pub maximum_lifetime_seconds: u64,
    /// Hash-first fetch request timeout.
    pub request_timeout_seconds: u64,
    /// Maximum pending hash-first fetches.
    pub maximum_pending_fetches: usize,
    /// Maximum peer identities retained for rate and abuse accounting.
    pub maximum_tracked_peers: usize,
    /// Maximum admitted-payload signer identities retained for rate and
    /// sequence accounting. Signers present only in pending announcements are
    /// independently bounded by `maximum_pending_fetches`.
    pub maximum_tracked_signers: usize,
    /// Maximum explicit local signer-policy records.
    pub maximum_signer_policies: usize,
    /// Per-peer announcement and payload operations in one fixed window.
    pub peer_operations_per_window: u32,
    /// Per-signer object admissions in one fixed window.
    pub signer_objects_per_window: u32,
    /// Rate-limit fixed window length.
    pub rate_window_seconds: u64,
    /// Malformed-object strikes before a progressive ban.
    pub strikes_before_ban: u32,
    /// Base progressive ban duration.
    pub base_ban_seconds: u64,
    /// Maximum progressive ban duration.
    pub maximum_ban_seconds: u64,
    /// Score at or below which a peer receives a progressive ban.
    pub minimum_peer_score: i32,
    /// Maximum positive score retained for one peer.
    pub maximum_peer_score: i32,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            maximum_payload_bytes: 512 * 1024,
            maximum_objects_per_role: 4_096,
            maximum_total_payload_bytes: 256 * 1024 * 1024,
            maximum_objects_per_signer: 128,
            maximum_lifetime_seconds: 7 * 24 * 60 * 60,
            request_timeout_seconds: 15,
            maximum_pending_fetches: 2_048,
            maximum_tracked_peers: 4_096,
            maximum_tracked_signers: 4_096,
            maximum_signer_policies: 4_096,
            peer_operations_per_window: 256,
            signer_objects_per_window: 64,
            rate_window_seconds: 60,
            strikes_before_ban: 3,
            base_ban_seconds: 60,
            maximum_ban_seconds: 24 * 60 * 60,
            minimum_peer_score: -100,
            maximum_peer_score: 100,
        }
    }
}

impl RelayLimits {
    /// Validate every bound before allocating a relay store.
    pub fn validate(self) -> Result<Self, RelayError> {
        if self.maximum_payload_bytes == 0
            || self.maximum_objects_per_role == 0
            || self.maximum_total_payload_bytes < self.maximum_payload_bytes
            || self.maximum_objects_per_signer == 0
            || self.maximum_lifetime_seconds == 0
            || self.request_timeout_seconds == 0
            || self.maximum_pending_fetches == 0
            || self.maximum_tracked_peers == 0
            || self.maximum_tracked_signers == 0
            || self.maximum_signer_policies == 0
            || self.peer_operations_per_window == 0
            || self.signer_objects_per_window == 0
            || self.rate_window_seconds == 0
            || self.strikes_before_ban == 0
            || self.base_ban_seconds == 0
            || self.maximum_ban_seconds < self.base_ban_seconds
            || self.minimum_peer_score >= 0
            || self.maximum_peer_score <= 0
        {
            return Err(RelayError::InvalidLimits);
        }
        Ok(self)
    }
}

/// Result of admitting a hash-first announcement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AnnouncementAdmission {
    /// Payload is absent and may be requested before the returned deadline.
    FetchRequired {
        /// Exclusive fetch deadline.
        deadline: u64,
    },
    /// Exact object is already retained; no payload request is needed.
    AlreadyStored,
    /// An identical fetch is already pending.
    AlreadyPending,
}

/// Result of admitting an exact payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ObjectAdmission {
    /// New verified object was retained.
    Stored,
    /// Exact object was already retained.
    Duplicate,
}

/// Bounded relay status suitable for node diagnostics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelayStatus {
    /// Enabled role mask.
    pub roles: RelayRoles,
    /// Current retained objects by role.
    pub objects_by_role: BTreeMap<RelayKind, usize>,
    /// Total retained payload bytes.
    pub retained_payload_bytes: usize,
    /// Pending hash-first fetches.
    pub pending_fetches: usize,
    /// Peers currently under a progressive ban.
    pub banned_peers: usize,
    /// Lifetime duplicate suppressions.
    pub duplicates: u64,
    /// Lifetime malformed penalties.
    pub malformed: u64,
    /// Lifetime rate-limit rejections.
    pub rate_limited: u64,
    /// Lifetime expiry/space evictions.
    pub evicted: u64,
}

/// Closed relay rejection/failure reason.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RelayError {
    /// Resource limits are internally invalid.
    #[error("invalid Denuo relay limits")]
    InvalidLimits,
    /// The independently negotiated role is disabled.
    #[error("Denuo relay role is disabled")]
    RoleDisabled,
    /// Peer is progressively banned.
    #[error("Denuo relay peer is banned")]
    PeerBanned,
    /// Per-peer fixed-window announcement rate exceeded.
    #[error("Denuo relay peer rate limit exceeded")]
    PeerRateLimited,
    /// Bounded peer abuse-accounting capacity is exhausted.
    #[error("Denuo relay peer accounting capacity exhausted")]
    PeerCapacity,
    /// Per-signer fixed-window object rate exceeded.
    #[error("Denuo relay signer rate limit exceeded")]
    SignerRateLimited,
    /// Per-signer policy disallows the role.
    #[error("Denuo relay signer policy disallows role")]
    SignerRoleDenied,
    /// Per-signer active-object cap exceeded.
    #[error("Denuo relay signer active-object limit exceeded")]
    SignerObjectLimit,
    /// Bounded signer accounting capacity is exhausted.
    #[error("Denuo relay signer accounting capacity exhausted")]
    SignerCapacity,
    /// Bounded explicit signer-policy capacity is exhausted.
    #[error("Denuo relay signer policy capacity exhausted")]
    SignerPolicyCapacity,
    /// Payload exceeds its configured or announced bound.
    #[error("Denuo relay payload exceeds bound")]
    PayloadTooLarge,
    /// Creation/expiry bounds are invalid or stale.
    #[error("Denuo relay object is stale or has invalid expiry")]
    InvalidExpiry,
    /// Signer sequence is not newer than the retained in-memory high-water.
    #[error("Denuo relay signer sequence is stale")]
    StaleSequence,
    /// Pending hash-first request capacity is exhausted.
    #[error("Denuo relay pending fetch capacity exhausted")]
    PendingCapacity,
    /// Payload arrived without a current matching hash-first request.
    #[error("Denuo relay payload was not requested")]
    NotRequested,
    /// Payload metadata differs from the pending announcement.
    #[error("Denuo relay payload metadata mismatch")]
    AnnouncementMismatch,
    /// Claimed content hash differs from the canonical object hash.
    #[error("Denuo relay content hash mismatch")]
    HashMismatch,
    /// Total byte capacity cannot retain even after bounded eviction.
    #[error("Denuo relay byte capacity exhausted")]
    Capacity,
}

#[derive(Clone, Copy, Debug)]
struct WindowCounter {
    start: u64,
    count: u32,
    last_seen: u64,
}

impl WindowCounter {
    fn admit(&mut self, now: u64, window: u64, maximum: u32) -> bool {
        self.last_seen = now;
        if now >= self.start.saturating_add(window) {
            self.start = now;
            self.count = 0;
        }
        if self.count >= maximum {
            return false;
        }
        self.count = self.count.saturating_add(1);
        true
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct PeerAbuseState {
    strikes: u32,
    ban_level: u32,
    banned_until: u64,
    score: i32,
}

#[derive(Clone, Debug)]
struct PendingFetch {
    announcement: Announcement,
    peer: PeerIdentity,
    deadline: u64,
}

#[derive(Debug, Default)]
struct RoleStore {
    objects: BTreeMap<ObjectHash, RelayObject>,
    insertion_order: BTreeSet<(u64, ObjectHash)>,
    insertion_sequences: BTreeMap<ObjectHash, u64>,
}

/// In-memory bounded relay cache and abuse-policy state.
///
/// Sequence high-water marks are cache-local replay suppression, not durable
/// cancellation authority. Inactive signer eviction or process restart may
/// forget them; adapters must still verify every canonical object and wallets
/// must reconcile current marketplace state independently.
#[derive(Debug)]
pub struct RelayStore {
    roles: RelayRoles,
    limits: RelayLimits,
    stores: BTreeMap<RelayKind, RoleStore>,
    global_insertion_order: BTreeSet<(u64, RelayKind, ObjectHash)>,
    pending: HashMap<ObjectHash, PendingFetch>,
    pending_deadlines: BTreeSet<(u64, ObjectHash)>,
    object_expirations: BTreeSet<(u64, RelayKind, ObjectHash)>,
    peer_windows: HashMap<PeerIdentity, WindowCounter>,
    peer_eviction_order: BTreeSet<(u64, PeerIdentity)>,
    peer_ban_expirations: BTreeSet<(u64, PeerIdentity)>,
    peer_pending_counts: HashMap<PeerIdentity, usize>,
    signer_windows: HashMap<SignerIdentity, WindowCounter>,
    signer_last_seen: HashMap<SignerIdentity, u64>,
    signer_eviction_order: BTreeSet<(u64, SignerIdentity)>,
    signer_active_counts: HashMap<SignerIdentity, usize>,
    // Pending-only identities are bounded independently by the pending-fetch
    // cap and do not consume admitted signer rate/sequence slots.
    signer_pending_counts: HashMap<SignerIdentity, usize>,
    peer_abuse: HashMap<PeerIdentity, PeerAbuseState>,
    signer_policies: HashMap<SignerIdentity, SignerPolicy>,
    // Bounded in-memory high-water only; removed with inactive signer tracking.
    signer_sequences: HashMap<(RelayKind, SignerIdentity), u64>,
    next_insertion_sequence: u64,
    retained_payload_bytes: usize,
    duplicates: u64,
    malformed: u64,
    rate_limited: u64,
    evicted: u64,
}

impl RelayStore {
    /// Create a bounded relay store. Public relay roles must be explicit.
    pub fn new(roles: RelayRoles, limits: RelayLimits) -> Result<Self, RelayError> {
        let limits = limits.validate()?;
        let stores = RelayKind::ALL
            .into_iter()
            .map(|kind| (kind, RoleStore::default()))
            .collect();
        Ok(Self {
            roles,
            limits,
            stores,
            global_insertion_order: BTreeSet::new(),
            pending: HashMap::new(),
            pending_deadlines: BTreeSet::new(),
            object_expirations: BTreeSet::new(),
            peer_windows: HashMap::new(),
            peer_eviction_order: BTreeSet::new(),
            peer_ban_expirations: BTreeSet::new(),
            peer_pending_counts: HashMap::new(),
            signer_windows: HashMap::new(),
            signer_last_seen: HashMap::new(),
            signer_eviction_order: BTreeSet::new(),
            signer_active_counts: HashMap::new(),
            signer_pending_counts: HashMap::new(),
            peer_abuse: HashMap::new(),
            signer_policies: HashMap::new(),
            signer_sequences: HashMap::new(),
            next_insertion_sequence: 0,
            retained_payload_bytes: 0,
            duplicates: 0,
            malformed: 0,
            rate_limited: 0,
            evicted: 0,
        })
    }

    /// Replace a signer's local relay policy. This never asserts object truth.
    pub fn set_signer_policy(
        &mut self,
        signer: SignerIdentity,
        policy: SignerPolicy,
    ) -> Result<(), RelayError> {
        if !self.signer_policies.contains_key(&signer)
            && self.signer_policies.len() >= self.limits.maximum_signer_policies
        {
            return Err(RelayError::SignerPolicyCapacity);
        }
        self.signer_policies.insert(signer, policy);
        Ok(())
    }

    /// Admit a bounded hash-first announcement and determine whether to fetch.
    pub fn announce(
        &mut self,
        peer: PeerIdentity,
        announcement: Announcement,
        now: u64,
    ) -> Result<AnnouncementAdmission, RelayError> {
        self.ensure_peer(peer, now)?;
        self.admit_peer_operation(peer, now)?;
        self.expire(now);
        if let Err(error) = self.validate_announcement_shape(&announcement, now) {
            self.record_malformed(peer, now);
            return Err(error);
        }
        if self
            .stores
            .get(&announcement.kind)
            .is_some_and(|store| store.objects.contains_key(&announcement.hash))
        {
            self.duplicates = self.duplicates.saturating_add(1);
            return Ok(AnnouncementAdmission::AlreadyStored);
        }
        if self.pending.contains_key(&announcement.hash) {
            self.duplicates = self.duplicates.saturating_add(1);
            return Ok(AnnouncementAdmission::AlreadyPending);
        }
        if let Err(error) = self.validate_announcement_sequence(&announcement) {
            self.record_malformed(peer, now);
            return Err(error);
        }
        if self.pending.len() >= self.limits.maximum_pending_fetches {
            return Err(RelayError::PendingCapacity);
        }
        let deadline = now.saturating_add(self.limits.request_timeout_seconds);
        let hash = announcement.hash;
        let signer = announcement.signer;
        self.pending.insert(
            hash,
            PendingFetch {
                announcement,
                peer,
                deadline,
            },
        );
        self.pending_deadlines.insert((deadline, hash));
        self.track_pending(peer, signer, now);
        Ok(AnnouncementAdmission::FetchRequired { deadline })
    }

    /// Admit exact already-verified bytes only after a matching hash request.
    pub fn put(
        &mut self,
        peer: PeerIdentity,
        object: RelayObject,
        now: u64,
    ) -> Result<ObjectAdmission, RelayError> {
        self.ensure_peer(peer, now)?;
        self.admit_peer_operation(peer, now)?;
        self.expire(now);
        if let Err(error) = self.validate_announcement_shape(&object.announcement, now) {
            self.record_malformed(peer, now);
            return Err(error);
        }
        if self
            .stores
            .get(&object.announcement.kind)
            .is_some_and(|store| store.objects.contains_key(&object.announcement.hash))
        {
            self.duplicates = self.duplicates.saturating_add(1);
            return Ok(ObjectAdmission::Duplicate);
        }
        if let Err(error) = self.validate_announcement_sequence(&object.announcement) {
            self.record_malformed(peer, now);
            return Err(error);
        }
        let Some(pending) = self.pending.get(&object.announcement.hash).cloned() else {
            self.record_malformed(peer, now);
            return Err(RelayError::NotRequested);
        };
        if pending.deadline <= now
            || pending.peer != peer
            || pending.announcement != object.announcement
        {
            self.record_malformed(peer, now);
            return Err(RelayError::AnnouncementMismatch);
        }
        self.remove_pending(object.announcement.hash, now)
            .ok_or(RelayError::NotRequested)?;
        if usize::try_from(object.announcement.payload_len).ok() != Some(object.payload.len()) {
            self.record_malformed(peer, now);
            return Err(RelayError::AnnouncementMismatch);
        }
        let expected = RelayObject::content_hash(
            object.announcement.kind,
            object.announcement.signer,
            object.announcement.sequence,
            object.announcement.created_at,
            object.announcement.expires_at,
            &object.payload,
        );
        if expected != object.announcement.hash {
            self.record_malformed(peer, now);
            return Err(RelayError::HashMismatch);
        }
        self.ensure_signer_tracking(object.announcement.signer, now)?;
        self.ensure_signer(&object.announcement, now)?;
        self.make_space(object.announcement.kind, object.payload.len(), now)?;
        let hash = object.announcement.hash;
        let kind = object.announcement.kind;
        let signer = object.announcement.signer;
        let sequence = object.announcement.sequence;
        let expires_at = object.announcement.expires_at;
        self.retained_payload_bytes = self
            .retained_payload_bytes
            .checked_add(object.payload.len())
            .ok_or(RelayError::Capacity)?;
        let store = self
            .stores
            .get_mut(&kind)
            .expect("all relay role stores are initialized");
        let insertion_sequence = self.next_insertion_sequence;
        self.next_insertion_sequence = self.next_insertion_sequence.saturating_add(1);
        store.insertion_order.insert((insertion_sequence, hash));
        store.insertion_sequences.insert(hash, insertion_sequence);
        store.objects.insert(hash, object);
        self.global_insertion_order
            .insert((insertion_sequence, kind, hash));
        self.object_expirations.insert((expires_at, kind, hash));
        self.track_active_object(signer);
        self.signer_sequences.insert((kind, signer), sequence);
        self.adjust_peer_score(peer, 1, now);
        Ok(ObjectAdmission::Stored)
    }

    /// Fetch one retained object by content hash, never by unbounded board scan.
    #[must_use]
    pub fn get(&self, kind: RelayKind, hash: ObjectHash, now: u64) -> Option<&RelayObject> {
        self.roles.contains(kind).then(|| {
            self.stores
                .get(&kind)?
                .objects
                .get(&hash)
                .filter(|object| object.announcement.expires_at > now)
        })?
    }

    /// Record a malformed protocol object and apply progressive peer bans.
    pub fn penalize_malformed(&mut self, peer: PeerIdentity, now: u64) -> Result<(), RelayError> {
        self.ensure_peer(peer, now)?;
        self.expire(now);
        self.record_malformed(peer, now);
        Ok(())
    }

    fn record_malformed(&mut self, peer: PeerIdentity, now: u64) {
        self.malformed = self.malformed.saturating_add(1);
        let (previous_banned_until, banned_until) = {
            let state = self.peer_abuse.entry(peer).or_default();
            let previous_banned_until = state.banned_until;
            state.score = state
                .score
                .saturating_sub(10)
                .max(self.limits.minimum_peer_score);
            state.strikes = state.strikes.saturating_add(1);
            if state.strikes >= self.limits.strikes_before_ban
                || state.score <= self.limits.minimum_peer_score
            {
                apply_progressive_ban(state, self.limits, now);
            }
            (previous_banned_until, state.banned_until)
        };
        self.update_peer_ban_index(peer, previous_banned_until, banned_until, now);
    }

    /// Remove expired requests/objects and return the number evicted.
    pub fn expire(&mut self, now: u64) -> usize {
        self.release_expired_peer_bans(now);
        while let Some(&(deadline, hash)) = self.pending_deadlines.first() {
            if deadline > now {
                break;
            }
            self.pending_deadlines.pop_first();
            if self
                .pending
                .get(&hash)
                .is_some_and(|pending| pending.deadline == deadline)
            {
                self.remove_pending(hash, now);
            }
        }
        let mut removed = 0_usize;
        while let Some(&(expires_at, kind, hash)) = self.object_expirations.first() {
            if expires_at > now {
                break;
            }
            self.object_expirations.pop_first();
            self.remove_object(kind, hash);
            removed = removed.saturating_add(1);
        }
        self.evicted = self
            .evicted
            .saturating_add(u64::try_from(removed).unwrap_or(u64::MAX));
        removed
    }

    /// Read bounded, name-free relay diagnostics.
    #[must_use]
    pub fn status(&mut self, now: u64) -> RelayStatus {
        self.expire(now);
        let objects_by_role = RelayKind::ALL
            .into_iter()
            .map(|kind| {
                let count = self.stores.get(&kind).map_or(0, |store| {
                    store
                        .objects
                        .values()
                        .filter(|object| object.announcement.expires_at > now)
                        .count()
                });
                (kind, count)
            })
            .collect();
        RelayStatus {
            roles: self.roles,
            objects_by_role,
            retained_payload_bytes: self.retained_payload_bytes,
            pending_fetches: self
                .pending
                .values()
                .filter(|pending| pending.deadline > now)
                .count(),
            banned_peers: self
                .peer_abuse
                .values()
                .filter(|state| state.banned_until > now)
                .count(),
            duplicates: self.duplicates,
            malformed: self.malformed,
            rate_limited: self.rate_limited,
            evicted: self.evicted,
        }
    }

    fn validate_announcement_shape(
        &self,
        announcement: &Announcement,
        now: u64,
    ) -> Result<(), RelayError> {
        if !self.roles.contains(announcement.kind) {
            return Err(RelayError::RoleDisabled);
        }
        if usize::try_from(announcement.payload_len)
            .ok()
            .is_none_or(|len| len == 0 || len > self.limits.maximum_payload_bytes)
        {
            return Err(RelayError::PayloadTooLarge);
        }
        if announcement.created_at > now
            || announcement.expires_at <= now
            || announcement.expires_at <= announcement.created_at
            || announcement
                .expires_at
                .saturating_sub(announcement.created_at)
                > self.limits.maximum_lifetime_seconds
        {
            return Err(RelayError::InvalidExpiry);
        }
        Ok(())
    }

    fn validate_announcement_sequence(
        &self,
        announcement: &Announcement,
    ) -> Result<(), RelayError> {
        if self
            .signer_sequences
            .get(&(announcement.kind, announcement.signer))
            .is_some_and(|sequence| announcement.sequence <= *sequence)
        {
            return Err(RelayError::StaleSequence);
        }
        Ok(())
    }

    fn admit_peer_operation(&mut self, peer: PeerIdentity, now: u64) -> Result<(), RelayError> {
        let window = self.peer_windows.entry(peer).or_insert(WindowCounter {
            start: now,
            count: 0,
            last_seen: now,
        });
        if window.admit(
            now,
            self.limits.rate_window_seconds,
            self.limits.peer_operations_per_window,
        ) {
            return Ok(());
        }
        self.rate_limited = self.rate_limited.saturating_add(1);
        self.adjust_peer_score(peer, -1, now);
        Err(RelayError::PeerRateLimited)
    }

    fn ensure_peer(&mut self, peer: PeerIdentity, now: u64) -> Result<(), RelayError> {
        self.release_expired_peer_bans(now);
        if self
            .peer_abuse
            .get(&peer)
            .is_some_and(|state| state.banned_until > now)
        {
            return Err(RelayError::PeerBanned);
        }
        if let Some(window) = self.peer_windows.get_mut(&peer) {
            self.peer_eviction_order.remove(&(window.last_seen, peer));
            window.last_seen = now;
            self.refresh_peer_eviction(peer, now);
            return Ok(());
        }
        if self.peer_windows.len() >= self.limits.maximum_tracked_peers {
            let Some((_, evictable)) = self.peer_eviction_order.pop_first() else {
                return Err(RelayError::PeerCapacity);
            };
            self.peer_windows.remove(&evictable);
            if let Some(state) = self.peer_abuse.remove(&evictable) {
                self.peer_ban_expirations
                    .remove(&(state.banned_until, evictable));
            }
            self.peer_pending_counts.remove(&evictable);
        }
        self.peer_windows.insert(
            peer,
            WindowCounter {
                start: now,
                count: 0,
                last_seen: now,
            },
        );
        self.refresh_peer_eviction(peer, now);
        Ok(())
    }

    fn refresh_peer_eviction(&mut self, peer: PeerIdentity, now: u64) {
        let Some(window) = self.peer_windows.get(&peer).copied() else {
            return;
        };
        self.peer_eviction_order.remove(&(window.last_seen, peer));
        let has_pending = self
            .peer_pending_counts
            .get(&peer)
            .is_some_and(|count| *count != 0);
        let banned = self
            .peer_abuse
            .get(&peer)
            .is_some_and(|state| state.banned_until > now);
        if !has_pending && !banned {
            self.peer_eviction_order.insert((window.last_seen, peer));
        }
    }

    fn release_expired_peer_bans(&mut self, now: u64) {
        while let Some(&(banned_until, peer)) = self.peer_ban_expirations.first() {
            if banned_until > now {
                break;
            }
            self.peer_ban_expirations.pop_first();
            if self
                .peer_abuse
                .get(&peer)
                .is_some_and(|state| state.banned_until == banned_until)
            {
                self.refresh_peer_eviction(peer, now);
            }
        }
    }

    fn update_peer_ban_index(
        &mut self,
        peer: PeerIdentity,
        previous_banned_until: u64,
        banned_until: u64,
        now: u64,
    ) {
        if previous_banned_until != 0 {
            self.peer_ban_expirations
                .remove(&(previous_banned_until, peer));
        }
        if banned_until > now {
            self.peer_ban_expirations.insert((banned_until, peer));
        }
        self.refresh_peer_eviction(peer, now);
    }

    fn track_pending(&mut self, peer: PeerIdentity, signer: SignerIdentity, now: u64) {
        let peer_count = self.peer_pending_counts.entry(peer).or_default();
        *peer_count = peer_count.saturating_add(1);
        let signer_count = self.signer_pending_counts.entry(signer).or_default();
        *signer_count = signer_count.saturating_add(1);
        self.refresh_peer_eviction(peer, now);
        self.refresh_signer_eviction(signer);
    }

    fn remove_pending(&mut self, hash: ObjectHash, now: u64) -> Option<PendingFetch> {
        let pending = self.pending.remove(&hash)?;
        self.pending_deadlines.remove(&(pending.deadline, hash));

        let remove_peer_count =
            self.peer_pending_counts
                .get_mut(&pending.peer)
                .is_some_and(|count| {
                    if *count > 1 {
                        *count -= 1;
                        false
                    } else {
                        true
                    }
                });
        if remove_peer_count {
            self.peer_pending_counts.remove(&pending.peer);
        }
        let remove_signer_count = self
            .signer_pending_counts
            .get_mut(&pending.announcement.signer)
            .is_some_and(|count| {
                if *count > 1 {
                    *count -= 1;
                    false
                } else {
                    true
                }
            });
        if remove_signer_count {
            self.signer_pending_counts
                .remove(&pending.announcement.signer);
        }
        self.refresh_peer_eviction(pending.peer, now);
        self.refresh_signer_eviction(pending.announcement.signer);
        Some(pending)
    }

    fn ensure_signer_tracking(
        &mut self,
        signer: SignerIdentity,
        now: u64,
    ) -> Result<(), RelayError> {
        if let Some(last_seen) = self.signer_last_seen.get_mut(&signer) {
            self.signer_eviction_order.remove(&(*last_seen, signer));
            *last_seen = now;
            self.refresh_signer_eviction(signer);
            return Ok(());
        }
        if self.signer_last_seen.len() >= self.limits.maximum_tracked_signers {
            let Some((_, evictable)) = self.signer_eviction_order.pop_first() else {
                return Err(RelayError::SignerCapacity);
            };
            self.signer_last_seen.remove(&evictable);
            self.signer_windows.remove(&evictable);
            self.signer_active_counts.remove(&evictable);
            self.signer_pending_counts.remove(&evictable);
            for kind in RelayKind::ALL {
                self.signer_sequences.remove(&(kind, evictable));
            }
        }
        self.signer_last_seen.insert(signer, now);
        self.refresh_signer_eviction(signer);
        Ok(())
    }

    fn refresh_signer_eviction(&mut self, signer: SignerIdentity) {
        let Some(last_seen) = self.signer_last_seen.get(&signer).copied() else {
            return;
        };
        self.signer_eviction_order.remove(&(last_seen, signer));
        let active = self.signer_active_counts.get(&signer).copied().unwrap_or(0);
        let pending = self
            .signer_pending_counts
            .get(&signer)
            .copied()
            .unwrap_or(0);
        if active == 0 && pending == 0 {
            self.signer_eviction_order.insert((last_seen, signer));
        }
    }

    fn track_active_object(&mut self, signer: SignerIdentity) {
        let active = self.signer_active_counts.entry(signer).or_default();
        *active = active.saturating_add(1);
        self.refresh_signer_eviction(signer);
    }

    fn untrack_active_object(&mut self, signer: SignerIdentity) {
        let remove_active = self
            .signer_active_counts
            .get_mut(&signer)
            .is_some_and(|active| {
                if *active > 1 {
                    *active -= 1;
                    false
                } else {
                    true
                }
            });
        if remove_active {
            self.signer_active_counts.remove(&signer);
        }
        self.refresh_signer_eviction(signer);
    }

    fn ensure_signer(&mut self, announcement: &Announcement, now: u64) -> Result<(), RelayError> {
        let policy = self
            .signer_policies
            .get(&announcement.signer)
            .copied()
            .unwrap_or(SignerPolicy {
                roles: self.roles,
                maximum_active_objects: self.limits.maximum_objects_per_signer,
            });
        if !policy.roles.contains(announcement.kind) {
            return Err(RelayError::SignerRoleDenied);
        }
        let active = self
            .signer_active_counts
            .get(&announcement.signer)
            .copied()
            .unwrap_or(0);
        if active >= policy.maximum_active_objects {
            return Err(RelayError::SignerObjectLimit);
        }
        let window = self
            .signer_windows
            .entry(announcement.signer)
            .or_insert(WindowCounter {
                start: now,
                count: 0,
                last_seen: now,
            });
        if !window.admit(
            now,
            self.limits.rate_window_seconds,
            self.limits.signer_objects_per_window,
        ) {
            self.rate_limited = self.rate_limited.saturating_add(1);
            return Err(RelayError::SignerRateLimited);
        }
        Ok(())
    }

    fn make_space(
        &mut self,
        kind: RelayKind,
        incoming_bytes: usize,
        now: u64,
    ) -> Result<(), RelayError> {
        self.expire(now);
        while self
            .stores
            .get(&kind)
            .is_some_and(|store| store.objects.len() >= self.limits.maximum_objects_per_role)
        {
            let Some(oldest) = self
                .stores
                .get(&kind)
                .and_then(|store| store.insertion_order.first().map(|(_, hash)| *hash))
            else {
                break;
            };
            self.remove_object(kind, oldest);
            self.evicted = self.evicted.saturating_add(1);
        }
        while self
            .retained_payload_bytes
            .checked_add(incoming_bytes)
            .is_none_or(|total| total > self.limits.maximum_total_payload_bytes)
        {
            let Some((_, oldest_kind, oldest_hash)) = self.global_insertion_order.pop_first()
            else {
                return Err(RelayError::Capacity);
            };
            self.remove_object(oldest_kind, oldest_hash);
            self.evicted = self.evicted.saturating_add(1);
        }
        Ok(())
    }

    fn remove_object(&mut self, kind: RelayKind, hash: ObjectHash) {
        let (insertion_sequence, object) = {
            let Some(store) = self.stores.get_mut(&kind) else {
                return;
            };
            let insertion_sequence = store.insertion_sequences.remove(&hash);
            if let Some(insertion_sequence) = insertion_sequence {
                store.insertion_order.remove(&(insertion_sequence, hash));
            }
            (insertion_sequence, store.objects.remove(&hash))
        };
        if let Some(insertion_sequence) = insertion_sequence {
            self.global_insertion_order
                .remove(&(insertion_sequence, kind, hash));
        }
        if let Some(object) = object {
            let signer = object.announcement.signer;
            self.object_expirations
                .remove(&(object.announcement.expires_at, kind, hash));
            self.retained_payload_bytes = self
                .retained_payload_bytes
                .saturating_sub(object.payload.len());
            self.untrack_active_object(signer);
        }
    }

    fn adjust_peer_score(&mut self, peer: PeerIdentity, adjustment: i32, now: u64) {
        let (previous_banned_until, banned_until) = {
            let state = self.peer_abuse.entry(peer).or_default();
            let previous_banned_until = state.banned_until;
            state.score = state.score.saturating_add(adjustment).clamp(
                self.limits.minimum_peer_score,
                self.limits.maximum_peer_score,
            );
            if state.score <= self.limits.minimum_peer_score {
                apply_progressive_ban(state, self.limits, now);
            }
            (previous_banned_until, state.banned_until)
        };
        self.update_peer_ban_index(peer, previous_banned_until, banned_until, now);
    }
}

fn apply_progressive_ban(state: &mut PeerAbuseState, limits: RelayLimits, now: u64) {
    state.strikes = 0;
    state.ban_level = state.ban_level.saturating_add(1);
    let exponent = state.ban_level.saturating_sub(1).min(31);
    let duration = limits
        .base_ban_seconds
        .saturating_mul(1_u64 << exponent)
        .min(limits.maximum_ban_seconds);
    state.banned_until = now.saturating_add(duration);
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_700_000_000;

    fn object(kind: RelayKind, signer: u8, sequence: u64, payload: &[u8]) -> RelayObject {
        RelayObject::new(
            kind,
            [signer; 32],
            sequence,
            NOW,
            NOW + 60,
            payload.to_vec(),
        )
        .unwrap()
    }

    #[test]
    fn hash_first_fetch_duplicate_and_expiry_are_bounded() {
        let mut relay = RelayStore::new(RelayRoles::ALL, RelayLimits::default()).unwrap();
        let peer = [3; 32];
        let object = object(RelayKind::NameMarket, 7, 1, b"listing");
        assert!(matches!(
            relay
                .announce(peer, object.announcement.clone(), NOW)
                .unwrap(),
            AnnouncementAdmission::FetchRequired { .. }
        ));
        assert_eq!(
            relay.put(peer, object.clone(), NOW).unwrap(),
            ObjectAdmission::Stored
        );
        assert_eq!(
            relay
                .announce(peer, object.announcement.clone(), NOW)
                .unwrap(),
            AnnouncementAdmission::AlreadyStored
        );
        assert_eq!(
            relay.get(RelayKind::NameMarket, object.announcement.hash, NOW),
            Some(&object)
        );
        assert_eq!(relay.expire(NOW + 60), 1);
        assert!(relay
            .get(RelayKind::NameMarket, object.announcement.hash, NOW + 60)
            .is_none());
    }

    #[test]
    fn wrong_peer_cannot_consume_another_peers_pending_fetch() {
        let mut relay = RelayStore::new(RelayRoles::ALL, RelayLimits::default()).unwrap();
        let requested_peer = [3; 32];
        let wrong_peer = [4; 32];
        let object = object(RelayKind::NameMarket, 7, 1, b"listing");
        relay
            .announce(requested_peer, object.announcement.clone(), NOW)
            .unwrap();

        assert_eq!(
            relay.put(wrong_peer, object.clone(), NOW),
            Err(RelayError::AnnouncementMismatch)
        );
        assert_eq!(relay.status(NOW).pending_fetches, 1);
        assert_eq!(
            relay.put(requested_peer, object.clone(), NOW).unwrap(),
            ObjectAdmission::Stored
        );
        assert_eq!(
            relay.get(RelayKind::NameMarket, object.announcement.hash, NOW),
            Some(&object)
        );
    }

    #[test]
    fn aggregate_capacity_evicts_global_oldest_without_role_bias() {
        let limits = RelayLimits {
            maximum_payload_bytes: 4,
            maximum_total_payload_bytes: 8,
            ..RelayLimits::default()
        };
        let mut relay = RelayStore::new(RelayRoles::ALL, limits).unwrap();
        let peer = [9; 32];
        let oldest = object(RelayKind::Price, 61, 1, b"old!");
        let retained = object(RelayKind::NameMarket, 62, 1, b"name");
        let incoming = object(RelayKind::CrossChainMarket, 63, 1, b"swap");

        for candidate in [&oldest, &retained, &incoming] {
            relay
                .announce(peer, candidate.announcement.clone(), NOW)
                .unwrap();
            relay.put(peer, candidate.clone(), NOW).unwrap();
        }

        assert!(relay
            .get(RelayKind::Price, oldest.announcement.hash, NOW)
            .is_none());
        assert_eq!(
            relay.get(RelayKind::NameMarket, retained.announcement.hash, NOW),
            Some(&retained)
        );
        assert_eq!(
            relay.get(RelayKind::CrossChainMarket, incoming.announcement.hash, NOW,),
            Some(&incoming)
        );
    }

    #[test]
    fn wrong_hash_is_penalized_and_progressively_banned() {
        let limits = RelayLimits {
            strikes_before_ban: 2,
            ..RelayLimits::default()
        };
        let mut relay = RelayStore::new(RelayRoles::ALL, limits).unwrap();
        let peer = [4; 32];
        for sequence in 1..=2 {
            let mut object = object(RelayKind::CrossChainMarket, 8, sequence, b"intent");
            relay
                .announce(peer, object.announcement.clone(), NOW)
                .unwrap();
            object.payload[0] ^= 1;
            assert_eq!(relay.put(peer, object, NOW), Err(RelayError::HashMismatch));
        }
        let next = object(RelayKind::CrossChainMarket, 8, 3, b"next");
        assert_eq!(
            relay.announce(peer, next.announcement, NOW),
            Err(RelayError::PeerBanned)
        );
        assert_eq!(relay.status(NOW).banned_peers, 1);
    }

    #[test]
    fn roles_rates_and_signer_policies_fail_closed() {
        let roles = RelayRoles::new(true, false, false, false, false);
        let mut relay = RelayStore::new(roles, RelayLimits::default()).unwrap();
        let disabled_peer = [4; 32];
        let disabled = object(RelayKind::SwapStatus, 9, 1, b"status");
        assert_eq!(
            relay.announce(disabled_peer, disabled.announcement, NOW),
            Err(RelayError::RoleDisabled)
        );
        assert_eq!(relay.status(NOW).malformed, 1);

        let limits = RelayLimits {
            peer_operations_per_window: 1,
            ..RelayLimits::default()
        };
        let mut rate_relay = RelayStore::new(roles, limits).unwrap();
        let peer = [5; 32];
        let first = object(RelayKind::NameMarket, 9, 1, b"first");
        rate_relay
            .announce(peer, first.announcement.clone(), NOW)
            .unwrap();
        let second = object(RelayKind::NameMarket, 10, 1, b"second");
        assert_eq!(
            rate_relay.announce(peer, second.announcement, NOW),
            Err(RelayError::PeerRateLimited)
        );

        let mut relay = RelayStore::new(roles, RelayLimits::default()).unwrap();
        relay
            .announce(peer, first.announcement.clone(), NOW)
            .unwrap();
        relay
            .set_signer_policy(
                [9; 32],
                SignerPolicy {
                    roles: RelayRoles::NONE,
                    maximum_active_objects: 1,
                },
            )
            .unwrap();
        assert_eq!(
            relay.put(peer, first, NOW),
            Err(RelayError::SignerRoleDenied)
        );
    }

    #[test]
    fn duplicate_and_invalid_announcements_consume_peer_budget() {
        let limits = RelayLimits {
            peer_operations_per_window: 3,
            strikes_before_ban: u32::MAX,
            ..RelayLimits::default()
        };
        let mut relay = RelayStore::new(RelayRoles::ALL, limits).unwrap();
        let peer = [17; 32];
        let stored = object(RelayKind::NameMarket, 18, 1, b"listing");
        relay
            .announce(peer, stored.announcement.clone(), NOW)
            .unwrap();
        relay.put(peer, stored.clone(), NOW).unwrap();
        assert_eq!(
            relay
                .announce(peer, stored.announcement.clone(), NOW)
                .unwrap(),
            AnnouncementAdmission::AlreadyStored
        );
        assert_eq!(
            relay.announce(peer, stored.announcement, NOW),
            Err(RelayError::PeerRateLimited)
        );

        let other_peer = [19; 32];
        let mut invalid = object(RelayKind::Price, 20, 1, b"price").announcement;
        invalid.expires_at = NOW;
        assert_eq!(
            relay.announce(other_peer, invalid, NOW),
            Err(RelayError::InvalidExpiry)
        );
        assert_eq!(relay.status(NOW).malformed, 1);
    }

    #[test]
    fn peer_signer_and_policy_accounting_are_hard_bounded() {
        let limits = RelayLimits {
            maximum_tracked_peers: 1,
            maximum_tracked_signers: 1,
            maximum_signer_policies: 1,
            ..RelayLimits::default()
        };
        let mut relay = RelayStore::new(RelayRoles::ALL, limits).unwrap();
        let first_peer = [21; 32];
        let first = object(RelayKind::NameMarket, 31, 1, b"first");
        relay
            .announce(first_peer, first.announcement.clone(), NOW)
            .unwrap();
        assert_eq!(
            relay.announce(
                [22; 32],
                object(RelayKind::NameMarket, 32, 1, b"second").announcement,
                NOW,
            ),
            Err(RelayError::PeerCapacity)
        );
        relay.put(first_peer, first, NOW).unwrap();

        let second = object(RelayKind::NameMarket, 32, 1, b"second");
        relay
            .announce(first_peer, second.announcement.clone(), NOW)
            .unwrap();
        assert_eq!(
            relay.put(first_peer, second, NOW),
            Err(RelayError::SignerCapacity)
        );

        relay
            .set_signer_policy(
                [41; 32],
                SignerPolicy {
                    roles: RelayRoles::ALL,
                    maximum_active_objects: 1,
                },
            )
            .unwrap();
        assert_eq!(
            relay.set_signer_policy(
                [42; 32],
                SignerPolicy {
                    roles: RelayRoles::ALL,
                    maximum_active_objects: 1,
                },
            ),
            Err(RelayError::SignerPolicyCapacity)
        );
    }

    #[test]
    fn ordered_accounting_releases_expired_peer_and_signer_capacity() {
        let limits = RelayLimits {
            maximum_tracked_peers: 1,
            maximum_tracked_signers: 1,
            request_timeout_seconds: 1,
            ..RelayLimits::default()
        };
        let mut relay = RelayStore::new(RelayRoles::ALL, limits).unwrap();
        let first = object(RelayKind::NameMarket, 51, 1, b"unanswered");
        relay.announce([51; 32], first.announcement, NOW).unwrap();
        relay.expire(NOW + 1);

        let second = RelayObject::new(
            RelayKind::NameMarket,
            [52; 32],
            1,
            NOW + 1,
            NOW + 61,
            b"stored".to_vec(),
        )
        .unwrap();
        relay
            .announce([52; 32], second.announcement.clone(), NOW + 1)
            .unwrap();
        relay.put([52; 32], second, NOW + 1).unwrap();
        relay.expire(NOW + 61);

        let third = RelayObject::new(
            RelayKind::NameMarket,
            [53; 32],
            1,
            NOW + 61,
            NOW + 121,
            b"replacement".to_vec(),
        )
        .unwrap();
        relay
            .announce([52; 32], third.announcement.clone(), NOW + 61)
            .unwrap();
        assert_eq!(
            relay.put([52; 32], third, NOW + 61).unwrap(),
            ObjectAdmission::Stored
        );
    }
}
