//! Durable, sole-owner namespaces for authority-bearing protocol state.
//!
//! Ordinary atomic batches are insufficient for HRM/HNSA/HNSR state: a
//! consumer must keep one namespace exclusively owned while loading the latest
//! image, compare the exact prior image, and validate the same fencing epoch in
//! the atomic publication that installs the replacement. This module provides
//! that native-store boundary. It deliberately reserves its storage keys from
//! [`crate::WriteBatch`], requires synchronous durability, and retains
//! ambiguous RocksDB publication failures behind the store-wide reopen fence.
//! Acquisition also requires the current storage schema to be initialized.
//! Once a segment archive is attached, namespace access must use that wrapper;
//! surviving raw aliases are fenced from this API.
//!
//! The checksums below detect corruption and bind the two database records.
//! They are not storage authentication and cannot stop replay of an older
//! whole-database checkpoint. Embeddings must retain an authenticated minimum
//! revision outside the replayable database before treating this state as the
//! complete HIP anti-rollback boundary.

use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

use hns_primitives::blake2b_256_many;
use thiserror::Error;

#[cfg(feature = "rocksdb-backend")]
use crate::RocksStore;
use crate::{
    apply_memory_changes, memory_value_at, segment_store_error, BatchOperations, ColumnFamily,
    DurabilityPolicy, MemoryStore, MemoryStoreState, ReadSnapshot, SegmentArchive, Store,
    StoreError, StoreHandle, StoreKey,
};

/// Maximum canonical bytes retained for one complete authority/replay image.
///
/// HNSR's bounded requester/rendezvous aggregates can approach fourteen MiB;
/// this ceiling leaves framing room. RocksDB values are first read as pinned
/// slices and checked against the ceiling before copying into Rust-owned state.
pub const AUTHENTICATED_NAMESPACE_MAX_STATE_BYTES: usize = 16 * 1024 * 1024;

const CONTROL_KEY_PREFIX: &[u8] = b"authenticated-namespace-control/v1/";
const STATE_KEY_PREFIX: &[u8] = b"authenticated-namespace-state/v1/";
const CONTROL_MAGIC: &[u8; 8] = b"HNSANSC\0";
const CONTROL_VERSION: u8 = 1;
const CONTROL_CHECKSUM_DOMAIN: &[u8] = b"HNS-STORE-AUTHENTICATED-NAMESPACE-CONTROL-CHECKSUM-V1\0";
const STATE_DIGEST_DOMAIN: &[u8] = b"HNS-STORE-AUTHENTICATED-NAMESPACE-STATE-V1\0";
const CONTROL_BODY_BYTES: usize = 8 + 1 + 32 + 8 + 1 + 8 + 32;
const CONTROL_BYTES: usize = CONTROL_BODY_BYTES + 32;

/// Shared live-owner registry carried by every clone of one physical backend.
///
/// The map is held only while resolving a namespace cell. Durable I/O occurs
/// after releasing it, so an fsync for one namespace cannot block unrelated
/// lease checks, releases, or acquisitions.
pub(super) type SharedNamespaceOwners =
    Arc<Mutex<BTreeMap<OperationNamespaceId, Weak<NamespaceOwnerCell>>>>;

/// One live segment wrapper registered against a physical backend.
///
/// Once attached, namespace access through a raw alias remains rejected even
/// while the weak reference is detached between wrapper instances. This keeps
/// every namespace publication on the archive's writer-before-database lock
/// path and also rejects a second live wrapper.
pub(super) type SharedNamespaceArchiveRegistration = Arc<Mutex<Option<Weak<SegmentArchive>>>>;

#[derive(Debug, Default)]
pub(super) struct NamespaceOwnerCell {
    owned: AtomicBool,
    fencing_token: AtomicU64,
}

/// Stable, embedding-derived identity for one physical logical state lineage.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct OperationNamespaceId([u8; 32]);

impl OperationNamespaceId {
    /// Construct a nonzero namespace identity.
    pub fn new(value: [u8; 32]) -> Result<Self, AuthenticatedNamespaceError> {
        if value == [0; 32] {
            return Err(AuthenticatedNamespaceError::ZeroNamespace);
        }
        Ok(Self(value))
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

/// Authenticated current topology loaded under an exact held namespace lease.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthenticatedNamespaceState {
    /// The durable epoch exists, but no state image has ever been initialized.
    NeverInitialized,
    /// Complete state and the nondecreasing revision floor bound to it.
    Initialized {
        encoded: Vec<u8>,
        minimum_revision: u64,
    },
}

/// Exact prior-image expectation for one state publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StateExpectation<'a> {
    /// Atomically create only if this namespace has never been initialized.
    Absent,
    /// Replace only this exact prior revision and complete-state byte image.
    Exact {
        minimum_revision: u64,
        encoded: &'a [u8],
    },
}

/// Result of an exact, fence-validated state publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuthenticatedNamespaceWrite {
    /// The proposed state was installed by this call.
    Committed,
    /// The exact proposal was already installed by an outcome-ambiguous retry.
    AlreadyCommitted,
    /// The durable image did not satisfy the supplied prior-image expectation.
    Conflict,
}

/// Fail-closed namespace acquisition, validation, or publication error.
#[derive(Debug, Error)]
pub enum AuthenticatedNamespaceError {
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("authenticated namespace identity must be nonzero")]
    ZeroNamespace,
    #[error("authenticated namespace is already exclusively owned")]
    Busy,
    #[error("authenticated namespace owner registry is poisoned")]
    OwnerRegistryPoisoned,
    #[error("authenticated namespace archive registry is poisoned")]
    ArchiveRegistryPoisoned,
    #[error("authenticated namespace lease was lost or superseded")]
    LeaseLost,
    #[error("authenticated namespaces require synchronous store durability")]
    NonDurableStore,
    #[error("authenticated namespace access requires the live segment-archive handle")]
    ArchiveHandleRequired,
    #[error("authenticated namespace segment-archive registration is inconsistent")]
    ArchiveRegistrationMismatch,
    #[error("authenticated namespace fencing epoch is exhausted")]
    FencingEpochExhausted,
    #[error("authenticated namespace state must not be empty")]
    EmptyState,
    #[error("authenticated namespace state has {actual} bytes; maximum is {maximum}")]
    StateTooLarge { actual: usize, maximum: usize },
    #[error(
        "authenticated namespace replacement revision must advance beyond {current}; proposed {proposed}"
    )]
    RevisionNotAdvanced { current: u64, proposed: u64 },
    #[error("corrupt authenticated namespace state: {0}")]
    Corrupt(&'static str),
}

/// Non-cloneable proof of sole live ownership for one exact namespace.
///
/// Dropping the guard releases only the in-process ownership cell. The durable
/// fencing epoch remains and is checked-incremented before a later acquisition
/// is exposed.
pub struct AuthenticatedNamespaceLease {
    store: StoreHandle,
    owners: SharedNamespaceOwners,
    owner: Arc<NamespaceOwnerCell>,
    namespace: OperationNamespaceId,
    fencing_token: NonZeroU64,
}

impl fmt::Debug for AuthenticatedNamespaceLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthenticatedNamespaceLease")
            .field("namespace", &self.namespace)
            .field("fencing_token", &self.fencing_token)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedNamespaceLease {
    pub const fn namespace(&self) -> OperationNamespaceId {
        self.namespace
    }

    pub const fn fencing_token(&self) -> NonZeroU64 {
        self.fencing_token
    }

    /// Confirm both live ownership and the exact durable fencing epoch.
    pub fn ensure_held(&self) -> Result<(), AuthenticatedNamespaceError> {
        self.ensure_live_owner()?;
        let image = self.store.load_namespace_image(self.namespace)?;
        let control = image.control.ok_or(AuthenticatedNamespaceError::Corrupt(
            "held namespace is missing its control record",
        ))?;
        if control.fencing_epoch != self.fencing_token.get() {
            return Err(AuthenticatedNamespaceError::LeaseLost);
        }
        Ok(())
    }

    /// Load the complete current image while checking the exact held epoch.
    pub fn load_complete_state(
        &self,
    ) -> Result<AuthenticatedNamespaceState, AuthenticatedNamespaceError> {
        self.ensure_live_owner()?;
        let image = self.store.load_namespace_image(self.namespace)?;
        let control = image.control.ok_or(AuthenticatedNamespaceError::Corrupt(
            "held namespace is missing its control record",
        ))?;
        if control.fencing_epoch != self.fencing_token.get() {
            return Err(AuthenticatedNamespaceError::LeaseLost);
        }
        image.public_state()
    }

    /// Compare the exact prior complete image and atomically install the
    /// proposal, its digest, and its minimum accepted revision while validating
    /// this guard's fencing epoch in the same backend publication section.
    pub fn compare_exchange_complete_state(
        &self,
        expectation: StateExpectation<'_>,
        proposed_revision: u64,
        proposed: &[u8],
    ) -> Result<AuthenticatedNamespaceWrite, AuthenticatedNamespaceError> {
        validate_proposed_state(proposed)?;
        self.ensure_live_owner()?;
        self.store.compare_exchange_namespace_image(
            self.namespace,
            self.fencing_token,
            expectation,
            proposed_revision,
            proposed,
        )
    }

    fn ensure_live_owner(&self) -> Result<(), AuthenticatedNamespaceError> {
        self.store.ensure_operational()?;
        if self.owner.owned.load(Ordering::Acquire)
            && self.owner.fencing_token.load(Ordering::Acquire) == self.fencing_token.get()
        {
            Ok(())
        } else {
            Err(AuthenticatedNamespaceError::LeaseLost)
        }
    }
}

impl Drop for AuthenticatedNamespaceLease {
    fn drop(&mut self) {
        if self
            .owner
            .fencing_token
            .compare_exchange(
                self.fencing_token.get(),
                0,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .is_ok()
        {
            self.owner.owned.store(false, Ordering::Release);
        }
        remove_unused_owner_cell(&self.owners, self.namespace, &self.owner);
    }
}

fn remove_unused_owner_cell(
    owners: &SharedNamespaceOwners,
    namespace: OperationNamespaceId,
    owner: &Arc<NamespaceOwnerCell>,
) {
    let mut owners = owners
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let weak_owner = Arc::downgrade(owner);
    let removable = !owner.owned.load(Ordering::Acquire)
        && Arc::strong_count(owner) == 1
        && owners
            .get(&namespace)
            .is_some_and(|current| current.ptr_eq(&weak_owner));
    if removable {
        owners.remove(&namespace);
    }
}

impl StoreHandle {
    /// Acquire sole ownership or fail immediately when the namespace is held.
    pub fn acquire_authenticated_namespace(
        &self,
        namespace: OperationNamespaceId,
    ) -> Result<AuthenticatedNamespaceLease, AuthenticatedNamespaceError> {
        self.try_acquire_authenticated_namespace(namespace)?
            .ok_or(AuthenticatedNamespaceError::Busy)
    }

    /// Try to acquire sole ownership without blocking on another operation.
    ///
    /// The store must already carry the exact current schema/profile and use
    /// synchronous durability. If a segment archive is live, this call must be
    /// made through that archived handle rather than a surviving raw alias.
    pub fn try_acquire_authenticated_namespace(
        &self,
        namespace: OperationNamespaceId,
    ) -> Result<Option<AuthenticatedNamespaceLease>, AuthenticatedNamespaceError> {
        self.ensure_operational()?;
        if self.durability_policy() != DurabilityPolicy::Sync {
            return Err(AuthenticatedNamespaceError::NonDurableStore);
        }
        require_initialized_schema(self)?;
        let owners = Arc::clone(self.authenticated_namespace_owners());
        let owner = {
            let mut current = owners
                .lock()
                .map_err(|_| AuthenticatedNamespaceError::OwnerRegistryPoisoned)?;
            match current.get(&namespace).and_then(Weak::upgrade) {
                Some(owner) => owner,
                None => {
                    let owner = Arc::new(NamespaceOwnerCell::default());
                    current.insert(namespace, Arc::downgrade(&owner));
                    owner
                }
            }
        };
        if owner
            .owned
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            remove_unused_owner_cell(&owners, namespace, &owner);
            return Ok(None);
        }
        let fencing_token = match self.reserve_namespace_epoch(namespace) {
            Ok(token) => token,
            Err(error) => {
                owner.owned.store(false, Ordering::Release);
                remove_unused_owner_cell(&owners, namespace, &owner);
                return Err(error);
            }
        };
        owner
            .fencing_token
            .store(fencing_token.get(), Ordering::Release);
        Ok(Some(AuthenticatedNamespaceLease {
            store: self.clone(),
            owners,
            owner,
            namespace,
            fencing_token,
        }))
    }

    fn authenticated_namespace_owners(&self) -> &SharedNamespaceOwners {
        match self {
            Self::Memory(store) => &store.authenticated_namespaces,
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(store) => &store.authenticated_namespaces,
            Self::Archived { inner, .. } => inner.authenticated_namespace_owners(),
        }
    }

    pub(super) fn authenticated_namespace_archive_registration(
        &self,
    ) -> &SharedNamespaceArchiveRegistration {
        match self {
            Self::Memory(store) => &store.authenticated_namespace_archive,
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(store) => &store.authenticated_namespace_archive,
            Self::Archived { inner, .. } => inner.authenticated_namespace_archive_registration(),
        }
    }

    fn lock_namespace_archive_registration(
        &self,
        expected: Option<&Arc<SegmentArchive>>,
    ) -> Result<MutexGuard<'_, Option<Weak<SegmentArchive>>>, AuthenticatedNamespaceError> {
        let registration = self
            .authenticated_namespace_archive_registration()
            .lock()
            .map_err(|_| AuthenticatedNamespaceError::ArchiveRegistryPoisoned)?;
        match (expected, registration.as_ref()) {
            (None, Some(_)) => return Err(AuthenticatedNamespaceError::ArchiveHandleRequired),
            (Some(expected), Some(registered)) => match registered.upgrade() {
                Some(live) if Arc::ptr_eq(expected, &live) => {}
                _ => return Err(AuthenticatedNamespaceError::ArchiveRegistrationMismatch),
            },
            (Some(_), None) => {
                return Err(AuthenticatedNamespaceError::ArchiveRegistrationMismatch);
            }
            (None, None) => {}
        }
        Ok(registration)
    }

    fn reserve_namespace_epoch(
        &self,
        namespace: OperationNamespaceId,
    ) -> Result<NonZeroU64, AuthenticatedNamespaceError> {
        match self {
            Self::Memory(_) => {
                let _registration = self.lock_namespace_archive_registration(None)?;
                self.reserve_physical_namespace_epoch(namespace)
            }
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(_) => {
                let _registration = self.lock_namespace_archive_registration(None)?;
                self.reserve_physical_namespace_epoch(namespace)
            }
            Self::Archived { inner, archive, .. } => {
                let _registration = inner.lock_namespace_archive_registration(Some(archive))?;
                let _writer = archive.writer().map_err(segment_store_error)?;
                inner.reserve_physical_namespace_epoch(namespace)
            }
        }
    }

    fn reserve_physical_namespace_epoch(
        &self,
        namespace: OperationNamespaceId,
    ) -> Result<NonZeroU64, AuthenticatedNamespaceError> {
        match self {
            Self::Memory(store) => reserve_memory_namespace_epoch(store, namespace),
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(store) => reserve_rocks_namespace_epoch(store, namespace),
            Self::Archived { .. } => Err(AuthenticatedNamespaceError::ArchiveRegistrationMismatch),
        }
    }

    fn load_namespace_image(
        &self,
        namespace: OperationNamespaceId,
    ) -> Result<NamespaceImage, AuthenticatedNamespaceError> {
        self.ensure_operational()?;
        match self {
            Self::Memory(_) => {
                let _registration = self.lock_namespace_archive_registration(None)?;
                self.load_physical_namespace_image(namespace)
            }
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(_) => {
                let _registration = self.lock_namespace_archive_registration(None)?;
                self.load_physical_namespace_image(namespace)
            }
            Self::Archived { inner, archive, .. } => {
                let _registration = inner.lock_namespace_archive_registration(Some(archive))?;
                let _writer = archive.writer().map_err(segment_store_error)?;
                inner.load_physical_namespace_image(namespace)
            }
        }
    }

    fn load_physical_namespace_image(
        &self,
        namespace: OperationNamespaceId,
    ) -> Result<NamespaceImage, AuthenticatedNamespaceError> {
        match self {
            Self::Memory(store) => load_memory_namespace_image(store, namespace),
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(store) => load_rocks_namespace_image(store, namespace),
            Self::Archived { .. } => Err(AuthenticatedNamespaceError::ArchiveRegistrationMismatch),
        }
    }

    fn compare_exchange_namespace_image(
        &self,
        namespace: OperationNamespaceId,
        fencing_token: NonZeroU64,
        expectation: StateExpectation<'_>,
        proposed_revision: u64,
        proposed: &[u8],
    ) -> Result<AuthenticatedNamespaceWrite, AuthenticatedNamespaceError> {
        self.ensure_operational()?;
        match self {
            Self::Memory(_) => {
                let _registration = self.lock_namespace_archive_registration(None)?;
                self.compare_exchange_physical_namespace_image(
                    namespace,
                    fencing_token,
                    expectation,
                    proposed_revision,
                    proposed,
                )
            }
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(_) => {
                let _registration = self.lock_namespace_archive_registration(None)?;
                self.compare_exchange_physical_namespace_image(
                    namespace,
                    fencing_token,
                    expectation,
                    proposed_revision,
                    proposed,
                )
            }
            Self::Archived { inner, archive, .. } => {
                let _registration = inner.lock_namespace_archive_registration(Some(archive))?;
                let _writer = archive.writer().map_err(segment_store_error)?;
                inner.compare_exchange_physical_namespace_image(
                    namespace,
                    fencing_token,
                    expectation,
                    proposed_revision,
                    proposed,
                )
            }
        }
    }

    fn compare_exchange_physical_namespace_image(
        &self,
        namespace: OperationNamespaceId,
        fencing_token: NonZeroU64,
        expectation: StateExpectation<'_>,
        proposed_revision: u64,
        proposed: &[u8],
    ) -> Result<AuthenticatedNamespaceWrite, AuthenticatedNamespaceError> {
        match self {
            Self::Memory(store) => compare_exchange_memory_namespace(
                store,
                namespace,
                fencing_token,
                expectation,
                proposed_revision,
                proposed,
            ),
            #[cfg(feature = "rocksdb-backend")]
            Self::Rocks(store) => compare_exchange_rocks_namespace(
                store,
                namespace,
                fencing_token,
                expectation,
                proposed_revision,
                proposed,
            ),
            Self::Archived { .. } => Err(AuthenticatedNamespaceError::ArchiveRegistrationMismatch),
        }
    }
}

fn require_initialized_schema(store: &StoreHandle) -> Result<(), AuthenticatedNamespaceError> {
    let snapshot = store.snapshot()?;
    let schema = snapshot.get(ColumnFamily::Meta, crate::MetaKey::SchemaVersion.as_bytes())?;
    let profile = snapshot.get(
        ColumnFamily::Meta,
        crate::MetaKey::StorageProfile.as_bytes(),
    )?;
    let name_tree_root =
        snapshot.get(ColumnFamily::Meta, crate::MetaKey::NameTreeRoot.as_bytes())?;
    let name_tree_commit_root = snapshot.get(
        ColumnFamily::Meta,
        crate::MetaKey::NameTreeCommitRoot.as_bytes(),
    )?;
    let airdrop_field =
        snapshot.get(ColumnFamily::Meta, crate::MetaKey::AirdropField.as_bytes())?;
    let block_manifest =
        snapshot.get(ColumnFamily::Snapshots, crate::BLOCK_SEGMENT_MANIFEST_KEY)?;
    let undo_manifest = snapshot.get(ColumnFamily::Snapshots, crate::UNDO_SEGMENT_MANIFEST_KEY)?;
    drop(snapshot);
    validate_initialized_schema_records(
        schema.as_deref(),
        profile.as_deref(),
        name_tree_root.as_deref(),
        name_tree_commit_root.as_deref(),
        airdrop_field.as_deref(),
    )?;
    match (block_manifest, undo_manifest) {
        (Some(_), Some(_)) if !matches!(store, StoreHandle::Archived { .. }) => {
            return Err(AuthenticatedNamespaceError::ArchiveHandleRequired);
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(StoreError::Schema(
                "authenticated namespace found partially initialized segment manifests".to_owned(),
            )
            .into());
        }
        _ => {}
    }
    Ok(())
}

fn validate_initialized_schema_records(
    schema: Option<&[u8]>,
    profile: Option<&[u8]>,
    name_tree_root: Option<&[u8]>,
    name_tree_commit_root: Option<&[u8]>,
    airdrop_field: Option<&[u8]>,
) -> Result<(), AuthenticatedNamespaceError> {
    let schema = schema.ok_or_else(|| {
        StoreError::Schema(
            "authenticated namespace acquisition requires an initialized store schema".to_owned(),
        )
    })?;
    let version = crate::decode_u32(schema)?;
    if version != crate::SCHEMA_VERSION {
        return Err(StoreError::Schema(format!(
            "authenticated namespace requires schema version {}, got {version}",
            crate::SCHEMA_VERSION
        ))
        .into());
    }
    let profile = profile.ok_or_else(|| {
        StoreError::Schema("authenticated namespace requires a storage-profile marker".to_owned())
    })?;
    if profile != crate::STORAGE_PROFILE {
        return Err(StoreError::Schema(
            "authenticated namespace storage profile does not match the current profile".to_owned(),
        )
        .into());
    }
    for (label, value, expected) in [
        ("name-tree-root", name_tree_root, 32),
        ("name-tree-commit-root", name_tree_commit_root, 32),
        ("airdrop-field", airdrop_field, crate::AIRDROP_FIELD_BYTES),
    ] {
        let value = value.ok_or_else(|| {
            StoreError::Schema(format!(
                "authenticated namespace requires the durable {label} binding"
            ))
        })?;
        if value.len() != expected {
            return Err(StoreError::Schema(format!(
                "authenticated namespace durable {label} binding has {} bytes; expected {expected}",
                value.len()
            ))
            .into());
        }
    }
    Ok(())
}

/// Reject ordinary batch access to the namespace module's control/state keys.
pub(super) fn ensure_ordinary_key(family: ColumnFamily, key: &[u8]) -> Result<(), StoreError> {
    let reserved = match family {
        ColumnFamily::Meta => key.starts_with(CONTROL_KEY_PREFIX),
        ColumnFamily::Snapshots => key.starts_with(STATE_KEY_PREFIX),
        _ => false,
    };
    if reserved {
        return Err(StoreError::Schema(
            "authenticated namespace keys are reserved for fenced publication".to_owned(),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NamespaceControl {
    fencing_epoch: u64,
    initialized: bool,
    minimum_revision: u64,
    state_digest: [u8; 32],
}

impl NamespaceControl {
    fn uninitialized(fencing_epoch: u64) -> Self {
        Self {
            fencing_epoch,
            initialized: false,
            minimum_revision: 0,
            state_digest: [0; 32],
        }
    }

    fn initialized(
        fencing_epoch: u64,
        minimum_revision: u64,
        namespace: OperationNamespaceId,
        state: &[u8],
    ) -> Self {
        Self {
            fencing_epoch,
            initialized: true,
            minimum_revision,
            state_digest: state_digest(namespace, state),
        }
    }

    fn encode(self, namespace: OperationNamespaceId) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(CONTROL_BYTES);
        encoded.extend_from_slice(CONTROL_MAGIC);
        encoded.push(CONTROL_VERSION);
        encoded.extend_from_slice(namespace.as_bytes());
        encoded.extend_from_slice(&self.fencing_epoch.to_be_bytes());
        encoded.push(u8::from(self.initialized));
        encoded.extend_from_slice(&self.minimum_revision.to_be_bytes());
        encoded.extend_from_slice(&self.state_digest);
        debug_assert_eq!(encoded.len(), CONTROL_BODY_BYTES);
        let checksum = blake2b_256_many([CONTROL_CHECKSUM_DOMAIN, encoded.as_slice()]);
        encoded.extend_from_slice(&checksum);
        encoded
    }

    fn decode(
        namespace: OperationNamespaceId,
        encoded: &[u8],
    ) -> Result<Self, AuthenticatedNamespaceError> {
        if encoded.len() != CONTROL_BYTES {
            return Err(AuthenticatedNamespaceError::Corrupt(
                "control record has the wrong size",
            ));
        }
        let (body, checksum) = encoded.split_at(CONTROL_BODY_BYTES);
        let expected = blake2b_256_many([CONTROL_CHECKSUM_DOMAIN, body]);
        if checksum != expected {
            return Err(AuthenticatedNamespaceError::Corrupt(
                "control checksum mismatch",
            ));
        }
        if &body[..8] != CONTROL_MAGIC || body[8] != CONTROL_VERSION {
            return Err(AuthenticatedNamespaceError::Corrupt(
                "unsupported control magic or version",
            ));
        }
        if &body[9..41] != namespace.as_bytes() {
            return Err(AuthenticatedNamespaceError::Corrupt(
                "control namespace binding mismatch",
            ));
        }
        let fencing_epoch = u64::from_be_bytes(
            body[41..49]
                .try_into()
                .expect("fixed control fencing epoch"),
        );
        if fencing_epoch == 0 {
            return Err(AuthenticatedNamespaceError::Corrupt(
                "control fencing epoch is zero",
            ));
        }
        let initialized = match body[49] {
            0 => false,
            1 => true,
            _ => {
                return Err(AuthenticatedNamespaceError::Corrupt(
                    "control initialized flag is invalid",
                ));
            }
        };
        let minimum_revision = u64::from_be_bytes(
            body[50..58]
                .try_into()
                .expect("fixed control minimum revision"),
        );
        let state_digest = body[58..90].try_into().expect("fixed control state digest");
        if !initialized && (minimum_revision != 0 || state_digest != [0; 32]) {
            return Err(AuthenticatedNamespaceError::Corrupt(
                "uninitialized control retains state metadata",
            ));
        }
        Ok(Self {
            fencing_epoch,
            initialized,
            minimum_revision,
            state_digest,
        })
    }
}

#[derive(Debug)]
struct NamespaceImage {
    control: Option<NamespaceControl>,
    state: Option<Vec<u8>>,
}

impl NamespaceImage {
    fn decode(
        namespace: OperationNamespaceId,
        control: Option<Vec<u8>>,
        state: Option<Vec<u8>>,
    ) -> Result<Self, AuthenticatedNamespaceError> {
        let control = control
            .map(|encoded| NamespaceControl::decode(namespace, &encoded))
            .transpose()?;
        match (control, state.as_deref()) {
            (None, None) => {}
            (None, Some(_)) => {
                return Err(AuthenticatedNamespaceError::Corrupt(
                    "state exists without a control record",
                ));
            }
            (Some(control), None) if control.initialized => {
                return Err(AuthenticatedNamespaceError::Corrupt(
                    "initialized control is missing complete state",
                ));
            }
            (Some(control), Some(_)) if !control.initialized => {
                return Err(AuthenticatedNamespaceError::Corrupt(
                    "uninitialized control has unexpected state",
                ));
            }
            (Some(control), Some(state)) => {
                validate_proposed_state(state)?;
                if state_digest(namespace, state) != control.state_digest {
                    return Err(AuthenticatedNamespaceError::Corrupt(
                        "complete-state digest mismatch",
                    ));
                }
            }
            (Some(_), None) => {}
        }
        Ok(Self { control, state })
    }

    fn public_state(self) -> Result<AuthenticatedNamespaceState, AuthenticatedNamespaceError> {
        let control = self.control.ok_or(AuthenticatedNamespaceError::Corrupt(
            "namespace control record is absent",
        ))?;
        match (control.initialized, self.state) {
            (false, None) => Ok(AuthenticatedNamespaceState::NeverInitialized),
            (true, Some(encoded)) => Ok(AuthenticatedNamespaceState::Initialized {
                encoded,
                minimum_revision: control.minimum_revision,
            }),
            _ => Err(AuthenticatedNamespaceError::Corrupt(
                "namespace topology changed after validation",
            )),
        }
    }
}

fn validate_proposed_state(proposed: &[u8]) -> Result<(), AuthenticatedNamespaceError> {
    if proposed.is_empty() {
        return Err(AuthenticatedNamespaceError::EmptyState);
    }
    if proposed.len() > AUTHENTICATED_NAMESPACE_MAX_STATE_BYTES {
        return Err(AuthenticatedNamespaceError::StateTooLarge {
            actual: proposed.len(),
            maximum: AUTHENTICATED_NAMESPACE_MAX_STATE_BYTES,
        });
    }
    Ok(())
}

fn control_key(namespace: OperationNamespaceId) -> Vec<u8> {
    let mut key = Vec::with_capacity(CONTROL_KEY_PREFIX.len() + 32);
    key.extend_from_slice(CONTROL_KEY_PREFIX);
    key.extend_from_slice(namespace.as_bytes());
    key
}

fn state_key(namespace: OperationNamespaceId) -> Vec<u8> {
    let mut key = Vec::with_capacity(STATE_KEY_PREFIX.len() + 32);
    key.extend_from_slice(STATE_KEY_PREFIX);
    key.extend_from_slice(namespace.as_bytes());
    key
}

fn state_digest(namespace: OperationNamespaceId, state: &[u8]) -> [u8; 32] {
    blake2b_256_many([STATE_DIGEST_DOMAIN, namespace.as_bytes(), state])
}

fn next_epoch(
    current: Option<NamespaceControl>,
) -> Result<NonZeroU64, AuthenticatedNamespaceError> {
    let previous = current.map_or(0, |control| control.fencing_epoch);
    previous
        .checked_add(1)
        .and_then(NonZeroU64::new)
        .ok_or(AuthenticatedNamespaceError::FencingEpochExhausted)
}

fn current_memory_value(
    state: &MemoryStoreState,
    family: ColumnFamily,
    key: &[u8],
) -> Option<Vec<u8>> {
    state
        .data
        .get(&StoreKey::new(family, key))
        .and_then(|history| memory_value_at(history, state.generation))
        .cloned()
}

fn memory_namespace_image(
    state: &MemoryStoreState,
    namespace: OperationNamespaceId,
) -> Result<NamespaceImage, AuthenticatedNamespaceError> {
    validate_initialized_schema_records(
        current_memory_value(
            state,
            ColumnFamily::Meta,
            crate::MetaKey::SchemaVersion.as_bytes(),
        )
        .as_deref(),
        current_memory_value(
            state,
            ColumnFamily::Meta,
            crate::MetaKey::StorageProfile.as_bytes(),
        )
        .as_deref(),
        current_memory_value(
            state,
            ColumnFamily::Meta,
            crate::MetaKey::NameTreeRoot.as_bytes(),
        )
        .as_deref(),
        current_memory_value(
            state,
            ColumnFamily::Meta,
            crate::MetaKey::NameTreeCommitRoot.as_bytes(),
        )
        .as_deref(),
        current_memory_value(
            state,
            ColumnFamily::Meta,
            crate::MetaKey::AirdropField.as_bytes(),
        )
        .as_deref(),
    )?;
    NamespaceImage::decode(
        namespace,
        current_memory_value(state, ColumnFamily::Meta, &control_key(namespace)),
        current_memory_value(state, ColumnFamily::Snapshots, &state_key(namespace)),
    )
}

fn reserve_memory_namespace_epoch(
    store: &MemoryStore,
    namespace: OperationNamespaceId,
) -> Result<NonZeroU64, AuthenticatedNamespaceError> {
    let mut state = store
        .inner
        .write()
        .map_err(|_| StoreError::Io("memory store write lock poisoned".to_owned()))?;
    let image = memory_namespace_image(&state, namespace)?;
    let token = next_epoch(image.control)?;
    let next_control = match image.control {
        Some(control) => NamespaceControl {
            fencing_epoch: token.get(),
            ..control
        },
        None => NamespaceControl::uninitialized(token.get()),
    };
    let mut changes = BatchOperations::new();
    changes.insert(
        StoreKey::new(ColumnFamily::Meta, &control_key(namespace)),
        Some(next_control.encode(namespace)),
    );
    apply_memory_changes(&mut state, changes)?;
    Ok(token)
}

fn load_memory_namespace_image(
    store: &MemoryStore,
    namespace: OperationNamespaceId,
) -> Result<NamespaceImage, AuthenticatedNamespaceError> {
    let state = store
        .inner
        .read()
        .map_err(|_| StoreError::Io("memory store read lock poisoned".to_owned()))?;
    memory_namespace_image(&state, namespace)
}

fn compare_exchange_memory_namespace(
    store: &MemoryStore,
    namespace: OperationNamespaceId,
    fencing_token: NonZeroU64,
    expectation: StateExpectation<'_>,
    proposed_revision: u64,
    proposed: &[u8],
) -> Result<AuthenticatedNamespaceWrite, AuthenticatedNamespaceError> {
    let mut state = store
        .inner
        .write()
        .map_err(|_| StoreError::Io("memory store write lock poisoned".to_owned()))?;
    let image = memory_namespace_image(&state, namespace)?;
    let control = image.control.ok_or(AuthenticatedNamespaceError::Corrupt(
        "held namespace is missing its control record",
    ))?;
    let (outcome, replacement) = prepare_replacement(
        namespace,
        control,
        image.state.as_deref(),
        fencing_token,
        expectation,
        proposed_revision,
        proposed,
    )?;
    let Some(control) = replacement else {
        return Ok(outcome);
    };
    let mut changes = BatchOperations::new();
    changes.insert(
        StoreKey::new(ColumnFamily::Meta, &control_key(namespace)),
        Some(control.encode(namespace)),
    );
    changes.insert(
        StoreKey::new(ColumnFamily::Snapshots, &state_key(namespace)),
        Some(proposed.to_vec()),
    );
    apply_memory_changes(&mut state, changes)?;
    Ok(outcome)
}

fn prepare_replacement(
    namespace: OperationNamespaceId,
    control: NamespaceControl,
    current_state: Option<&[u8]>,
    fencing_token: NonZeroU64,
    expectation: StateExpectation<'_>,
    proposed_revision: u64,
    proposed: &[u8],
) -> Result<(AuthenticatedNamespaceWrite, Option<NamespaceControl>), AuthenticatedNamespaceError> {
    if control.fencing_epoch != fencing_token.get() {
        return Err(AuthenticatedNamespaceError::LeaseLost);
    }
    if control.initialized
        && control.minimum_revision == proposed_revision
        && current_state == Some(proposed)
    {
        return Ok((AuthenticatedNamespaceWrite::AlreadyCommitted, None));
    }
    let matched = match expectation {
        StateExpectation::Absent => !control.initialized && current_state.is_none(),
        StateExpectation::Exact {
            minimum_revision,
            encoded,
        } => {
            control.initialized
                && control.minimum_revision == minimum_revision
                && current_state == Some(encoded)
        }
    };
    if !matched {
        return Ok((AuthenticatedNamespaceWrite::Conflict, None));
    }
    if control.initialized && proposed_revision <= control.minimum_revision {
        return Err(AuthenticatedNamespaceError::RevisionNotAdvanced {
            current: control.minimum_revision,
            proposed: proposed_revision,
        });
    }
    Ok((
        AuthenticatedNamespaceWrite::Committed,
        Some(NamespaceControl::initialized(
            control.fencing_epoch,
            proposed_revision,
            namespace,
            proposed,
        )),
    ))
}

#[cfg(feature = "rocksdb-backend")]
fn rocks_namespace_image_locked(
    store: &RocksStore,
    namespace: OperationNamespaceId,
) -> Result<NamespaceImage, AuthenticatedNamespaceError> {
    let control_cf = RocksStore::cf(&store.db, ColumnFamily::Meta)?;
    let state_cf = RocksStore::cf(&store.db, ColumnFamily::Snapshots)?;
    let schema = store
        .db
        .get_pinned_cf(control_cf, crate::MetaKey::SchemaVersion.as_bytes())
        .map_err(|error| StoreError::Backend(error.to_string()))?;
    let profile = store
        .db
        .get_pinned_cf(control_cf, crate::MetaKey::StorageProfile.as_bytes())
        .map_err(|error| StoreError::Backend(error.to_string()))?;
    let name_tree_root = store
        .db
        .get_pinned_cf(control_cf, crate::MetaKey::NameTreeRoot.as_bytes())
        .map_err(|error| StoreError::Backend(error.to_string()))?;
    let name_tree_commit_root = store
        .db
        .get_pinned_cf(control_cf, crate::MetaKey::NameTreeCommitRoot.as_bytes())
        .map_err(|error| StoreError::Backend(error.to_string()))?;
    let airdrop_field = store
        .db
        .get_pinned_cf(control_cf, crate::MetaKey::AirdropField.as_bytes())
        .map_err(|error| StoreError::Backend(error.to_string()))?;
    validate_initialized_schema_records(
        schema.as_deref(),
        profile.as_deref(),
        name_tree_root.as_deref(),
        name_tree_commit_root.as_deref(),
        airdrop_field.as_deref(),
    )?;
    let control = store
        .db
        .get_pinned_cf(control_cf, control_key(namespace))
        .map_err(|error| StoreError::Backend(error.to_string()))?;
    if control
        .as_ref()
        .is_some_and(|encoded| encoded.len() != CONTROL_BYTES)
    {
        return Err(AuthenticatedNamespaceError::Corrupt(
            "control record has the wrong size",
        ));
    }
    let state = store
        .db
        .get_pinned_cf(state_cf, state_key(namespace))
        .map_err(|error| StoreError::Backend(error.to_string()))?;
    if let Some(encoded) = state.as_ref() {
        validate_proposed_state(encoded)?;
    }
    NamespaceImage::decode(
        namespace,
        control.map(|encoded| encoded.as_ref().to_vec()),
        state.map(|encoded| encoded.as_ref().to_vec()),
    )
}

#[cfg(feature = "rocksdb-backend")]
fn reserve_rocks_namespace_epoch(
    store: &RocksStore,
    namespace: OperationNamespaceId,
) -> Result<NonZeroU64, AuthenticatedNamespaceError> {
    let _publication = store.lock_publication()?;
    store.ensure_operational()?;
    let image = rocks_namespace_image_locked(store, namespace)?;
    let token = next_epoch(image.control)?;
    let next_control = match image.control {
        Some(control) => NamespaceControl {
            fencing_epoch: token.get(),
            ..control
        },
        None => NamespaceControl::uninitialized(token.get()),
    };
    let mut changes = BatchOperations::new();
    changes.insert(
        StoreKey::new(ColumnFamily::Meta, &control_key(namespace)),
        Some(next_control.encode(namespace)),
    );
    store.commit_operations_locked(changes)?;
    Ok(token)
}

#[cfg(feature = "rocksdb-backend")]
fn load_rocks_namespace_image(
    store: &RocksStore,
    namespace: OperationNamespaceId,
) -> Result<NamespaceImage, AuthenticatedNamespaceError> {
    let _publication = store.lock_publication()?;
    store.ensure_operational()?;
    rocks_namespace_image_locked(store, namespace)
}

#[cfg(feature = "rocksdb-backend")]
fn compare_exchange_rocks_namespace(
    store: &RocksStore,
    namespace: OperationNamespaceId,
    fencing_token: NonZeroU64,
    expectation: StateExpectation<'_>,
    proposed_revision: u64,
    proposed: &[u8],
) -> Result<AuthenticatedNamespaceWrite, AuthenticatedNamespaceError> {
    let _publication = store.lock_publication()?;
    store.ensure_operational()?;
    let image = rocks_namespace_image_locked(store, namespace)?;
    let control = image.control.ok_or(AuthenticatedNamespaceError::Corrupt(
        "held namespace is missing its control record",
    ))?;
    let (outcome, replacement) = prepare_replacement(
        namespace,
        control,
        image.state.as_deref(),
        fencing_token,
        expectation,
        proposed_revision,
        proposed,
    )?;
    let Some(control) = replacement else {
        return Ok(outcome);
    };
    let mut changes = BatchOperations::new();
    changes.insert(
        StoreKey::new(ColumnFamily::Meta, &control_key(namespace)),
        Some(control.encode(namespace)),
    );
    changes.insert(
        StoreKey::new(ColumnFamily::Snapshots, &state_key(namespace)),
        Some(proposed.to_vec()),
    );
    store.commit_operations_locked(changes)?;
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ReadSnapshot, Store, WriteBatch};

    #[cfg(feature = "rocksdb-backend")]
    fn temporary_directory(label: &str) -> std::path::PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "hsrd-authenticated-namespace-{label}-{}-{nonce}",
            std::process::id()
        ));
        assert!(!path.exists(), "temporary fixture unexpectedly exists");
        path
    }

    fn directory_image(
        directory: &std::path::Path,
    ) -> std::collections::BTreeMap<std::ffi::OsString, Vec<u8>> {
        std::fs::read_dir(directory)
            .expect("read archive directory")
            .map(|entry| {
                let entry = entry.expect("archive entry");
                assert!(entry.file_type().expect("archive file type").is_file());
                (
                    entry.file_name(),
                    std::fs::read(entry.path()).expect("read archive file"),
                )
            })
            .collect()
    }

    fn namespace(byte: u8) -> OperationNamespaceId {
        OperationNamespaceId::new([byte; 32]).expect("nonzero namespace")
    }

    #[test]
    fn memory_namespace_create_replace_restart_and_retry_are_exact() {
        let store = StoreHandle::memory();
        crate::initialize_schema(&store).expect("initialize schema");
        let key = namespace(1);
        let lease = store
            .acquire_authenticated_namespace(key)
            .expect("acquire namespace");
        assert_eq!(lease.fencing_token().get(), 1);
        assert_eq!(
            lease.load_complete_state().expect("load new namespace"),
            AuthenticatedNamespaceState::NeverInitialized
        );
        assert_eq!(
            lease
                .compare_exchange_complete_state(StateExpectation::Absent, 0, b"revision-zero")
                .expect("create state"),
            AuthenticatedNamespaceWrite::Committed
        );
        assert_eq!(
            lease
                .compare_exchange_complete_state(StateExpectation::Absent, 0, b"revision-zero")
                .expect("retry create"),
            AuthenticatedNamespaceWrite::AlreadyCommitted
        );
        assert_eq!(
            lease
                .compare_exchange_complete_state(
                    StateExpectation::Exact {
                        minimum_revision: 99,
                        encoded: b"revision-zero",
                    },
                    1,
                    b"revision-one",
                )
                .expect("conflicting exact revision"),
            AuthenticatedNamespaceWrite::Conflict
        );
        assert_eq!(
            lease
                .compare_exchange_complete_state(
                    StateExpectation::Exact {
                        minimum_revision: 0,
                        encoded: b"wrong",
                    },
                    1,
                    b"revision-one",
                )
                .expect("conflicting exact image"),
            AuthenticatedNamespaceWrite::Conflict
        );
        assert_eq!(
            lease
                .compare_exchange_complete_state(
                    StateExpectation::Exact {
                        minimum_revision: 0,
                        encoded: b"revision-zero",
                    },
                    1,
                    b"revision-one",
                )
                .expect("replace state"),
            AuthenticatedNamespaceWrite::Committed
        );
        assert_eq!(
            lease.load_complete_state().expect("load replacement"),
            AuthenticatedNamespaceState::Initialized {
                encoded: b"revision-one".to_vec(),
                minimum_revision: 1,
            }
        );
        drop(lease);

        let reopened = store
            .acquire_authenticated_namespace(key)
            .expect("reacquire namespace");
        assert_eq!(reopened.fencing_token().get(), 2);
        assert_eq!(
            reopened
                .load_complete_state()
                .expect("load after reacquire"),
            AuthenticatedNamespaceState::Initialized {
                encoded: b"revision-one".to_vec(),
                minimum_revision: 1,
            }
        );
    }

    #[test]
    fn memory_namespace_clones_exclude_and_distinct_namespaces_isolate() {
        let store = StoreHandle::memory();
        crate::initialize_schema(&store).expect("initialize schema");
        let clone = store.clone();
        let first = store
            .acquire_authenticated_namespace(namespace(2))
            .expect("first owner");
        assert!(matches!(
            clone.acquire_authenticated_namespace(namespace(2)),
            Err(AuthenticatedNamespaceError::Busy)
        ));
        let distinct = clone
            .acquire_authenticated_namespace(namespace(3))
            .expect("distinct owner");
        assert_eq!(distinct.fencing_token().get(), 1);
        drop(first);
        let second = clone
            .acquire_authenticated_namespace(namespace(2))
            .expect("second owner");
        assert_eq!(second.fencing_token().get(), 2);
    }

    #[test]
    fn namespace_acquisition_requires_schema_before_control_state() {
        let store = StoreHandle::memory();
        assert!(matches!(
            store.acquire_authenticated_namespace(namespace(19)),
            Err(AuthenticatedNamespaceError::Store(StoreError::Schema(_)))
        ));
        let empty = store.snapshot().expect("empty snapshot");
        assert_eq!(
            empty
                .get(ColumnFamily::Meta, crate::MetaKey::SchemaVersion.as_bytes())
                .expect("absent schema marker"),
            None
        );
        assert_eq!(
            empty
                .get(ColumnFamily::Meta, &control_key(namespace(19)))
                .expect("absent namespace control"),
            None
        );
        drop(empty);
        crate::initialize_schema(&store).expect("initialize schema explicitly");
        let lease = store
            .acquire_authenticated_namespace(namespace(19))
            .expect("acquire initialized store");
        crate::initialize_schema(&store).expect("schema remains valid after acquisition");
        let snapshot = store.snapshot().expect("schema snapshot");
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, crate::MetaKey::SchemaVersion.as_bytes())
                .expect("schema marker read"),
            Some(crate::encode_u32(crate::SCHEMA_VERSION).to_vec())
        );
        drop(snapshot);
        drop(lease);
    }

    #[test]
    fn held_namespace_revalidates_schema_inside_each_physical_operation() {
        let store = StoreHandle::memory();
        crate::initialize_schema(&store).expect("initialize schema");
        let lease = store
            .acquire_authenticated_namespace(namespace(25))
            .expect("acquire namespace");
        let mut corrupt = store.batch();
        corrupt
            .put(
                ColumnFamily::Meta,
                crate::MetaKey::StorageProfile.as_bytes(),
                b"wrong-profile",
            )
            .expect("stage corrupt profile");
        store.commit(corrupt).expect("commit corrupt profile");
        assert!(matches!(
            lease.ensure_held(),
            Err(AuthenticatedNamespaceError::Store(StoreError::Schema(_)))
        ));
        assert!(matches!(
            lease.compare_exchange_complete_state(StateExpectation::Absent, 0, b"blocked"),
            Err(AuthenticatedNamespaceError::Store(StoreError::Schema(_)))
        ));

        let mut repair = store.batch();
        repair
            .put(
                ColumnFamily::Meta,
                crate::MetaKey::StorageProfile.as_bytes(),
                crate::STORAGE_PROFILE,
            )
            .expect("stage profile repair");
        store.commit(repair).expect("commit profile repair");
        lease.ensure_held().expect("valid schema restores access");
    }

    #[test]
    fn memory_namespace_rejects_revision_regression_empty_and_oversize() {
        assert!(matches!(
            OperationNamespaceId::new([0; 32]),
            Err(AuthenticatedNamespaceError::ZeroNamespace)
        ));
        let store = StoreHandle::memory();
        crate::initialize_schema(&store).expect("initialize schema");
        let lease = store
            .acquire_authenticated_namespace(namespace(4))
            .expect("owner");
        lease
            .compare_exchange_complete_state(StateExpectation::Absent, 7, b"current")
            .expect("create current");
        assert!(matches!(
            lease.compare_exchange_complete_state(
                StateExpectation::Exact {
                    minimum_revision: 7,
                    encoded: b"current",
                },
                7,
                b"different"
            ),
            Err(AuthenticatedNamespaceError::RevisionNotAdvanced {
                current: 7,
                proposed: 7
            })
        ));
        assert!(matches!(
            lease.compare_exchange_complete_state(
                StateExpectation::Exact {
                    minimum_revision: 7,
                    encoded: b"current",
                },
                8,
                b""
            ),
            Err(AuthenticatedNamespaceError::EmptyState)
        ));
        let oversized = vec![0; AUTHENTICATED_NAMESPACE_MAX_STATE_BYTES + 1];
        assert!(matches!(
            lease.compare_exchange_complete_state(
                StateExpectation::Exact {
                    minimum_revision: 7,
                    encoded: b"current",
                },
                8,
                &oversized
            ),
            Err(AuthenticatedNamespaceError::StateTooLarge { .. })
        ));
        let maximum = vec![0x5a; AUTHENTICATED_NAMESPACE_MAX_STATE_BYTES];
        assert_eq!(
            lease
                .compare_exchange_complete_state(
                    StateExpectation::Exact {
                        minimum_revision: 7,
                        encoded: b"current",
                    },
                    8,
                    &maximum,
                )
                .expect("accept exact maximum state"),
            AuthenticatedNamespaceWrite::Committed
        );
        assert!(matches!(
            lease.load_complete_state().expect("load maximum state"),
            AuthenticatedNamespaceState::Initialized {
                encoded,
                minimum_revision: 8,
            } if encoded.len() == AUTHENTICATED_NAMESPACE_MAX_STATE_BYTES
        ));
    }

    #[test]
    fn ordinary_batches_cannot_mutate_reserved_namespace_records() {
        let store = StoreHandle::memory();
        let key = namespace(5);
        let mut batch = store.batch();
        assert!(batch
            .put(ColumnFamily::Meta, &control_key(key), b"bypass")
            .is_err());
        assert!(batch
            .delete(ColumnFamily::Snapshots, &state_key(key))
            .is_err());
        assert!(matches!(
            &batch,
            crate::StoreHandleBatch::Memory(batch) if batch.is_empty()
        ));
    }

    #[test]
    fn memory_namespace_corrupt_partial_topology_fails_closed() {
        let store = StoreHandle::memory();
        crate::initialize_schema(&store).expect("initialize schema");
        let key = namespace(6);
        let StoreHandle::Memory(memory) = &store else {
            unreachable!();
        };
        let mut state = memory.inner.write().expect("memory write lock");
        let mut changes = BatchOperations::new();
        changes.insert(
            StoreKey::new(ColumnFamily::Snapshots, &state_key(key)),
            Some(b"orphan".to_vec()),
        );
        apply_memory_changes(&mut state, changes).expect("inject orphan state");
        drop(state);
        assert!(matches!(
            store.acquire_authenticated_namespace(key),
            Err(AuthenticatedNamespaceError::Corrupt(
                "state exists without a control record"
            ))
        ));
    }

    #[test]
    fn ordinary_memory_commit_rechecks_reserved_keys_authoritatively() {
        let store = MemoryStore::new();
        let key = namespace(7);
        let mut operations = BatchOperations::new();
        operations.insert(
            StoreKey::new(ColumnFamily::Meta, &control_key(key)),
            Some(b"bypass".to_vec()),
        );
        let batch = crate::MemoryBatch {
            operations,
            checkpoint: None,
        };
        assert!(store.commit(batch).is_err());
        let snapshot = store.snapshot().expect("snapshot");
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, &control_key(key))
                .expect("reserved read"),
            None
        );
    }

    #[test]
    fn memory_namespace_rejects_stale_fence_and_epoch_exhaustion() {
        let store = StoreHandle::memory();
        crate::initialize_schema(&store).expect("initialize schema");
        let stale_key = namespace(8);
        let lease = store
            .acquire_authenticated_namespace(stale_key)
            .expect("acquire stale fixture");
        let StoreHandle::Memory(memory) = &store else {
            unreachable!();
        };
        let mut state = memory.inner.write().expect("memory write lock");
        let mut changes = BatchOperations::new();
        changes.insert(
            StoreKey::new(ColumnFamily::Meta, &control_key(stale_key)),
            Some(NamespaceControl::uninitialized(2).encode(stale_key)),
        );
        apply_memory_changes(&mut state, changes).expect("inject newer durable fence");
        drop(state);
        assert!(matches!(
            lease.ensure_held(),
            Err(AuthenticatedNamespaceError::LeaseLost)
        ));
        assert!(matches!(
            store.acquire_authenticated_namespace(stale_key),
            Err(AuthenticatedNamespaceError::Busy)
        ));
        drop(lease);
        let successor = store
            .acquire_authenticated_namespace(stale_key)
            .expect("acquire after stale owner drops");
        assert_eq!(successor.fencing_token().get(), 3);
        drop(successor);

        let exhausted_key = namespace(9);
        let mut state = memory.inner.write().expect("memory write lock");
        let mut changes = BatchOperations::new();
        changes.insert(
            StoreKey::new(ColumnFamily::Meta, &control_key(exhausted_key)),
            Some(NamespaceControl::uninitialized(u64::MAX).encode(exhausted_key)),
        );
        apply_memory_changes(&mut state, changes).expect("inject exhausted durable fence");
        drop(state);
        assert!(matches!(
            store.acquire_authenticated_namespace(exhausted_key),
            Err(AuthenticatedNamespaceError::FencingEpochExhausted)
        ));
        assert!(
            !memory
                .authenticated_namespaces
                .lock()
                .expect("owner registry")
                .contains_key(&exhausted_key),
            "failed acquisition must not retain live ownership"
        );
    }

    #[test]
    fn namespace_codec_rejects_wrong_binding_checksum_and_state_digest() {
        let key = namespace(10);
        let control = NamespaceControl::initialized(1, 4, key, b"complete");
        let encoded = control.encode(key);
        assert!(matches!(
            NamespaceControl::decode(namespace(11), &encoded),
            Err(AuthenticatedNamespaceError::Corrupt(
                "control namespace binding mismatch"
            ))
        ));

        let mut corrupt = encoded.clone();
        corrupt[41] ^= 1;
        assert!(matches!(
            NamespaceControl::decode(key, &corrupt),
            Err(AuthenticatedNamespaceError::Corrupt(
                "control checksum mismatch"
            ))
        ));
        assert!(matches!(
            NamespaceImage::decode(key, Some(encoded), Some(b"different".to_vec())),
            Err(AuthenticatedNamespaceError::Corrupt(
                "complete-state digest mismatch"
            ))
        ));

        let zero_epoch = NamespaceControl::uninitialized(0).encode(key);
        assert!(matches!(
            NamespaceControl::decode(key, &zero_epoch),
            Err(AuthenticatedNamespaceError::Corrupt(
                "control fencing epoch is zero"
            ))
        ));
        let initialized = NamespaceControl::initialized(1, 0, key, b"complete").encode(key);
        assert!(matches!(
            NamespaceImage::decode(key, Some(initialized), None),
            Err(AuthenticatedNamespaceError::Corrupt(
                "initialized control is missing complete state"
            ))
        ));
        let uninitialized = NamespaceControl::uninitialized(1).encode(key);
        assert!(matches!(
            NamespaceImage::decode(key, Some(uninitialized), Some(b"unexpected".to_vec())),
            Err(AuthenticatedNamespaceError::Corrupt(
                "uninitialized control has unexpected state"
            ))
        ));
    }

    #[test]
    fn namespace_lease_drop_during_unwind_releases_ownership() {
        let store = StoreHandle::memory();
        crate::initialize_schema(&store).expect("initialize schema");
        let key = namespace(24);
        let owner = store.clone();
        assert!(std::thread::spawn(move || {
            let _lease = owner
                .acquire_authenticated_namespace(key)
                .expect("acquire panic fixture");
            panic!("drop namespace lease during unwind");
        })
        .join()
        .is_err());
        let lease = store
            .acquire_authenticated_namespace(key)
            .expect("reacquire after unwind");
        assert_eq!(lease.fencing_token().get(), 2);
    }

    #[test]
    fn archived_namespace_shares_ownership_and_never_mutates_segment_files() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hsrd-authenticated-namespace-archive-{}-{nonce}",
            std::process::id()
        ));
        assert!(!directory.exists(), "temporary fixture unexpectedly exists");
        let raw = StoreHandle::memory();
        crate::initialize_schema(&raw).expect("initialize archive fixture schema");
        let archived = raw
            .clone()
            .with_segment_archive(directory.clone())
            .expect("attach archive");
        let before = directory_image(&directory);
        let key = namespace(12);
        let lease = archived
            .acquire_authenticated_namespace(key)
            .expect("acquire through archive");
        assert!(matches!(
            raw.acquire_authenticated_namespace(key),
            Err(AuthenticatedNamespaceError::ArchiveHandleRequired)
        ));
        assert!(matches!(
            raw.acquire_authenticated_namespace(namespace(20)),
            Err(AuthenticatedNamespaceError::ArchiveHandleRequired)
        ));
        assert_eq!(
            lease
                .compare_exchange_complete_state(StateExpectation::Absent, 0, b"archive-neutral")
                .expect("publish archive-neutral state"),
            AuthenticatedNamespaceWrite::Committed
        );
        assert_eq!(
            directory_image(&directory),
            before,
            "namespace publication must not append or rewrite segment files"
        );

        let mut bypass = raw.batch();
        assert!(bypass
            .put(ColumnFamily::Meta, &control_key(key), b"raw bypass")
            .is_err());
        drop(lease);
        drop(archived);
        drop(raw);
        std::fs::remove_dir_all(directory).expect("remove archive fixture");
    }

    #[test]
    fn attaching_archive_fences_preexisting_raw_namespace_lease() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        let directory = std::env::temp_dir().join(format!(
            "hsrd-authenticated-namespace-archive-fence-{}-{nonce}",
            std::process::id()
        ));
        let duplicate = directory.with_extension("duplicate");
        assert!(!directory.exists(), "temporary fixture unexpectedly exists");
        assert!(!duplicate.exists(), "temporary fixture unexpectedly exists");
        let raw = StoreHandle::memory();
        crate::initialize_schema(&raw).expect("initialize archive fixture schema");
        let key = namespace(21);
        let raw_lease = raw
            .acquire_authenticated_namespace(key)
            .expect("acquire before archive attachment");
        let archived = raw
            .clone()
            .with_segment_archive(directory.clone())
            .expect("attach archive");
        assert!(matches!(
            raw_lease.ensure_held(),
            Err(AuthenticatedNamespaceError::ArchiveHandleRequired)
        ));
        assert!(matches!(
            archived.acquire_authenticated_namespace(key),
            Err(AuthenticatedNamespaceError::Busy)
        ));
        assert!(raw.clone().with_segment_archive(duplicate.clone()).is_err());
        assert!(
            !duplicate.exists(),
            "rejected duplicate must create no files"
        );
        drop(raw_lease);
        let archived_lease = archived
            .acquire_authenticated_namespace(key)
            .expect("reacquire through archive");
        assert_eq!(archived_lease.fencing_token().get(), 2);
        drop(archived_lease);
        drop(archived);
        assert!(matches!(
            raw.acquire_authenticated_namespace(namespace(22)),
            Err(AuthenticatedNamespaceError::ArchiveHandleRequired)
        ));
        let reattached = raw
            .clone()
            .with_segment_archive(directory.clone())
            .expect("reattach archive after wrapper drop");
        let reattached_lease = reattached
            .acquire_authenticated_namespace(key)
            .expect("acquire through reattached archive");
        assert_eq!(reattached_lease.fencing_token().get(), 3);
        drop(reattached_lease);
        drop(reattached);
        drop(raw);
        std::fs::remove_dir_all(directory).expect("remove archive fence fixture");
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn rocks_namespace_persists_state_and_fencing_epoch_across_true_reopen() {
        let path = temporary_directory("reopen");
        let key = namespace(13);
        let rocks = RocksStore::open(&path).expect("open RocksDB");
        let store = StoreHandle::Rocks(rocks.clone());
        crate::initialize_schema(&store).expect("initialize schema");
        let lease = store
            .acquire_authenticated_namespace(key)
            .expect("acquire namespace");
        assert_eq!(lease.fencing_token().get(), 1);
        assert_eq!(
            lease
                .compare_exchange_complete_state(StateExpectation::Absent, 0, b"durable-zero")
                .expect("create durable state"),
            AuthenticatedNamespaceWrite::Committed
        );
        drop(lease);
        drop(store);
        drop(rocks);

        let rocks = RocksStore::open(&path).expect("truly reopen RocksDB");
        let store = StoreHandle::Rocks(rocks.clone());
        let lease = store
            .acquire_authenticated_namespace(key)
            .expect("reacquire namespace");
        assert_eq!(lease.fencing_token().get(), 2);
        assert_eq!(
            lease.load_complete_state().expect("load reopened state"),
            AuthenticatedNamespaceState::Initialized {
                encoded: b"durable-zero".to_vec(),
                minimum_revision: 0,
            }
        );
        drop(lease);
        drop(store);
        drop(rocks);
        std::fs::remove_dir_all(path).expect("remove RocksDB reopen fixture");
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn rocks_archive_manifests_persistently_require_archived_namespace_handle() {
        let root = temporary_directory("archive-reopen");
        let chain = root.join("chain");
        let segments = root.join("segments");
        let key = namespace(23);
        let rocks = RocksStore::open(&chain).expect("open RocksDB");
        let store = StoreHandle::Rocks(rocks.clone());
        crate::initialize_schema(&store).expect("initialize schema");
        let archived = store
            .with_segment_archive(segments.clone())
            .expect("attach archive");
        let lease = archived
            .acquire_authenticated_namespace(key)
            .expect("acquire archived namespace");
        assert_eq!(lease.fencing_token().get(), 1);
        drop(lease);
        drop(archived);
        drop(rocks);

        let rocks = RocksStore::open(&chain).expect("truly reopen RocksDB");
        let raw = StoreHandle::Rocks(rocks.clone());
        assert!(matches!(
            raw.acquire_authenticated_namespace(key),
            Err(AuthenticatedNamespaceError::ArchiveHandleRequired)
        ));
        let archived = raw
            .with_segment_archive(segments)
            .expect("recover archive wrapper");
        let lease = archived
            .acquire_authenticated_namespace(key)
            .expect("acquire after archive recovery");
        assert_eq!(lease.fencing_token().get(), 2);
        drop(lease);
        drop(archived);
        drop(rocks);
        std::fs::remove_dir_all(root).expect("remove archive-reopen fixture");
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn archived_rocks_namespace_ambiguous_write_fences_and_recovers() {
        let root = temporary_directory("archived-ambiguous");
        let chain = root.join("chain");
        let segments = root.join("segments");
        let key = namespace(26);
        let rocks = RocksStore::open(&chain).expect("open RocksDB");
        let raw = StoreHandle::Rocks(rocks.clone());
        crate::initialize_schema(&raw).expect("initialize schema");
        let archived = raw
            .with_segment_archive(segments.clone())
            .expect("attach archive");
        let lease = archived
            .acquire_authenticated_namespace(key)
            .expect("acquire archived namespace");
        rocks.inject_next_commit_fault(crate::RocksCommitFault::AfterWrite);
        assert!(lease
            .compare_exchange_complete_state(StateExpectation::Absent, 0, b"archived-new")
            .is_err());
        assert!(archived.reopen_required());
        assert!(rocks.reopen_required());
        assert!(lease.load_complete_state().is_err());
        drop(lease);
        drop(archived);
        drop(rocks);

        let rocks = RocksStore::open(&chain).expect("truly reopen RocksDB");
        let archived = StoreHandle::Rocks(rocks.clone())
            .with_segment_archive(segments)
            .expect("recover archive");
        let lease = archived
            .acquire_authenticated_namespace(key)
            .expect("acquire recovered namespace");
        assert_eq!(lease.fencing_token().get(), 2);
        assert_eq!(
            lease.load_complete_state().expect("resolve durable state"),
            AuthenticatedNamespaceState::Initialized {
                encoded: b"archived-new".to_vec(),
                minimum_revision: 0,
            }
        );
        drop(lease);
        drop(archived);
        drop(rocks);
        std::fs::remove_dir_all(root).expect("remove archived ambiguity fixture");
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn rocks_namespace_rejects_wal_and_authoritatively_rechecks_reserved_keys() {
        let wal_path = temporary_directory("wal");
        let key = namespace(14);
        let rocks = RocksStore::open_with_durability(&wal_path, DurabilityPolicy::Wal)
            .expect("open WAL RocksDB");
        let store = StoreHandle::Rocks(rocks.clone());
        assert!(matches!(
            store.acquire_authenticated_namespace(key),
            Err(AuthenticatedNamespaceError::NonDurableStore)
        ));
        assert_eq!(
            rocks
                .snapshot()
                .expect("WAL snapshot")
                .get(ColumnFamily::Meta, &control_key(key))
                .expect("WAL control read"),
            None
        );
        drop(store);
        drop(rocks);
        std::fs::remove_dir_all(wal_path).expect("remove WAL fixture");

        let path = temporary_directory("reserved");
        let rocks = RocksStore::open(&path).expect("open RocksDB");
        let mut operations = BatchOperations::new();
        operations.insert(
            StoreKey::new(ColumnFamily::Snapshots, &state_key(key)),
            Some(b"bypass".to_vec()),
        );
        let batch = crate::RocksBatch {
            operations,
            checkpoint: None,
        };
        assert!(rocks.commit(batch).is_err());
        assert_eq!(
            rocks
                .snapshot()
                .expect("reserved snapshot")
                .get(ColumnFamily::Snapshots, &state_key(key))
                .expect("reserved state read"),
            None
        );
        drop(rocks);
        std::fs::remove_dir_all(path).expect("remove reserved-key fixture");
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn rocks_namespace_known_rejection_keeps_lease_retryable() {
        let path = temporary_directory("before-write");
        let key = namespace(15);
        let rocks = RocksStore::open(&path).expect("open RocksDB");
        let store = StoreHandle::Rocks(rocks.clone());

        crate::initialize_schema(&store).expect("initialize fault fixture schema");

        rocks.inject_next_commit_fault(crate::RocksCommitFault::BeforeWrite);
        assert!(store.acquire_authenticated_namespace(key).is_err());
        assert!(!store.reopen_required());
        let lease = store
            .acquire_authenticated_namespace(key)
            .expect("retry known-rejected acquisition");
        assert_eq!(lease.fencing_token().get(), 1);

        rocks.inject_next_commit_fault(crate::RocksCommitFault::BeforeWrite);
        assert!(lease
            .compare_exchange_complete_state(StateExpectation::Absent, 0, b"retryable")
            .is_err());
        assert!(!store.reopen_required());
        assert_eq!(
            lease.load_complete_state().expect("load rejected state"),
            AuthenticatedNamespaceState::NeverInitialized
        );
        assert_eq!(
            lease
                .compare_exchange_complete_state(StateExpectation::Absent, 0, b"retryable")
                .expect("retry known-rejected publication"),
            AuthenticatedNamespaceWrite::Committed
        );
        drop(lease);
        drop(store);
        drop(rocks);
        std::fs::remove_dir_all(path).expect("remove known-rejection fixture");
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn rocks_namespace_ambiguous_publication_fences_every_clone_until_reopen() {
        let path = temporary_directory("ambiguous-publication");
        let key = namespace(16);
        let rocks = RocksStore::open(&path).expect("open RocksDB");
        let store = StoreHandle::Rocks(rocks.clone());
        let clone = store.clone();
        crate::initialize_schema(&store).expect("initialize fault fixture schema");
        let lease = store
            .acquire_authenticated_namespace(key)
            .expect("acquire namespace");
        rocks.inject_next_commit_fault(crate::RocksCommitFault::AfterWrite);
        assert!(lease
            .compare_exchange_complete_state(StateExpectation::Absent, 0, b"committed-new")
            .is_err());
        assert!(store.reopen_required());
        assert!(clone.reopen_required());
        assert!(lease.load_complete_state().is_err());
        assert!(clone
            .acquire_authenticated_namespace(namespace(17))
            .is_err());
        drop(lease);
        drop(clone);
        drop(store);
        drop(rocks);

        let rocks = RocksStore::open(&path).expect("truly reopen RocksDB");
        let store = StoreHandle::Rocks(rocks.clone());
        let lease = store
            .acquire_authenticated_namespace(key)
            .expect("acquire after ambiguous publication");
        assert_eq!(lease.fencing_token().get(), 2);
        assert_eq!(
            lease
                .load_complete_state()
                .expect("resolve durable outcome"),
            AuthenticatedNamespaceState::Initialized {
                encoded: b"committed-new".to_vec(),
                minimum_revision: 0,
            }
        );
        assert_eq!(
            lease
                .compare_exchange_complete_state(StateExpectation::Absent, 0, b"committed-new",)
                .expect("idempotently resolve committed proposal"),
            AuthenticatedNamespaceWrite::AlreadyCommitted
        );
        drop(lease);
        drop(store);
        drop(rocks);
        std::fs::remove_dir_all(path).expect("remove ambiguous-publication fixture");
    }

    #[cfg(feature = "rocksdb-backend")]
    #[test]
    fn rocks_namespace_ambiguous_acquisition_exposes_no_lease_and_burns_epoch() {
        let path = temporary_directory("ambiguous-acquisition");
        let key = namespace(18);
        let rocks = RocksStore::open(&path).expect("open RocksDB");
        let store = StoreHandle::Rocks(rocks.clone());
        crate::initialize_schema(&store).expect("initialize fault fixture schema");
        rocks.inject_next_commit_fault(crate::RocksCommitFault::AfterWrite);
        assert!(store.acquire_authenticated_namespace(key).is_err());
        assert!(store.reopen_required());
        assert!(
            !rocks
                .authenticated_namespaces
                .lock()
                .expect("owner registry")
                .contains_key(&key),
            "ambiguous acquisition must not expose or retain a live lease"
        );
        drop(store);
        drop(rocks);

        let rocks = RocksStore::open(&path).expect("truly reopen RocksDB");
        let store = StoreHandle::Rocks(rocks.clone());
        let lease = store
            .acquire_authenticated_namespace(key)
            .expect("acquire after ambiguous reservation");
        assert_eq!(lease.fencing_token().get(), 2);
        assert_eq!(
            lease
                .load_complete_state()
                .expect("load uninitialized state"),
            AuthenticatedNamespaceState::NeverInitialized
        );
        drop(lease);
        drop(store);
        drop(rocks);
        std::fs::remove_dir_all(path).expect("remove ambiguous-acquisition fixture");
    }
}
