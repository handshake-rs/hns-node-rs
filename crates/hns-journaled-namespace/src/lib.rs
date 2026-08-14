#![forbid(unsafe_code)]
#![doc = "Crash-safe composition of one external rollback journal and one local namespace."]

use std::cell::Cell;

use hns_rollback_journal::{
    plan_recovery, BindingFingerprint, DatabaseObservation, FailClosedReason, FencingToken,
    JournalBinding, JournalError, JournalLeaseContext, JournalMutation, JournalRecord,
    JournalState, MutationReconciliation, RecoveryPlan, SnapshotImage, StateIdentity,
    MAX_PLAINTEXT_SNAPSHOT_SIZE,
};
use hns_store::{
    AuthenticatedNamespaceError, AuthenticatedNamespaceLease, AuthenticatedNamespaceState,
    AuthenticatedNamespaceWrite, OperationNamespaceId, StateExpectation, StoreHandle,
};
use thiserror::Error;

const MAX_RECOVERY_ACTIONS: usize = 16;

thread_local! {
    static RUN_ACTIVE: Cell<bool> = const { Cell::new(false) };
}

/// A backend-neutral failure at the trusted external journal boundary.
///
/// Implementations should log sensitive backend detail inside the broker and
/// return one fail-closed class here. `run_scoped` does not directly expose a
/// broker guard, fencing token, journal record, key, nonce, or raw snapshot.
/// Broker and protocol implementations are trusted boundary code and must not
/// leak them through their own APIs or through an over-broad projection.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ExternalJournalError {
    #[error("the external journal namespace lease is unavailable")]
    LeaseUnavailable,
    #[error("the external journal namespace lease was lost")]
    LeaseLost,
    #[error("the external journal record could not be authenticated and loaded")]
    AuthenticatedLoadFailed,
    #[error("the external journal snapshot could not be sealed")]
    SealFailed,
    #[error("the external journal snapshot could not be authenticated and opened")]
    OpenFailed,
    #[error("the external journal backend failed closed: {0}")]
    Backend(&'static str),
}

/// Result reported by one external fenced compare-and-swap attempt.
///
/// Only `Durable` asserts that the exact proposal and its parent directory
/// metadata are durably acknowledged. `OutcomeUnknown` and backend errors are
/// reloaded and reconciled, with at most one byte-identical retry. `Conflict`
/// is definite: it is reloaded only to recognize an already-installed exact
/// proposal and is never retried.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalWrite {
    Durable,
    OutcomeUnknown,
    Conflict,
}

/// Sole-owner broker for one authenticated external journal namespace.
///
/// The associated guard is a capability and must not implement `Clone`. The
/// coordinator acquires it before the local namespace lease and retains it
/// until after the local lease has been dropped.
pub trait ExternalJournalBroker {
    type Guard<'a>: ExternalJournalGuard + 'a
    where
        Self: 'a;

    /// Attest that this concrete broker, its key custody, persistence, lease
    /// implementation, and rollback domain have passed the embedding's
    /// production qualification for this exact binding. This is a live broker
    /// guarantee; the binding's protection enum is not evidence by itself.
    fn ensure_production_qualified(
        &self,
        binding: &JournalBinding,
    ) -> Result<(), ExternalJournalError>;

    fn acquire<'a>(
        &'a self,
        binding: &JournalBinding,
    ) -> Result<Self::Guard<'a>, ExternalJournalError>;
}

/// Trusted operations available only while an external lease is live.
///
/// For this synchronous coordinator the lease must not expire or be
/// superseded while the non-cloneable guard exists. If a backend uses expiring
/// leases, it must renew them internally and make every method fail before
/// expiry; it must not expose a guard that can silently become stale during a
/// dependent operation.
pub trait ExternalJournalGuard {
    fn binding_fingerprint(&self) -> BindingFingerprint;

    fn fencing_token(&self) -> FencingToken;

    fn ensure_held(&self) -> Result<(), ExternalJournalError>;

    /// Load a record only after authenticating its storage representation.
    fn load_authenticated(&self) -> Result<Option<JournalRecord>, ExternalJournalError>;

    /// Atomically enforce the mutation's binding, fencing token, and exact
    /// prior-record expectation, then durably install the exact proposal.
    ///
    /// An `Err` is conservatively treated as outcome-ambiguous because an
    /// attempt may have reached durable storage. A guaranteed pre-attempt
    /// rejection should be reported by `ensure_held` before this method.
    fn compare_exchange_durable(
        &mut self,
        mutation: &JournalMutation,
    ) -> Result<ExternalWrite, ExternalJournalError>;

    /// Seal one exact new snapshot with fresh qualified nonce allocation and
    /// the binding's associated data. An exact retry must reuse the returned
    /// image and must never call this method again.
    fn seal_snapshot(
        &mut self,
        binding: &JournalBinding,
        revision: u64,
        protocol_fingerprint: [u8; 32],
        plaintext: &[u8],
    ) -> Result<SnapshotImage, ExternalJournalError>;

    /// Authenticate, decrypt, and return one complete sealed snapshot.
    fn open_snapshot(
        &self,
        binding: &JournalBinding,
        image: &SnapshotImage,
    ) -> Result<Vec<u8>, ExternalJournalError>;
}

/// Semantic rejection of a complete protocol snapshot.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[error("invalid complete protocol snapshot: {0}")]
pub struct ProtocolValidationError(pub &'static str);

/// A complete validation result with deliberately separate security and use
/// views.
///
/// `TransitionState` retains every security-relevant aggregate field needed to
/// reject rollback, removal, or unauthorized reset anywhere in the complete
/// namespace. It remains coordinator-internal. `Projection` is the narrower
/// role-specific view exposed to scoped callbacks.
pub struct ValidatedSnapshot<TransitionState, Projection> {
    transition_state: TransitionState,
    projection: Projection,
}

impl<TransitionState, Projection> ValidatedSnapshot<TransitionState, Projection> {
    pub const fn new(transition_state: TransitionState, projection: Projection) -> Self {
        Self {
            transition_state,
            projection,
        }
    }

    const fn transition_state(&self) -> &TransitionState {
        &self.transition_state
    }

    fn into_parts(self) -> (TransitionState, Projection) {
        (self.transition_state, self.projection)
    }
}

/// Role-specific validation for complete canonical namespace images.
///
/// Implementations are trusted coordinator internals: they receive decrypted
/// bytes solely to validate semantics and must expose only a least-privilege
/// typed projection to the scoped role callbacks.
pub trait SnapshotProtocol {
    /// Complete security state used only for whole-snapshot transition checks.
    /// It must retain every relevant high-water, tombstone, retained-key, and
    /// aggregate invariant even when the current operation selects one item.
    type TransitionState: Eq;

    /// Least-privilege operation view exposed to scoped role callbacks.
    type Projection;

    /// Fixed identity of this exact protocol snapshot format. It must not vary
    /// with state contents, an HRM sequence, service generation, route counter,
    /// or local persistence revision. The coordinator captures it once per
    /// run. This method must be deterministic and side-effect-free.
    fn protocol_fingerprint(&self, binding: &JournalBinding) -> [u8; 32];

    /// Validate one complete snapshot and derive both complete transition state
    /// and the least-privilege typed view needed by scoped role callbacks.
    ///
    /// The result must be fully derived from the supplied arguments plus
    /// immutable adapter configuration and evidence. This method must be
    /// deterministic and side-effect-free; implementations must not depend on
    /// mutable call history or place raw snapshot, key, nonce, journal, lease,
    /// or fencing material in the projection.
    fn validate_snapshot(
        &self,
        binding: &JournalBinding,
        revision: u64,
        encoded: &[u8],
    ) -> Result<ValidatedSnapshot<Self::TransitionState, Self::Projection>, ProtocolValidationError>;

    /// Validate old-to-new monotonic and retention invariants after both
    /// complete snapshots have independently passed semantic validation.
    /// This method must be deterministic, side-effect-free, and fully derived
    /// from its arguments plus immutable adapter configuration and evidence;
    /// it must not depend on mutable call history. Any evidence needed to
    /// accept a transition must be reconstructible after restart because
    /// recovery revalidates both sides of a durable `Prepared` record.
    fn validate_transition(
        &self,
        binding: &JournalBinding,
        current_revision: u64,
        current: &Self::TransitionState,
        proposed_revision: u64,
        proposed: &Self::TransitionState,
    ) -> Result<(), ProtocolValidationError>;
}

/// A settled state identity visible only during one scoped operation.
///
/// Its coordinator-owned fields contain no raw snapshot, lease, token,
/// journal, CAS, key, or nonce material; the trusted protocol adapter supplies
/// only a least-privilege typed projection. Raw decrypted state otherwise
/// remains coordinator-internal. Its lifetime cannot escape `run_scoped`.
/// Call `ensure_current` during a long dependent operation to fail closed
/// promptly if either lease is lost.
pub struct SettledNamespace<'scope, T> {
    binding: &'scope JournalBinding,
    revision: u64,
    projection: &'scope T,
    leases: &'scope dyn ScopedLeaseCheck,
}

impl<'scope, T> SettledNamespace<'scope, T> {
    pub const fn binding(&self) -> &JournalBinding {
        self.binding
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn projection(&self) -> &T {
        self.projection
    }

    pub fn ensure_current(&self) -> Result<(), JournaledNamespaceError> {
        self.leases.ensure_current()
    }

    pub fn keep<C>(self, context: C) -> SettledAction<C> {
        SettledAction {
            kind: ActionKind::Keep,
            context,
        }
    }

    pub fn replace<C>(
        self,
        proposed_revision: u64,
        proposed_encoded: Vec<u8>,
        context: C,
    ) -> SettledAction<C> {
        SettledAction {
            kind: ActionKind::Replace {
                proposed_revision,
                proposed_encoded,
            },
            context,
        }
    }
}

/// An owned state plan plus application-owned context.
///
/// The context is not passed to `use_settled` until the selected state is
/// durably Stable and has been exactly reread from both stores.
pub struct SettledAction<C> {
    kind: ActionKind,
    context: C,
}

/// Output of a dependent operation, tagged as historical evidence for the
/// exact settled revision under which that operation completed.
///
/// This is not a transferable current-authorization capability. A later use
/// that requires current authority must enter a new guarded operation or use a
/// broker-owned session established completely inside `use_settled`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoricalEvidence<R> {
    binding_fingerprint: BindingFingerprint,
    revision: u64,
    protocol_fingerprint: [u8; 32],
    byte_fingerprint: [u8; 32],
    value: R,
}

impl<R> HistoricalEvidence<R> {
    pub const fn binding_fingerprint(&self) -> BindingFingerprint {
        self.binding_fingerprint
    }

    pub const fn revision(&self) -> u64 {
        self.revision
    }

    pub const fn protocol_fingerprint(&self) -> [u8; 32] {
        self.protocol_fingerprint
    }

    pub const fn byte_fingerprint(&self) -> [u8; 32] {
        self.byte_fingerprint
    }

    pub const fn value(&self) -> &R {
        &self.value
    }
}

enum ActionKind {
    Keep,
    Replace {
        proposed_revision: u64,
        proposed_encoded: Vec<u8>,
    },
}

/// Fail-closed coordinator error. No variant authorizes implicit enrollment,
/// reset, retirement reversal, or result promotion.
#[derive(Debug, Error)]
pub enum JournaledNamespaceError {
    #[error("journaled namespace runs must not be nested on one thread")]
    NestedRun,
    #[error(transparent)]
    External(#[from] ExternalJournalError),
    #[error(transparent)]
    Local(AuthenticatedNamespaceError),
    #[error("the local database publication outcome is uncertain; reopen required")]
    LocalReopenRequired,
    #[error(transparent)]
    Journal(#[from] JournalError),
    #[error(transparent)]
    Protocol(#[from] ProtocolValidationError),
    #[error("rollback recovery failed closed: {0:?}")]
    FailClosed(FailClosedReason),
    #[error("complete protocol snapshots must not be empty")]
    EmptySnapshot,
    #[error("complete protocol snapshot has {actual} bytes; maximum is {maximum}")]
    SnapshotTooLarge { actual: usize, maximum: usize },
    #[error("replacement revision must advance beyond {current}; proposed {proposed}")]
    RevisionNotAdvanced { current: u64, proposed: u64 },
    #[error("opened snapshot bytes do not match their authenticated identity")]
    SnapshotFingerprintMismatch,
    #[error("snapshot protocol fingerprint does not match its authenticated identity")]
    ProtocolFingerprintMismatch,
    #[error("protocol validation produced inconsistent transition state for identical bytes")]
    ProtocolValidationInconsistent,
    #[error("the external lease guard is bound to a different journal namespace")]
    ExternalBindingMismatch,
    #[error("the external journal binding does not claim an independent rollback domain")]
    UnqualifiedRollbackDomain,
    #[error("the local authenticated namespace backend is not restart-durable")]
    VolatileLocalBackend,
    #[error("the external lease guard changed its fencing token")]
    ExternalFencingMismatch,
    #[error("the external journal mutation conflicts with a different durable record")]
    ExternalConflict,
    #[error("the external journal mutation outcome remains unresolved after one exact retry")]
    ExternalOutcomeUnresolved,
    #[error("the authenticated external reread does not equal the acknowledged proposal")]
    ExternalRereadMismatch,
    #[error("the local exact compare-and-swap conflicted")]
    LocalConflict,
    #[error("the local mandatory reread does not equal the exact proposal")]
    LocalRereadMismatch,
    #[error("rollback recovery exceeded its bounded action limit")]
    RecoveryLimitExceeded,
}

/// Inert coordinator for one local store. It installs no role, CLI, broker,
/// provisioning path, enrollment path, retirement path, or default backend.
#[derive(Clone, Debug)]
pub struct JournaledNamespace {
    store: StoreHandle,
}

impl JournaledNamespace {
    pub const fn new(store: StoreHandle) -> Self {
        Self { store }
    }

    /// Recover one pair to Stable, plan an optional exact transition, then run
    /// dependent use only after the chosen state is durably Stable.
    ///
    /// A single call coordinates exactly one external/local pair and is
    /// deliberately non-nestable. Multi-namespace roles must use a future
    /// coordinator that sorts namespace identities, acquires every external
    /// lease first and then every local lease, and loads no state until all
    /// leases are held. Never nest pairwise calls to approximate that order.
    ///
    /// `plan` may only derive an owned proposal and application context. It
    /// must not perform irreversible or externally visible effects because a
    /// proposed transition can still fail. `use_settled` is the sole phase in
    /// which dependent effects may be promoted.
    pub fn run_scoped<B, P, C, R, Plan, Use>(
        &self,
        broker: &B,
        binding: &JournalBinding,
        protocol: &P,
        plan: Plan,
        use_settled: Use,
    ) -> Result<HistoricalEvidence<R>, JournaledNamespaceError>
    where
        B: ExternalJournalBroker,
        P: SnapshotProtocol,
        Plan: for<'scope> FnOnce(SettledNamespace<'scope, P::Projection>) -> SettledAction<C>,
        Use: for<'scope> FnOnce(SettledNamespace<'scope, P::Projection>, C) -> R,
    {
        let _run = RunSentinel::enter()?;
        ensure_production_boundary(self.store.is_restart_durable(), broker, binding)?;
        let driver = StoreLocalDriver { store: &self.store };
        run_with_driver(&driver, broker, binding, protocol, plan, use_settled)
    }
}

fn ensure_production_boundary<B: ExternalJournalBroker>(
    local_is_restart_durable: bool,
    broker: &B,
    binding: &JournalBinding,
) -> Result<(), JournaledNamespaceError> {
    if !local_is_restart_durable {
        return Err(JournaledNamespaceError::VolatileLocalBackend);
    }
    if !binding.protection().has_independent_rollback_domain() {
        return Err(JournaledNamespaceError::UnqualifiedRollbackDomain);
    }
    broker.ensure_production_qualified(binding)?;
    Ok(())
}

struct RunSentinel;

impl RunSentinel {
    fn enter() -> Result<Self, JournaledNamespaceError> {
        RUN_ACTIVE.with(|active| {
            if active.replace(true) {
                Err(JournaledNamespaceError::NestedRun)
            } else {
                Ok(Self)
            }
        })
    }
}

impl Drop for RunSentinel {
    fn drop(&mut self) {
        RUN_ACTIVE.with(|active| active.set(false));
    }
}

trait ScopedLeaseCheck {
    fn ensure_current(&self) -> Result<(), JournaledNamespaceError>;
}

trait LocalNamespaceDriver {
    type Guard: LocalNamespaceGuard;

    fn acquire(
        &self,
        namespace: OperationNamespaceId,
    ) -> Result<Self::Guard, AuthenticatedNamespaceError>;

    fn reopen_required(&self) -> bool;
}

trait LocalNamespaceGuard {
    fn ensure_held(&self) -> Result<(), AuthenticatedNamespaceError>;

    fn load(&self) -> Result<AuthenticatedNamespaceState, AuthenticatedNamespaceError>;

    fn compare_exchange(
        &self,
        expectation: StateExpectation<'_>,
        proposed_revision: u64,
        proposed: &[u8],
    ) -> Result<AuthenticatedNamespaceWrite, AuthenticatedNamespaceError>;
}

struct StoreLocalDriver<'store> {
    store: &'store StoreHandle,
}

impl LocalNamespaceDriver for StoreLocalDriver<'_> {
    type Guard = StoreLocalGuard;

    fn acquire(
        &self,
        namespace: OperationNamespaceId,
    ) -> Result<Self::Guard, AuthenticatedNamespaceError> {
        self.store
            .acquire_authenticated_namespace(namespace)
            .map(StoreLocalGuard)
    }

    fn reopen_required(&self) -> bool {
        self.store.reopen_required()
    }
}

struct StoreLocalGuard(AuthenticatedNamespaceLease);

impl LocalNamespaceGuard for StoreLocalGuard {
    fn ensure_held(&self) -> Result<(), AuthenticatedNamespaceError> {
        self.0.ensure_held()
    }

    fn load(&self) -> Result<AuthenticatedNamespaceState, AuthenticatedNamespaceError> {
        self.0.load_complete_state()
    }

    fn compare_exchange(
        &self,
        expectation: StateExpectation<'_>,
        proposed_revision: u64,
        proposed: &[u8],
    ) -> Result<AuthenticatedNamespaceWrite, AuthenticatedNamespaceError> {
        self.0
            .compare_exchange_complete_state(expectation, proposed_revision, proposed)
    }
}

struct HeldLeases<'lease, D, G>
where
    D: LocalNamespaceDriver,
    G: ExternalJournalGuard,
{
    driver: &'lease D,
    local: &'lease D::Guard,
    external: &'lease G,
    binding_fingerprint: BindingFingerprint,
    fencing_token: FencingToken,
}

impl<D, G> ScopedLeaseCheck for HeldLeases<'_, D, G>
where
    D: LocalNamespaceDriver,
    G: ExternalJournalGuard,
{
    fn ensure_current(&self) -> Result<(), JournaledNamespaceError> {
        local_result(self.driver, self.local.ensure_held())?;
        if self.external.binding_fingerprint() != self.binding_fingerprint {
            return Err(JournaledNamespaceError::ExternalBindingMismatch);
        }
        if self.external.fencing_token() != self.fencing_token {
            return Err(JournaledNamespaceError::ExternalFencingMismatch);
        }
        self.external.ensure_held()?;
        Ok(())
    }
}

#[derive(Clone)]
struct SettledOwned<T, V> {
    record: JournalRecord,
    revision: u64,
    encoded: Vec<u8>,
    identity: StateIdentity,
    transition_state: T,
    projection: V,
}

fn run_with_driver<D, B, P, C, R, Plan, Use>(
    driver: &D,
    broker: &B,
    binding: &JournalBinding,
    protocol: &P,
    plan: Plan,
    use_settled: Use,
) -> Result<HistoricalEvidence<R>, JournaledNamespaceError>
where
    D: LocalNamespaceDriver,
    B: ExternalJournalBroker,
    P: SnapshotProtocol,
    Plan: for<'scope> FnOnce(SettledNamespace<'scope, P::Projection>) -> SettledAction<C>,
    Use: for<'scope> FnOnce(SettledNamespace<'scope, P::Projection>, C) -> R,
{
    let mut external = broker.acquire(binding)?;
    let expected_binding = binding.fingerprint();
    if external.binding_fingerprint() != expected_binding {
        return Err(JournaledNamespaceError::ExternalBindingMismatch);
    }
    let fencing_token = external.fencing_token();
    external.ensure_held()?;

    let namespace = OperationNamespaceId::new(*binding.storage_namespace_id())
        .map_err(JournaledNamespaceError::Local)?;
    let local = local_result(driver, driver.acquire(namespace))?;

    ensure_leases(driver, &local, &external, expected_binding, fencing_token)?;
    let protocol_fingerprint = protocol.protocol_fingerprint(binding);

    let current = recover_to_stable(
        driver,
        &local,
        &mut external,
        binding,
        protocol,
        protocol_fingerprint,
        expected_binding,
        fencing_token,
    )?;
    confirm_settled(
        driver,
        &local,
        &external,
        &current,
        expected_binding,
        fencing_token,
    )?;

    let action = {
        let leases = HeldLeases {
            driver,
            local: &local,
            external: &external,
            binding_fingerprint: expected_binding,
            fencing_token,
        };
        plan(SettledNamespace {
            binding,
            revision: current.revision,
            projection: &current.projection,
            leases: &leases,
        })
    };

    let (selected, context) = match action.kind {
        ActionKind::Keep => (current, action.context),
        ActionKind::Replace {
            proposed_revision,
            proposed_encoded,
        } => {
            let replaced = replace_stable(
                driver,
                &local,
                &mut external,
                binding,
                protocol,
                current,
                proposed_revision,
                proposed_encoded,
                protocol_fingerprint,
                expected_binding,
                fencing_token,
            )?;
            (replaced, action.context)
        }
    };

    let leases = HeldLeases {
        driver,
        local: &local,
        external: &external,
        binding_fingerprint: expected_binding,
        fencing_token,
    };
    confirm_settled(
        driver,
        &local,
        &external,
        &selected,
        expected_binding,
        fencing_token,
    )?;
    leases.ensure_current()?;

    let result = use_settled(
        SettledNamespace {
            binding,
            revision: selected.revision,
            projection: &selected.projection,
            leases: &leases,
        },
        context,
    );

    leases.ensure_current()?;
    confirm_settled(
        driver,
        &local,
        &external,
        &selected,
        expected_binding,
        fencing_token,
    )?;
    Ok(HistoricalEvidence {
        binding_fingerprint: expected_binding,
        revision: selected.revision,
        protocol_fingerprint: selected.identity.protocol_fingerprint(),
        byte_fingerprint: selected.identity.byte_fingerprint(),
        value: result,
    })
}

#[allow(clippy::too_many_arguments)]
fn recover_to_stable<D, G, P>(
    driver: &D,
    local: &D::Guard,
    external: &mut G,
    binding: &JournalBinding,
    protocol: &P,
    protocol_fingerprint: [u8; 32],
    expected_binding: BindingFingerprint,
    fencing_token: FencingToken,
) -> Result<SettledOwned<P::TransitionState, P::Projection>, JournaledNamespaceError>
where
    D: LocalNamespaceDriver,
    G: ExternalJournalGuard,
    P: SnapshotProtocol,
{
    for _ in 0..MAX_RECOVERY_ACTIONS {
        ensure_leases(driver, local, external, expected_binding, fencing_token)?;
        let record = external.load_authenticated()?;
        let local_state = local_result(driver, local.load())?;
        let observation = observe_local(protocol, binding, protocol_fingerprint, &local_state)?;

        match plan_recovery(binding, record.as_ref(), observation) {
            RecoveryPlan::Ready { current } => {
                let (opened, validated) =
                    open_and_validate(external, binding, protocol, protocol_fingerprint, current)?;
                let AuthenticatedNamespaceState::Initialized {
                    encoded,
                    minimum_revision,
                } = local_state
                else {
                    return Err(JournaledNamespaceError::LocalRereadMismatch);
                };
                if minimum_revision != current.identity().revision() || encoded != opened {
                    return Err(JournaledNamespaceError::LocalRereadMismatch);
                }
                let Some(record) = record.clone() else {
                    return Err(JournaledNamespaceError::FailClosed(
                        FailClosedReason::MissingJournalRecord,
                    ));
                };
                let (transition_state, projection) = validated.into_parts();
                return Ok(SettledOwned {
                    record,
                    revision: minimum_revision,
                    encoded,
                    identity: current.identity(),
                    transition_state,
                    projection,
                });
            }
            RecoveryPlan::RestoreStableThenReread { current, .. } => {
                let image = current.clone();
                let (opened, _) =
                    open_and_validate(external, binding, protocol, protocol_fingerprint, &image)?;
                ensure_leases(driver, local, external, expected_binding, fencing_token)?;
                apply_local_exact(
                    driver,
                    local,
                    &local_state,
                    image.identity().revision(),
                    &opened,
                )?;
            }
            RecoveryPlan::RetryPreparedDatabaseCas { proposed, .. } => {
                let Some(prepared) = record.as_ref() else {
                    return Err(JournaledNamespaceError::FailClosed(
                        FailClosedReason::MissingJournalRecord,
                    ));
                };
                let opened =
                    open_prepared(external, binding, protocol, protocol_fingerprint, prepared)?;
                if opened.new_identity != proposed.identity() {
                    return Err(JournaledNamespaceError::ExternalRereadMismatch);
                }
                ensure_leases(driver, local, external, expected_binding, fencing_token)?;
                apply_local_exact(
                    driver,
                    local,
                    &local_state,
                    opened.new_identity.revision(),
                    &opened.new_encoded,
                )?;
            }
            RecoveryPlan::RestorePreparedOldThenReread { old, .. } => {
                let Some(prepared) = record.as_ref() else {
                    return Err(JournaledNamespaceError::FailClosed(
                        FailClosedReason::MissingJournalRecord,
                    ));
                };
                let opened =
                    open_prepared(external, binding, protocol, protocol_fingerprint, prepared)?;
                if opened.old_identity != old.identity() {
                    return Err(JournaledNamespaceError::ExternalRereadMismatch);
                }
                ensure_leases(driver, local, external, expected_binding, fencing_token)?;
                apply_local_exact(
                    driver,
                    local,
                    &local_state,
                    opened.old_identity.revision(),
                    &opened.old_encoded,
                )?;
            }
            RecoveryPlan::FinalizePrepared { .. } => {
                let Some(record) = record else {
                    return Err(JournaledNamespaceError::FailClosed(
                        FailClosedReason::MissingJournalRecord,
                    ));
                };
                let opened =
                    open_prepared(external, binding, protocol, protocol_fingerprint, &record)?;
                let AuthenticatedNamespaceState::Initialized {
                    encoded,
                    minimum_revision,
                } = &local_state
                else {
                    return Err(JournaledNamespaceError::LocalRereadMismatch);
                };
                if *minimum_revision != opened.new_identity.revision()
                    || *encoded != opened.new_encoded
                {
                    return Err(JournaledNamespaceError::LocalRereadMismatch);
                }
                ensure_leases(driver, local, external, expected_binding, fencing_token)?;
                let mutation = record.finalize_prepared(
                    JournalLeaseContext::new(binding, fencing_token),
                    observation,
                )?;
                persist_external_exact(external, &mutation, expected_binding, fencing_token)?;
            }
            RecoveryPlan::FailClosed(reason) => {
                return Err(JournaledNamespaceError::FailClosed(reason));
            }
        }
    }
    Err(JournaledNamespaceError::RecoveryLimitExceeded)
}

#[allow(clippy::too_many_arguments)]
fn replace_stable<D, G, P>(
    driver: &D,
    local: &D::Guard,
    external: &mut G,
    binding: &JournalBinding,
    protocol: &P,
    current: SettledOwned<P::TransitionState, P::Projection>,
    proposed_revision: u64,
    proposed_encoded: Vec<u8>,
    protocol_fingerprint: [u8; 32],
    expected_binding: BindingFingerprint,
    fencing_token: FencingToken,
) -> Result<SettledOwned<P::TransitionState, P::Projection>, JournaledNamespaceError>
where
    D: LocalNamespaceDriver,
    G: ExternalJournalGuard,
    P: SnapshotProtocol,
{
    validate_bounds(&proposed_encoded)?;
    if proposed_revision <= current.revision {
        return Err(JournaledNamespaceError::RevisionNotAdvanced {
            current: current.revision,
            proposed: proposed_revision,
        });
    }
    let proposed_validated =
        protocol.validate_snapshot(binding, proposed_revision, &proposed_encoded)?;
    protocol.validate_transition(
        binding,
        current.revision,
        &current.transition_state,
        proposed_revision,
        proposed_validated.transition_state(),
    )?;
    ensure_leases(driver, local, external, expected_binding, fencing_token)?;

    let image = external.seal_snapshot(
        binding,
        proposed_revision,
        protocol_fingerprint,
        &proposed_encoded,
    )?;
    let expected_identity =
        StateIdentity::from_plaintext(proposed_revision, protocol_fingerprint, &proposed_encoded)?;
    if image.identity() != expected_identity || !image.verifies_plaintext(&proposed_encoded) {
        return Err(JournaledNamespaceError::SnapshotFingerprintMismatch);
    }
    let (opened, opened_validated) =
        open_and_validate(external, binding, protocol, protocol_fingerprint, &image)?;
    if opened != proposed_encoded {
        return Err(JournaledNamespaceError::SnapshotFingerprintMismatch);
    }
    if proposed_validated.transition_state() != opened_validated.transition_state() {
        return Err(JournaledNamespaceError::ProtocolValidationInconsistent);
    }
    protocol.validate_transition(
        binding,
        current.revision,
        &current.transition_state,
        proposed_revision,
        opened_validated.transition_state(),
    )?;
    ensure_leases(driver, local, external, expected_binding, fencing_token)?;

    let old_observation = DatabaseObservation::Present(current.identity);
    let prepared = current.record.prepare_transition(
        JournalLeaseContext::new(binding, fencing_token),
        old_observation,
        image,
    )?;
    let prepared_record =
        persist_external_exact(external, &prepared, expected_binding, fencing_token)?;

    ensure_leases(driver, local, external, expected_binding, fencing_token)?;
    let old_state = AuthenticatedNamespaceState::Initialized {
        encoded: current.encoded,
        minimum_revision: current.revision,
    };
    apply_local_exact(
        driver,
        local,
        &old_state,
        proposed_revision,
        &proposed_encoded,
    )?;
    let reread = local_result(driver, local.load())?;
    let observation = observe_local(protocol, binding, protocol_fingerprint, &reread)?;
    if observation != DatabaseObservation::Present(expected_identity) {
        return Err(JournaledNamespaceError::LocalRereadMismatch);
    }
    ensure_leases(driver, local, external, expected_binding, fencing_token)?;

    let stable = prepared_record.finalize_prepared(
        JournalLeaseContext::new(binding, fencing_token),
        observation,
    )?;
    let stable_record = persist_external_exact(external, &stable, expected_binding, fencing_token)?;
    let (opened_transition_state, opened_projection) = opened_validated.into_parts();
    let selected = SettledOwned {
        record: stable_record,
        revision: proposed_revision,
        encoded: proposed_encoded,
        identity: expected_identity,
        transition_state: opened_transition_state,
        projection: opened_projection,
    };
    confirm_settled(
        driver,
        local,
        external,
        &selected,
        expected_binding,
        fencing_token,
    )?;
    Ok(selected)
}

fn validate_bounds(encoded: &[u8]) -> Result<(), JournaledNamespaceError> {
    if encoded.is_empty() {
        return Err(JournaledNamespaceError::EmptySnapshot);
    }
    if encoded.len() > MAX_PLAINTEXT_SNAPSHOT_SIZE {
        return Err(JournaledNamespaceError::SnapshotTooLarge {
            actual: encoded.len(),
            maximum: MAX_PLAINTEXT_SNAPSHOT_SIZE,
        });
    }
    Ok(())
}

fn observe_local<P: SnapshotProtocol>(
    protocol: &P,
    binding: &JournalBinding,
    protocol_fingerprint: [u8; 32],
    state: &AuthenticatedNamespaceState,
) -> Result<DatabaseObservation, JournaledNamespaceError> {
    match state {
        AuthenticatedNamespaceState::NeverInitialized => Ok(DatabaseObservation::Absent),
        AuthenticatedNamespaceState::Initialized {
            encoded,
            minimum_revision,
        } => {
            validate_bounds(encoded)?;
            let _projection = protocol.validate_snapshot(binding, *minimum_revision, encoded)?;
            Ok(DatabaseObservation::from_plaintext(
                *minimum_revision,
                protocol_fingerprint,
                encoded,
            )?)
        }
    }
}

type OpenedValidated<P> = (
    Vec<u8>,
    ValidatedSnapshot<
        <P as SnapshotProtocol>::TransitionState,
        <P as SnapshotProtocol>::Projection,
    >,
);

fn open_and_validate<G, P>(
    external: &G,
    binding: &JournalBinding,
    protocol: &P,
    protocol_fingerprint: [u8; 32],
    image: &SnapshotImage,
) -> Result<OpenedValidated<P>, JournaledNamespaceError>
where
    G: ExternalJournalGuard,
    P: SnapshotProtocol,
{
    if protocol_fingerprint != image.identity().protocol_fingerprint() {
        return Err(JournaledNamespaceError::ProtocolFingerprintMismatch);
    }
    let opened = external.open_snapshot(binding, image)?;
    validate_bounds(&opened)?;
    if !image.verifies_plaintext(&opened) {
        return Err(JournaledNamespaceError::SnapshotFingerprintMismatch);
    }
    let validated = protocol.validate_snapshot(binding, image.identity().revision(), &opened)?;
    Ok((opened, validated))
}

struct OpenedPrepared {
    old_identity: StateIdentity,
    old_encoded: Vec<u8>,
    new_identity: StateIdentity,
    new_encoded: Vec<u8>,
}

fn open_prepared<G, P>(
    external: &G,
    binding: &JournalBinding,
    protocol: &P,
    protocol_fingerprint: [u8; 32],
    record: &JournalRecord,
) -> Result<OpenedPrepared, JournaledNamespaceError>
where
    G: ExternalJournalGuard,
    P: SnapshotProtocol,
{
    let JournalState::Prepared { old, new, .. } = record.state() else {
        return Err(JournaledNamespaceError::ExternalRereadMismatch);
    };
    let (old_encoded, old_validated) =
        open_and_validate(external, binding, protocol, protocol_fingerprint, old)?;
    let (new_encoded, new_validated) =
        open_and_validate(external, binding, protocol, protocol_fingerprint, new)?;
    protocol.validate_transition(
        binding,
        old.identity().revision(),
        old_validated.transition_state(),
        new.identity().revision(),
        new_validated.transition_state(),
    )?;
    Ok(OpenedPrepared {
        old_identity: old.identity(),
        old_encoded,
        new_identity: new.identity(),
        new_encoded,
    })
}

fn expectation(state: &AuthenticatedNamespaceState) -> StateExpectation<'_> {
    match state {
        AuthenticatedNamespaceState::NeverInitialized => StateExpectation::Absent,
        AuthenticatedNamespaceState::Initialized {
            encoded,
            minimum_revision,
        } => StateExpectation::Exact {
            minimum_revision: *minimum_revision,
            encoded,
        },
    }
}

fn apply_local_exact<D: LocalNamespaceDriver>(
    driver: &D,
    local: &D::Guard,
    prior: &AuthenticatedNamespaceState,
    proposed_revision: u64,
    proposed: &[u8],
) -> Result<(), JournaledNamespaceError> {
    let write = local_result(
        driver,
        local.compare_exchange(expectation(prior), proposed_revision, proposed),
    )?;
    match write {
        AuthenticatedNamespaceWrite::Committed | AuthenticatedNamespaceWrite::AlreadyCommitted => {}
        AuthenticatedNamespaceWrite::Conflict => {
            return Err(JournaledNamespaceError::LocalConflict);
        }
    }
    let reread = local_result(driver, local.load())?;
    match reread {
        AuthenticatedNamespaceState::Initialized {
            encoded,
            minimum_revision,
        } if minimum_revision == proposed_revision && encoded == proposed => Ok(()),
        _ => Err(JournaledNamespaceError::LocalRereadMismatch),
    }
}

fn local_result<D, T>(
    driver: &D,
    result: Result<T, AuthenticatedNamespaceError>,
) -> Result<T, JournaledNamespaceError>
where
    D: LocalNamespaceDriver,
{
    if driver.reopen_required() {
        return Err(JournaledNamespaceError::LocalReopenRequired);
    }
    result.map_err(JournaledNamespaceError::Local)
}

fn ensure_leases<D, G>(
    driver: &D,
    local: &D::Guard,
    external: &G,
    binding_fingerprint: BindingFingerprint,
    fencing_token: FencingToken,
) -> Result<(), JournaledNamespaceError>
where
    D: LocalNamespaceDriver,
    G: ExternalJournalGuard,
{
    HeldLeases {
        driver,
        local,
        external,
        binding_fingerprint,
        fencing_token,
    }
    .ensure_current()
}

fn persist_external_exact<G: ExternalJournalGuard>(
    external: &mut G,
    mutation: &JournalMutation,
    binding_fingerprint: BindingFingerprint,
    fencing_token: FencingToken,
) -> Result<JournalRecord, JournaledNamespaceError> {
    ensure_external(external, binding_fingerprint, fencing_token)?;
    match external.compare_exchange_durable(mutation) {
        Ok(ExternalWrite::Durable) => confirm_external_held(
            external,
            mutation.proposed(),
            binding_fingerprint,
            fencing_token,
        ),
        Ok(ExternalWrite::Conflict) => {
            confirm_after_definite_conflict(external, mutation, binding_fingerprint, fencing_token)
        }
        Ok(ExternalWrite::OutcomeUnknown) | Err(_) => {
            reconcile_external(external, mutation, binding_fingerprint, fencing_token)
        }
    }
}

fn reconcile_external<G: ExternalJournalGuard>(
    external: &mut G,
    mutation: &JournalMutation,
    binding_fingerprint: BindingFingerprint,
    fencing_token: FencingToken,
) -> Result<JournalRecord, JournaledNamespaceError> {
    ensure_external(external, binding_fingerprint, fencing_token)?;
    let loaded = external.load_authenticated()?;
    match mutation.reconcile(loaded.as_ref()) {
        MutationReconciliation::Committed => confirm_external_held(
            external,
            mutation.proposed(),
            binding_fingerprint,
            fencing_token,
        ),
        MutationReconciliation::FailClosedConflict => {
            Err(JournaledNamespaceError::ExternalConflict)
        }
        MutationReconciliation::RetryExact => {
            ensure_external(external, binding_fingerprint, fencing_token)?;
            match external.compare_exchange_durable(mutation) {
                Ok(ExternalWrite::Durable) => confirm_external_held(
                    external,
                    mutation.proposed(),
                    binding_fingerprint,
                    fencing_token,
                ),
                Ok(ExternalWrite::Conflict) => confirm_after_definite_conflict(
                    external,
                    mutation,
                    binding_fingerprint,
                    fencing_token,
                ),
                Ok(ExternalWrite::OutcomeUnknown) | Err(_) => {
                    ensure_external(external, binding_fingerprint, fencing_token)?;
                    let retried = external.load_authenticated()?;
                    match mutation.reconcile(retried.as_ref()) {
                        MutationReconciliation::Committed => confirm_external_held(
                            external,
                            mutation.proposed(),
                            binding_fingerprint,
                            fencing_token,
                        ),
                        MutationReconciliation::FailClosedConflict => {
                            Err(JournaledNamespaceError::ExternalConflict)
                        }
                        MutationReconciliation::RetryExact => {
                            Err(JournaledNamespaceError::ExternalOutcomeUnresolved)
                        }
                    }
                }
            }
        }
    }
}

fn confirm_after_definite_conflict<G: ExternalJournalGuard>(
    external: &G,
    mutation: &JournalMutation,
    binding_fingerprint: BindingFingerprint,
    fencing_token: FencingToken,
) -> Result<JournalRecord, JournaledNamespaceError> {
    ensure_external(external, binding_fingerprint, fencing_token)?;
    let loaded = external.load_authenticated()?;
    match loaded {
        Some(record) if record == *mutation.proposed() => confirm_external_held(
            external,
            mutation.proposed(),
            binding_fingerprint,
            fencing_token,
        ),
        _ => Err(JournaledNamespaceError::ExternalConflict),
    }
}

fn ensure_external<G: ExternalJournalGuard>(
    external: &G,
    binding_fingerprint: BindingFingerprint,
    fencing_token: FencingToken,
) -> Result<(), JournaledNamespaceError> {
    if external.binding_fingerprint() != binding_fingerprint {
        return Err(JournaledNamespaceError::ExternalBindingMismatch);
    }
    if external.fencing_token() != fencing_token {
        return Err(JournaledNamespaceError::ExternalFencingMismatch);
    }
    external.ensure_held()?;
    Ok(())
}

fn confirm_external<G: ExternalJournalGuard>(
    external: &G,
    expected: &JournalRecord,
) -> Result<JournalRecord, JournaledNamespaceError> {
    let loaded = external.load_authenticated()?;
    match loaded {
        Some(record) if record == *expected => Ok(record),
        _ => Err(JournaledNamespaceError::ExternalRereadMismatch),
    }
}

fn confirm_external_held<G: ExternalJournalGuard>(
    external: &G,
    expected: &JournalRecord,
    binding_fingerprint: BindingFingerprint,
    fencing_token: FencingToken,
) -> Result<JournalRecord, JournaledNamespaceError> {
    ensure_external(external, binding_fingerprint, fencing_token)?;
    confirm_external(external, expected)
}

fn confirm_settled<D, G, T, V>(
    driver: &D,
    local: &D::Guard,
    external: &G,
    settled: &SettledOwned<T, V>,
    binding_fingerprint: BindingFingerprint,
    fencing_token: FencingToken,
) -> Result<(), JournaledNamespaceError>
where
    D: LocalNamespaceDriver,
    G: ExternalJournalGuard,
{
    ensure_leases(driver, local, external, binding_fingerprint, fencing_token)?;
    let record = external.load_authenticated()?;
    if record.as_ref() != Some(&settled.record) {
        return Err(JournaledNamespaceError::ExternalRereadMismatch);
    }
    let local_state = local_result(driver, local.load())?;
    match local_state {
        AuthenticatedNamespaceState::Initialized {
            encoded,
            minimum_revision,
        } if minimum_revision == settled.revision && encoded == settled.encoded => Ok(()),
        _ => Err(JournaledNamespaceError::LocalRereadMismatch),
    }
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::num::NonZeroU64;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::rc::Rc;

    use hns_rollback_journal::{
        privileged_provision, JournalBindingParts, RollbackProtectionClass,
    };
    use hns_store::{MemoryStore, StoreError};

    use super::*;

    const PROTOCOL_FINGERPRINT: [u8; 32] = [0x42; 32];
    const EXTERNAL_TOKEN: u64 = 17;

    type Events = Rc<RefCell<Vec<&'static str>>>;

    fn binding(protection: RollbackProtectionClass) -> JournalBinding {
        JournalBinding::new(JournalBindingParts {
            installation_lineage: [1; 32],
            network_magic: 0xfeed_beef,
            role_id: [2; 32],
            storage_namespace_id: [3; 32],
            logical_key: [4; 32],
            protocol_id: [5; 32],
            protocol_version: 1,
            aead_suite: 1,
            key_version: 1,
            key_id: [6; 32],
            protection,
        })
        .expect("valid binding")
    }

    fn token(value: u64) -> FencingToken {
        FencingToken::new(NonZeroU64::new(value).expect("nonzero token"))
    }

    fn sealed_image(revision: u64, plaintext: &[u8]) -> SnapshotImage {
        let mut sealed = vec![0xa5; 12];
        sealed.extend_from_slice(plaintext);
        sealed.extend_from_slice(&[0x5a; 16]);
        SnapshotImage::new(revision, PROTOCOL_FINGERPRINT, plaintext, sealed)
            .expect("valid sealed image")
    }

    fn enrolled_stable(binding: JournalBinding, revision: u64, plaintext: &[u8]) -> JournalRecord {
        let lease = JournalLeaseContext::new(&binding, token(EXTERNAL_TOKEN));
        let marker = privileged_provision(binding, lease)
            .expect("provision marker")
            .into_proposed();
        let image = sealed_image(revision, plaintext);
        let observation =
            DatabaseObservation::from_plaintext(revision, PROTOCOL_FINGERPRINT, plaintext)
                .expect("observation");
        marker
            .privileged_enroll(lease, observation, image)
            .expect("enroll stable")
            .into_proposed()
    }

    fn prepared_record(
        binding: JournalBinding,
        old_revision: u64,
        old: &[u8],
        new_revision: u64,
        new: &[u8],
    ) -> JournalRecord {
        let stable = enrolled_stable(binding, old_revision, old);
        let observation =
            DatabaseObservation::from_plaintext(old_revision, PROTOCOL_FINGERPRINT, old)
                .expect("old observation");
        stable
            .prepare_transition(
                JournalLeaseContext::new(&binding, token(EXTERNAL_TOKEN)),
                observation,
                sealed_image(new_revision, new),
            )
            .expect("prepare")
            .into_proposed()
    }

    #[derive(Clone, Copy)]
    struct TestProtocol;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TestProjection {
        encoded_len: usize,
        selected_marker: u8,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TestTransitionState {
        unrelated_highwater: u8,
    }

    impl SnapshotProtocol for TestProtocol {
        type TransitionState = TestTransitionState;
        type Projection = TestProjection;

        fn protocol_fingerprint(&self, _binding: &JournalBinding) -> [u8; 32] {
            PROTOCOL_FINGERPRINT
        }

        fn validate_snapshot(
            &self,
            _binding: &JournalBinding,
            _revision: u64,
            encoded: &[u8],
        ) -> Result<
            ValidatedSnapshot<Self::TransitionState, Self::Projection>,
            ProtocolValidationError,
        > {
            if encoded == b"invalid" {
                return Err(ProtocolValidationError("test rejection"));
            }
            Ok(ValidatedSnapshot::new(
                TestTransitionState {
                    unrelated_highwater: *encoded
                        .last()
                        .ok_or(ProtocolValidationError("empty test snapshot"))?,
                },
                TestProjection {
                    encoded_len: encoded.len(),
                    selected_marker: *encoded
                        .first()
                        .ok_or(ProtocolValidationError("empty test snapshot"))?,
                },
            ))
        }

        fn validate_transition(
            &self,
            _binding: &JournalBinding,
            current_revision: u64,
            current: &Self::TransitionState,
            proposed_revision: u64,
            proposed: &Self::TransitionState,
        ) -> Result<(), ProtocolValidationError> {
            if proposed_revision <= current_revision {
                return Err(ProtocolValidationError("test revision regression"));
            }
            if proposed.unrelated_highwater < current.unrelated_highwater {
                return Err(ProtocolValidationError("test semantic regression"));
            }
            Ok(())
        }
    }

    struct ExternalAttempt {
        outcome: Result<ExternalWrite, ExternalJournalError>,
        apply: bool,
    }

    struct FakeExternalState {
        record: Option<JournalRecord>,
        binding_fingerprint: BindingFingerprint,
        fencing_token: FencingToken,
        held: bool,
        qualification_error: Option<ExternalJournalError>,
        attempts: VecDeque<ExternalAttempt>,
        load_attempts: VecDeque<Result<(), ExternalJournalError>>,
        open_attempts: VecDeque<Result<Option<Vec<u8>>, ExternalJournalError>>,
        seal_attempts: VecDeque<Result<(), ExternalJournalError>>,
        mutation_bytes: Vec<Vec<u8>>,
        seals: usize,
        ensure_calls: usize,
        open_override: Option<Vec<u8>>,
        lose_on_event: Option<&'static str>,
        lose_after_event: Option<&'static str>,
        events: Events,
    }

    #[derive(Clone)]
    struct FakeExternalControl(Rc<RefCell<FakeExternalState>>);

    impl FakeExternalControl {
        fn new(binding: &JournalBinding, record: Option<JournalRecord>, events: Events) -> Self {
            Self(Rc::new(RefCell::new(FakeExternalState {
                record,
                binding_fingerprint: binding.fingerprint(),
                fencing_token: token(EXTERNAL_TOKEN),
                held: false,
                qualification_error: None,
                attempts: VecDeque::new(),
                load_attempts: VecDeque::new(),
                open_attempts: VecDeque::new(),
                seal_attempts: VecDeque::new(),
                mutation_bytes: Vec::new(),
                seals: 0,
                ensure_calls: 0,
                open_override: None,
                lose_on_event: None,
                lose_after_event: None,
                events,
            })))
        }

        fn push_attempt(&self, outcome: Result<ExternalWrite, ExternalJournalError>, apply: bool) {
            self.0
                .borrow_mut()
                .attempts
                .push_back(ExternalAttempt { outcome, apply });
        }

        fn push_open_attempt(&self, outcome: Result<Option<Vec<u8>>, ExternalJournalError>) {
            self.0.borrow_mut().open_attempts.push_back(outcome);
        }
    }

    fn enter_external_event(
        state: &mut FakeExternalState,
        event: &'static str,
    ) -> Result<(), ExternalJournalError> {
        state.events.borrow_mut().push(event);
        if state.lose_on_event == Some(event) {
            state.lose_on_event = None;
            state.held = false;
        }
        if state.held {
            Ok(())
        } else {
            Err(ExternalJournalError::LeaseLost)
        }
    }

    fn finish_external_event(state: &mut FakeExternalState, event: &'static str) {
        if state.lose_after_event == Some(event) {
            state.lose_after_event = None;
            state.held = false;
        }
    }

    struct FakeBroker {
        control: FakeExternalControl,
    }

    struct FakeExternalGuard {
        control: FakeExternalControl,
    }

    impl ExternalJournalBroker for FakeBroker {
        type Guard<'a> = FakeExternalGuard;

        fn ensure_production_qualified(
            &self,
            _binding: &JournalBinding,
        ) -> Result<(), ExternalJournalError> {
            let state = self.control.0.borrow();
            state.events.borrow_mut().push("external_qualified");
            match &state.qualification_error {
                Some(error) => Err(error.clone()),
                None => Ok(()),
            }
        }

        fn acquire<'a>(
            &'a self,
            _binding: &JournalBinding,
        ) -> Result<Self::Guard<'a>, ExternalJournalError> {
            let mut state = self.control.0.borrow_mut();
            state.events.borrow_mut().push("external_acquire");
            if state.held {
                return Err(ExternalJournalError::LeaseUnavailable);
            }
            state.held = true;
            Ok(FakeExternalGuard {
                control: self.control.clone(),
            })
        }
    }

    impl ExternalJournalGuard for FakeExternalGuard {
        fn binding_fingerprint(&self) -> BindingFingerprint {
            self.control.0.borrow().binding_fingerprint
        }

        fn fencing_token(&self) -> FencingToken {
            self.control.0.borrow().fencing_token
        }

        fn ensure_held(&self) -> Result<(), ExternalJournalError> {
            let mut state = self.control.0.borrow_mut();
            state.ensure_calls += 1;
            enter_external_event(&mut state, "external_ensure")
        }

        fn load_authenticated(&self) -> Result<Option<JournalRecord>, ExternalJournalError> {
            let mut state = self.control.0.borrow_mut();
            enter_external_event(&mut state, "external_load")?;
            if let Some(outcome) = state.load_attempts.pop_front() {
                outcome?;
            }
            Ok(state.record.clone())
        }

        fn compare_exchange_durable(
            &mut self,
            mutation: &JournalMutation,
        ) -> Result<ExternalWrite, ExternalJournalError> {
            let mut state = self.control.0.borrow_mut();
            let event = match mutation.proposed().state() {
                JournalState::Prepared { .. } => "external_write_prepared",
                JournalState::Stable { .. } => "external_write_stable",
                _ => "external_write_other",
            };
            enter_external_event(&mut state, event)?;
            state.mutation_bytes.push(mutation.proposed().encode());
            let attempt = state.attempts.pop_front().unwrap_or(ExternalAttempt {
                outcome: Ok(ExternalWrite::Durable),
                apply: true,
            });
            if mutation.expectation().binding_fingerprint() != state.binding_fingerprint
                || mutation.expectation().fencing_token() != state.fencing_token
            {
                finish_external_event(&mut state, event);
                return Ok(ExternalWrite::Conflict);
            }
            if attempt.apply {
                match mutation.reconcile(state.record.as_ref()) {
                    MutationReconciliation::Committed => {}
                    MutationReconciliation::RetryExact => {
                        state.record = Some(mutation.proposed().clone());
                    }
                    MutationReconciliation::FailClosedConflict => {
                        finish_external_event(&mut state, event);
                        return Ok(ExternalWrite::Conflict);
                    }
                }
            }
            finish_external_event(&mut state, event);
            attempt.outcome
        }

        fn seal_snapshot(
            &mut self,
            _binding: &JournalBinding,
            revision: u64,
            protocol_fingerprint: [u8; 32],
            plaintext: &[u8],
        ) -> Result<SnapshotImage, ExternalJournalError> {
            let mut state = self.control.0.borrow_mut();
            enter_external_event(&mut state, "external_seal")?;
            state.seals += 1;
            if let Some(outcome) = state.seal_attempts.pop_front() {
                outcome?;
            }
            let mut sealed = vec![0xa5; 12];
            sealed.extend_from_slice(plaintext);
            sealed.extend_from_slice(&[0x5a; 16]);
            let image = SnapshotImage::new(revision, protocol_fingerprint, plaintext, sealed)
                .map_err(|_| ExternalJournalError::SealFailed)?;
            finish_external_event(&mut state, "external_seal");
            Ok(image)
        }

        fn open_snapshot(
            &self,
            _binding: &JournalBinding,
            image: &SnapshotImage,
        ) -> Result<Vec<u8>, ExternalJournalError> {
            let mut state = self.control.0.borrow_mut();
            enter_external_event(&mut state, "external_open")?;
            let scripted = state.open_attempts.pop_front().transpose()?;
            Ok(scripted
                .flatten()
                .or_else(|| state.open_override.clone())
                .unwrap_or_else(|| image.sealed().encrypted_payload().to_vec()))
        }
    }

    impl Drop for FakeExternalGuard {
        fn drop(&mut self) {
            let mut state = self.control.0.borrow_mut();
            state.held = false;
            state.events.borrow_mut().push("external_drop");
        }
    }

    enum LocalBehavior {
        Commit,
        AlreadyCommitted,
        CommitWrongReread,
        Conflict,
        Error { apply: bool, reopen: bool },
    }

    struct FakeLocalState {
        image: AuthenticatedNamespaceState,
        held: bool,
        reopen_required: bool,
        lose_on_event: Option<&'static str>,
        lose_after_event: Option<&'static str>,
        behaviors: VecDeque<LocalBehavior>,
        loads: usize,
        writes: usize,
        acquired_namespace: Option<OperationNamespaceId>,
        events: Events,
    }

    #[derive(Clone)]
    struct FakeLocalDriver {
        state: Rc<RefCell<FakeLocalState>>,
    }

    struct FakeLocalGuard {
        state: Rc<RefCell<FakeLocalState>>,
    }

    impl FakeLocalDriver {
        fn new(image: AuthenticatedNamespaceState, events: Events) -> Self {
            Self {
                state: Rc::new(RefCell::new(FakeLocalState {
                    image,
                    held: false,
                    reopen_required: false,
                    lose_on_event: None,
                    lose_after_event: None,
                    behaviors: VecDeque::new(),
                    loads: 0,
                    writes: 0,
                    acquired_namespace: None,
                    events,
                })),
            }
        }

        fn push_behavior(&self, behavior: LocalBehavior) {
            self.state.borrow_mut().behaviors.push_back(behavior);
        }
    }

    fn enter_local_event(
        state: &mut FakeLocalState,
        event: &'static str,
    ) -> Result<(), AuthenticatedNamespaceError> {
        state.events.borrow_mut().push(event);
        if state.lose_on_event == Some(event) {
            state.lose_on_event = None;
            state.held = false;
        }
        if state.held {
            Ok(())
        } else {
            Err(AuthenticatedNamespaceError::LeaseLost)
        }
    }

    fn finish_local_event(state: &mut FakeLocalState, event: &'static str) {
        if state.lose_after_event == Some(event) {
            state.lose_after_event = None;
            state.held = false;
        }
    }

    impl LocalNamespaceDriver for FakeLocalDriver {
        type Guard = FakeLocalGuard;

        fn acquire(
            &self,
            namespace: OperationNamespaceId,
        ) -> Result<Self::Guard, AuthenticatedNamespaceError> {
            let mut state = self.state.borrow_mut();
            state.events.borrow_mut().push("local_acquire");
            if state.held {
                return Err(AuthenticatedNamespaceError::Busy);
            }
            state.held = true;
            state.acquired_namespace = Some(namespace);
            Ok(FakeLocalGuard {
                state: Rc::clone(&self.state),
            })
        }

        fn reopen_required(&self) -> bool {
            self.state.borrow().reopen_required
        }
    }

    impl LocalNamespaceGuard for FakeLocalGuard {
        fn ensure_held(&self) -> Result<(), AuthenticatedNamespaceError> {
            let mut state = self.state.borrow_mut();
            enter_local_event(&mut state, "local_ensure")
        }

        fn load(&self) -> Result<AuthenticatedNamespaceState, AuthenticatedNamespaceError> {
            let mut state = self.state.borrow_mut();
            enter_local_event(&mut state, "local_load")?;
            state.loads += 1;
            Ok(state.image.clone())
        }

        fn compare_exchange(
            &self,
            expected: StateExpectation<'_>,
            proposed_revision: u64,
            proposed: &[u8],
        ) -> Result<AuthenticatedNamespaceWrite, AuthenticatedNamespaceError> {
            let mut state = self.state.borrow_mut();
            enter_local_event(&mut state, "local_cas")?;
            state.writes += 1;
            if !expectation_matches(expected, &state.image) {
                return Ok(AuthenticatedNamespaceWrite::Conflict);
            }
            let behavior = state.behaviors.pop_front().unwrap_or(LocalBehavior::Commit);
            let replacement = AuthenticatedNamespaceState::Initialized {
                encoded: proposed.to_vec(),
                minimum_revision: proposed_revision,
            };
            let result = match behavior {
                LocalBehavior::Commit => {
                    state.image = replacement;
                    Ok(AuthenticatedNamespaceWrite::Committed)
                }
                LocalBehavior::AlreadyCommitted => {
                    state.image = replacement;
                    Ok(AuthenticatedNamespaceWrite::AlreadyCommitted)
                }
                LocalBehavior::CommitWrongReread => {
                    state.image = AuthenticatedNamespaceState::Initialized {
                        encoded: b"wrong-reread".to_vec(),
                        minimum_revision: proposed_revision,
                    };
                    Ok(AuthenticatedNamespaceWrite::Committed)
                }
                LocalBehavior::Conflict => Ok(AuthenticatedNamespaceWrite::Conflict),
                LocalBehavior::Error { apply, reopen } => {
                    if apply {
                        state.image = replacement;
                    }
                    state.reopen_required = reopen;
                    Err(AuthenticatedNamespaceError::Store(StoreError::Backend(
                        "injected local publication error".to_owned(),
                    )))
                }
            };
            finish_local_event(&mut state, "local_cas");
            result
        }
    }

    impl Drop for FakeLocalGuard {
        fn drop(&mut self) {
            let mut state = self.state.borrow_mut();
            state.held = false;
            state.events.borrow_mut().push("local_drop");
        }
    }

    fn expectation_matches(
        expected: StateExpectation<'_>,
        current: &AuthenticatedNamespaceState,
    ) -> bool {
        match (expected, current) {
            (StateExpectation::Absent, AuthenticatedNamespaceState::NeverInitialized) => true,
            (
                StateExpectation::Exact {
                    minimum_revision: expected_revision,
                    encoded: expected_encoded,
                },
                AuthenticatedNamespaceState::Initialized {
                    encoded,
                    minimum_revision,
                },
            ) => expected_revision == *minimum_revision && expected_encoded == encoded,
            _ => false,
        }
    }

    fn initialized(revision: u64, encoded: &[u8]) -> AuthenticatedNamespaceState {
        AuthenticatedNamespaceState::Initialized {
            encoded: encoded.to_vec(),
            minimum_revision: revision,
        }
    }

    fn position(events: &[&'static str], needle: &'static str) -> usize {
        events
            .iter()
            .position(|event| *event == needle)
            .unwrap_or_else(|| panic!("missing event {needle:?}: {events:?}"))
    }

    #[test]
    fn stable_keep_acquires_external_first_and_drops_local_first() {
        let binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let external = FakeExternalControl::new(
            &binding,
            Some(enrolled_stable(binding, 7, b"current")),
            Rc::clone(&events),
        );
        let broker = FakeBroker { control: external };
        let local = FakeLocalDriver::new(initialized(7, b"current"), Rc::clone(&events));

        let evidence = run_with_driver(
            &local,
            &broker,
            &binding,
            &TestProtocol,
            |settled| {
                assert_eq!(settled.revision(), 7);
                assert_eq!(settled.projection().encoded_len, b"current".len());
                assert_eq!(settled.projection().selected_marker, b'c');
                settled.ensure_current().expect("planner leases");
                settled.keep("context")
            },
            |settled, context| {
                assert_eq!(settled.revision(), 7);
                assert_eq!(settled.projection().encoded_len, b"current".len());
                assert_eq!(context, "context");
                settled.ensure_current().expect("use leases");
                11_u64
            },
        )
        .expect("stable keep");

        assert_eq!(evidence.revision(), 7);
        assert_eq!(evidence.protocol_fingerprint(), PROTOCOL_FINGERPRINT);
        assert_eq!(*evidence.value(), 11);
        assert_eq!(
            local.state.borrow().acquired_namespace,
            Some(OperationNamespaceId::new(*binding.storage_namespace_id()).expect("namespace"))
        );
        let events = events.borrow();
        assert!(position(&events, "external_acquire") < position(&events, "local_acquire"));
        assert_eq!(&events[events.len() - 2..], ["local_drop", "external_drop"]);
    }

    #[test]
    fn replacement_is_prepared_then_local_then_stable_before_use() {
        let binding = binding(RollbackProtectionClass::IndependentLocalRoot);
        let events = Rc::new(RefCell::new(Vec::new()));
        let external = FakeExternalControl::new(
            &binding,
            Some(enrolled_stable(binding, 7, b"old")),
            Rc::clone(&events),
        );
        let broker = FakeBroker {
            control: external.clone(),
        };
        let local = FakeLocalDriver::new(initialized(7, b"old"), Rc::clone(&events));

        let evidence = run_with_driver(
            &local,
            &broker,
            &binding,
            &TestProtocol,
            |settled| {
                assert_eq!(settled.projection().selected_marker, b'o');
                settled.replace(8, b"new".to_vec(), "promote")
            },
            |settled, context| {
                assert_eq!(settled.revision(), 8);
                assert_eq!(settled.projection().selected_marker, b'n');
                assert_eq!(context, "promote");
                events.borrow_mut().push("dependent_use");
                true
            },
        )
        .expect("replace");

        assert_eq!(evidence.revision(), 8);
        assert!(*evidence.value());
        assert_eq!(external.0.borrow().seals, 1);
        assert_eq!(local.state.borrow().image, initialized(8, b"new"));
        let external_record = external.0.borrow().record.clone().expect("record");
        assert!(matches!(
            external_record.state(),
            JournalState::Stable { .. }
        ));
        let events = events.borrow();
        let prepared = position(&events, "external_write_prepared");
        let local_cas = position(&events, "local_cas");
        let stable = position(&events, "external_write_stable");
        let dependent = position(&events, "dependent_use");
        assert!(prepared < local_cas && local_cas < stable && stable < dependent);
    }

    #[test]
    fn semantic_regression_is_rejected_before_seal_or_prepared() {
        let binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let original = enrolled_stable(binding, 1, b"old");
        let external =
            FakeExternalControl::new(&binding, Some(original.clone()), Rc::clone(&events));
        let broker = FakeBroker {
            control: external.clone(),
        };
        let local = FakeLocalDriver::new(initialized(1, b"old"), events);

        let error = run_with_driver(
            &local,
            &broker,
            &binding,
            &TestProtocol,
            |settled| settled.replace(2, b"regress-a".to_vec(), ()),
            |_, ()| panic!("semantic regression must never reach dependent use"),
        )
        .expect_err("semantic regression");

        assert!(matches!(
            error,
            JournaledNamespaceError::Protocol(ProtocolValidationError("test semantic regression"))
        ));
        let state = external.0.borrow();
        assert_eq!(state.record.as_ref(), Some(&original));
        assert_eq!(state.seals, 0);
        assert!(state.mutation_bytes.is_empty());
        assert_eq!(local.state.borrow().writes, 0);
    }

    #[test]
    fn mutable_call_history_in_protocol_validation_fails_before_prepared() {
        struct InconsistentProtocol(std::cell::Cell<u8>);

        impl SnapshotProtocol for InconsistentProtocol {
            type TransitionState = u8;
            type Projection = ();

            fn protocol_fingerprint(&self, _binding: &JournalBinding) -> [u8; 32] {
                PROTOCOL_FINGERPRINT
            }

            fn validate_snapshot(
                &self,
                _binding: &JournalBinding,
                _revision: u64,
                _encoded: &[u8],
            ) -> Result<
                ValidatedSnapshot<Self::TransitionState, Self::Projection>,
                ProtocolValidationError,
            > {
                let next = self.0.get().checked_add(1).expect("test call count");
                self.0.set(next);
                Ok(ValidatedSnapshot::new(next, ()))
            }

            fn validate_transition(
                &self,
                _binding: &JournalBinding,
                _current_revision: u64,
                _current: &Self::TransitionState,
                _proposed_revision: u64,
                _proposed: &Self::TransitionState,
            ) -> Result<(), ProtocolValidationError> {
                Ok(())
            }
        }

        let binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let original = enrolled_stable(binding, 1, b"old");
        let external =
            FakeExternalControl::new(&binding, Some(original.clone()), Rc::clone(&events));
        let broker = FakeBroker {
            control: external.clone(),
        };
        let local = FakeLocalDriver::new(initialized(1, b"old"), events);
        let protocol = InconsistentProtocol(std::cell::Cell::new(0));

        let error = run_with_driver(
            &local,
            &broker,
            &binding,
            &protocol,
            |settled| settled.replace(2, b"new".to_vec(), ()),
            |_, ()| panic!("inconsistent validation must never promote"),
        )
        .expect_err("mutable validation call history");

        assert!(matches!(
            error,
            JournaledNamespaceError::ProtocolValidationInconsistent
        ));
        let state = external.0.borrow();
        assert_eq!(state.record.as_ref(), Some(&original));
        assert_eq!(state.seals, 1);
        assert!(state.mutation_bytes.is_empty());
        assert_eq!(local.state.borrow().writes, 0);
    }

    #[test]
    fn journal_valid_prepared_semantic_regression_never_recovers_or_promotes() {
        for local_image in [
            initialized(5, b"old"),
            initialized(7, b"regress-a"),
            AuthenticatedNamespaceState::NeverInitialized,
        ] {
            let binding = binding(RollbackProtectionClass::RemoteWitness);
            let events = Rc::new(RefCell::new(Vec::new()));
            let prepared = prepared_record(binding, 5, b"old", 7, b"regress-a");
            let external =
                FakeExternalControl::new(&binding, Some(prepared.clone()), Rc::clone(&events));
            let broker = FakeBroker {
                control: external.clone(),
            };
            let local = FakeLocalDriver::new(local_image, events);

            let error = run_with_driver(
                &local,
                &broker,
                &binding,
                &TestProtocol,
                |settled| settled.keep(()),
                |_, ()| panic!("invalid Prepared transition must never promote"),
            )
            .expect_err("Prepared semantic regression");

            assert!(matches!(
                error,
                JournaledNamespaceError::Protocol(ProtocolValidationError(
                    "test semantic regression"
                ))
            ));
            let state = external.0.borrow();
            assert_eq!(state.record.as_ref(), Some(&prepared));
            assert!(state.mutation_bytes.is_empty());
            assert_eq!(local.state.borrow().writes, 0);
        }
    }

    #[test]
    fn sealed_replacement_must_round_trip_open_before_prepared() {
        let binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let original = enrolled_stable(binding, 1, b"old");
        let external =
            FakeExternalControl::new(&binding, Some(original.clone()), Rc::clone(&events));
        external.push_open_attempt(Ok(None));
        external.push_open_attempt(Err(ExternalJournalError::OpenFailed));
        let broker = FakeBroker {
            control: external.clone(),
        };
        let local = FakeLocalDriver::new(initialized(1, b"old"), events);

        let error = run_with_driver(
            &local,
            &broker,
            &binding,
            &TestProtocol,
            |settled| settled.replace(2, b"new".to_vec(), ()),
            |_, ()| panic!("unopened replacement must never promote"),
        )
        .expect_err("round-trip open failure");

        assert!(matches!(
            error,
            JournaledNamespaceError::External(ExternalJournalError::OpenFailed)
        ));
        let state = external.0.borrow();
        assert_eq!(state.record.as_ref(), Some(&original));
        assert_eq!(state.seals, 1);
        assert!(state.mutation_bytes.is_empty());
        assert_eq!(local.state.borrow().writes, 0);
    }

    #[test]
    fn prepared_new_tamper_cannot_finalize_stable() {
        let binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let prepared = prepared_record(binding, 5, b"old", 7, b"new");
        let external =
            FakeExternalControl::new(&binding, Some(prepared.clone()), Rc::clone(&events));
        external.push_open_attempt(Ok(None));
        external.push_open_attempt(Ok(Some(b"bad".to_vec())));
        let broker = FakeBroker {
            control: external.clone(),
        };
        let local = FakeLocalDriver::new(initialized(7, b"new"), events);

        let error = run_with_driver(
            &local,
            &broker,
            &binding,
            &TestProtocol,
            |settled| settled.keep(()),
            |_, ()| panic!("tampered Prepared image must never promote"),
        )
        .expect_err("tampered Prepared new image");

        assert!(matches!(
            error,
            JournaledNamespaceError::SnapshotFingerprintMismatch
        ));
        let state = external.0.borrow();
        assert_eq!(state.record.as_ref(), Some(&prepared));
        assert!(state.mutation_bytes.is_empty());
        assert_eq!(local.state.borrow().writes, 0);
    }

    #[test]
    fn ambiguous_prepared_commit_reconciles_without_resealing_or_retry() {
        let binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let external = FakeExternalControl::new(
            &binding,
            Some(enrolled_stable(binding, 1, b"old")),
            Rc::clone(&events),
        );
        external.push_attempt(Ok(ExternalWrite::OutcomeUnknown), true);
        let broker = FakeBroker {
            control: external.clone(),
        };
        let local = FakeLocalDriver::new(initialized(1, b"old"), events);

        run_with_driver(
            &local,
            &broker,
            &binding,
            &TestProtocol,
            |settled| settled.replace(2, b"new".to_vec(), ()),
            |_, ()| (),
        )
        .expect("reconciled replacement");

        let state = external.0.borrow();
        assert_eq!(state.seals, 1);
        assert_eq!(
            state
                .mutation_bytes
                .iter()
                .filter(|bytes| JournalRecord::decode(bytes)
                    .is_ok_and(|record| matches!(record.state(), JournalState::Prepared { .. })))
                .count(),
            1
        );
    }

    #[test]
    fn ambiguous_prepared_retries_once_with_identical_bytes() {
        let binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let external = FakeExternalControl::new(
            &binding,
            Some(enrolled_stable(binding, 1, b"old")),
            Rc::clone(&events),
        );
        external.push_attempt(Ok(ExternalWrite::OutcomeUnknown), false);
        external.push_attempt(Ok(ExternalWrite::OutcomeUnknown), true);
        let broker = FakeBroker {
            control: external.clone(),
        };
        let local = FakeLocalDriver::new(initialized(1, b"old"), events);

        run_with_driver(
            &local,
            &broker,
            &binding,
            &TestProtocol,
            |settled| settled.replace(2, b"new".to_vec(), ()),
            |_, ()| (),
        )
        .expect("exact retry");

        let state = external.0.borrow();
        assert_eq!(state.seals, 1);
        assert!(state.mutation_bytes.len() >= 3);
        assert_eq!(state.mutation_bytes[0], state.mutation_bytes[1]);
    }

    #[test]
    fn external_error_and_ambiguous_stable_write_reconcile_exactly() {
        for first_outcome in [
            Err(ExternalJournalError::Backend("injected transport error")),
            Ok(ExternalWrite::OutcomeUnknown),
        ] {
            let binding = binding(RollbackProtectionClass::RemoteWitness);
            let events = Rc::new(RefCell::new(Vec::new()));
            let external = FakeExternalControl::new(
                &binding,
                Some(enrolled_stable(binding, 1, b"old")),
                Rc::clone(&events),
            );
            external.push_attempt(first_outcome, true);
            external.push_attempt(Ok(ExternalWrite::OutcomeUnknown), true);
            let broker = FakeBroker {
                control: external.clone(),
            };
            let local = FakeLocalDriver::new(initialized(1, b"old"), events);

            run_with_driver(
                &local,
                &broker,
                &binding,
                &TestProtocol,
                |settled| settled.replace(2, b"new".to_vec(), ()),
                |_, ()| (),
            )
            .expect("error and Stable ambiguity reconcile");

            assert_eq!(external.0.borrow().seals, 1);
            assert!(matches!(
                external.0.borrow().record.as_ref().expect("stable").state(),
                JournalState::Stable { .. }
            ));
        }
    }

    #[test]
    fn ambiguous_stable_retries_once_with_identical_bytes() {
        let binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let external = FakeExternalControl::new(
            &binding,
            Some(enrolled_stable(binding, 1, b"old")),
            Rc::clone(&events),
        );
        external.push_attempt(Ok(ExternalWrite::Durable), true);
        external.push_attempt(Ok(ExternalWrite::OutcomeUnknown), false);
        external.push_attempt(Ok(ExternalWrite::OutcomeUnknown), true);
        let broker = FakeBroker {
            control: external.clone(),
        };
        let local = FakeLocalDriver::new(initialized(1, b"old"), events);

        run_with_driver(
            &local,
            &broker,
            &binding,
            &TestProtocol,
            |settled| settled.replace(2, b"new".to_vec(), ()),
            |_, ()| (),
        )
        .expect("exact Stable retry");

        let state = external.0.borrow();
        assert_eq!(state.mutation_bytes.len(), 3);
        assert_eq!(state.mutation_bytes[1], state.mutation_bytes[2]);
        assert!(JournalRecord::decode(&state.mutation_bytes[1])
            .is_ok_and(|record| matches!(record.state(), JournalState::Stable { .. })));
    }

    #[test]
    fn unresolved_stable_retry_leaves_prepared_and_never_promotes() {
        let binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let external = FakeExternalControl::new(
            &binding,
            Some(enrolled_stable(binding, 1, b"old")),
            Rc::clone(&events),
        );
        external.push_attempt(Ok(ExternalWrite::Durable), true);
        external.push_attempt(Ok(ExternalWrite::OutcomeUnknown), false);
        external.push_attempt(Ok(ExternalWrite::OutcomeUnknown), false);
        let broker = FakeBroker {
            control: external.clone(),
        };
        let local = FakeLocalDriver::new(initialized(1, b"old"), events);

        let error = run_with_driver(
            &local,
            &broker,
            &binding,
            &TestProtocol,
            |settled| settled.replace(2, b"new".to_vec(), ()),
            |_, ()| panic!("unresolved Stable outcome must never promote"),
        )
        .expect_err("unresolved Stable outcome");

        assert!(matches!(
            error,
            JournaledNamespaceError::ExternalOutcomeUnresolved
        ));
        assert_eq!(local.state.borrow().image, initialized(2, b"new"));
        let state = external.0.borrow();
        assert!(matches!(
            state.record.as_ref().expect("Prepared retained").state(),
            JournalState::Prepared { .. }
        ));
        assert_eq!(state.mutation_bytes.len(), 3);
        assert_eq!(state.mutation_bytes[1], state.mutation_bytes[2]);
    }

    #[test]
    fn definite_stable_conflict_never_retries_or_promotes() {
        let binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let external = FakeExternalControl::new(
            &binding,
            Some(enrolled_stable(binding, 1, b"old")),
            Rc::clone(&events),
        );
        external.push_attempt(Ok(ExternalWrite::Durable), true);
        external.push_attempt(Ok(ExternalWrite::Conflict), false);
        let broker = FakeBroker {
            control: external.clone(),
        };
        let local = FakeLocalDriver::new(initialized(1, b"old"), events);

        let error = run_with_driver(
            &local,
            &broker,
            &binding,
            &TestProtocol,
            |settled| settled.replace(2, b"new".to_vec(), ()),
            |_, ()| panic!("definite Stable conflict must never promote"),
        )
        .expect_err("definite Stable conflict");

        assert!(matches!(error, JournaledNamespaceError::ExternalConflict));
        assert_eq!(local.state.borrow().image, initialized(2, b"new"));
        let state = external.0.borrow();
        assert!(matches!(
            state.record.as_ref().expect("Prepared retained").state(),
            JournalState::Prepared { .. }
        ));
        assert_eq!(state.mutation_bytes.len(), 2);
    }

    #[test]
    fn durable_claim_requires_exact_authenticated_reread() {
        let binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let external = FakeExternalControl::new(
            &binding,
            Some(enrolled_stable(binding, 1, b"old")),
            Rc::clone(&events),
        );
        external.push_attempt(Ok(ExternalWrite::Durable), false);
        let broker = FakeBroker {
            control: external.clone(),
        };
        let local = FakeLocalDriver::new(initialized(1, b"old"), events);

        let error = run_with_driver(
            &local,
            &broker,
            &binding,
            &TestProtocol,
            |settled| settled.replace(2, b"new".to_vec(), ()),
            |_, ()| panic!("false durable claim must not promote"),
        )
        .expect_err("durable reread mismatch");
        assert!(matches!(
            error,
            JournaledNamespaceError::ExternalRereadMismatch
        ));
        assert_eq!(local.state.borrow().writes, 0);
    }

    #[test]
    fn ambiguous_retry_never_attempts_a_third_write() {
        let binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let external = FakeExternalControl::new(
            &binding,
            Some(enrolled_stable(binding, 1, b"old")),
            Rc::clone(&events),
        );
        external.push_attempt(Ok(ExternalWrite::OutcomeUnknown), false);
        external.push_attempt(Ok(ExternalWrite::OutcomeUnknown), false);
        let broker = FakeBroker {
            control: external.clone(),
        };
        let local = FakeLocalDriver::new(initialized(1, b"old"), events);

        let error = run_with_driver(
            &local,
            &broker,
            &binding,
            &TestProtocol,
            |settled| settled.replace(2, b"new".to_vec(), ()),
            |_, ()| (),
        )
        .expect_err("unresolved retry");

        assert!(matches!(
            error,
            JournaledNamespaceError::ExternalOutcomeUnresolved
        ));
        let state = external.0.borrow();
        assert_eq!(state.seals, 1);
        assert_eq!(state.mutation_bytes.len(), 2);
        assert_eq!(state.mutation_bytes[0], state.mutation_bytes[1]);
    }

    #[test]
    fn definite_external_conflict_never_retries_exact_old_state() {
        let binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let external = FakeExternalControl::new(
            &binding,
            Some(enrolled_stable(binding, 1, b"old")),
            Rc::clone(&events),
        );
        external.push_attempt(Ok(ExternalWrite::Conflict), false);
        let broker = FakeBroker {
            control: external.clone(),
        };
        let local = FakeLocalDriver::new(initialized(1, b"old"), events);

        let error = run_with_driver(
            &local,
            &broker,
            &binding,
            &TestProtocol,
            |settled| settled.replace(2, b"new".to_vec(), ()),
            |_, ()| (),
        )
        .expect_err("definite conflict");

        assert!(matches!(error, JournaledNamespaceError::ExternalConflict));
        assert_eq!(external.0.borrow().mutation_bytes.len(), 1);
        assert_eq!(local.state.borrow().writes, 0);
    }

    #[test]
    fn local_ambiguous_error_requires_reopen_and_leaves_prepared() {
        for apply in [true, false] {
            let binding = binding(RollbackProtectionClass::IndependentLocalRoot);
            let events = Rc::new(RefCell::new(Vec::new()));
            let external = FakeExternalControl::new(
                &binding,
                Some(enrolled_stable(binding, 1, b"old")),
                Rc::clone(&events),
            );
            let broker = FakeBroker {
                control: external.clone(),
            };
            let local = FakeLocalDriver::new(initialized(1, b"old"), events);
            local.push_behavior(LocalBehavior::Error {
                apply,
                reopen: true,
            });

            let error = run_with_driver(
                &local,
                &broker,
                &binding,
                &TestProtocol,
                |settled| settled.replace(2, b"new".to_vec(), ()),
                |_, ()| panic!("ambiguous local publication must never promote"),
            )
            .expect_err("reopen fence");

            assert!(matches!(
                error,
                JournaledNamespaceError::LocalReopenRequired
            ));
            assert_eq!(
                local.state.borrow().image,
                if apply {
                    initialized(2, b"new")
                } else {
                    initialized(1, b"old")
                }
            );
            assert!(matches!(
                external
                    .0
                    .borrow()
                    .record
                    .as_ref()
                    .expect("prepared")
                    .state(),
                JournalState::Prepared { .. }
            ));
            assert_eq!(external.0.borrow().seals, 1);
        }
    }

    #[test]
    fn preexisting_reopen_fence_prevents_state_access() {
        let binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let original = enrolled_stable(binding, 1, b"old");
        let external =
            FakeExternalControl::new(&binding, Some(original.clone()), Rc::clone(&events));
        let broker = FakeBroker {
            control: external.clone(),
        };
        let local = FakeLocalDriver::new(initialized(1, b"old"), Rc::clone(&events));
        local.state.borrow_mut().reopen_required = true;

        let error = run_with_driver(
            &local,
            &broker,
            &binding,
            &TestProtocol,
            |settled| settled.keep(()),
            |_, ()| panic!("preexisting reopen fence must prevent use"),
        )
        .expect_err("preexisting reopen fence");

        assert!(matches!(
            error,
            JournaledNamespaceError::LocalReopenRequired
        ));
        assert_eq!(local.state.borrow().loads, 0);
        assert_eq!(local.state.borrow().writes, 0);
        assert_eq!(external.0.borrow().record.as_ref(), Some(&original));
        assert_eq!(
            &events.borrow()[events.borrow().len() - 2..],
            ["local_drop", "external_drop"]
        );
    }

    #[test]
    fn ordinary_local_error_leaves_prepared_and_drops_local_first() {
        let binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let external = FakeExternalControl::new(
            &binding,
            Some(enrolled_stable(binding, 1, b"old")),
            Rc::clone(&events),
        );
        let broker = FakeBroker {
            control: external.clone(),
        };
        let local = FakeLocalDriver::new(initialized(1, b"old"), Rc::clone(&events));
        local.push_behavior(LocalBehavior::Error {
            apply: false,
            reopen: false,
        });

        let error = run_with_driver(
            &local,
            &broker,
            &binding,
            &TestProtocol,
            |settled| settled.replace(2, b"new".to_vec(), ()),
            |_, ()| panic!("ordinary local error must never promote"),
        )
        .expect_err("ordinary local error");

        assert!(matches!(
            error,
            JournaledNamespaceError::Local(AuthenticatedNamespaceError::Store(
                StoreError::Backend(_)
            ))
        ));
        assert_eq!(local.state.borrow().image, initialized(1, b"old"));
        assert!(matches!(
            external
                .0
                .borrow()
                .record
                .as_ref()
                .expect("Prepared retained")
                .state(),
            JournalState::Prepared { .. }
        ));
        assert_eq!(
            &events.borrow()[events.borrow().len() - 2..],
            ["local_drop", "external_drop"]
        );
    }

    #[test]
    fn local_committed_wrong_reread_leaves_prepared_and_never_promotes() {
        let binding = binding(RollbackProtectionClass::IndependentLocalRoot);
        let events = Rc::new(RefCell::new(Vec::new()));
        let external = FakeExternalControl::new(
            &binding,
            Some(enrolled_stable(binding, 1, b"old")),
            Rc::clone(&events),
        );
        let broker = FakeBroker {
            control: external.clone(),
        };
        let local = FakeLocalDriver::new(initialized(1, b"old"), events);
        local.push_behavior(LocalBehavior::CommitWrongReread);

        let error = run_with_driver(
            &local,
            &broker,
            &binding,
            &TestProtocol,
            |settled| settled.replace(2, b"new".to_vec(), ()),
            |_, ()| panic!("wrong reread must not promote"),
        )
        .expect_err("wrong mandatory reread");
        assert!(matches!(
            error,
            JournaledNamespaceError::LocalRereadMismatch
        ));
        assert!(matches!(
            external
                .0
                .borrow()
                .record
                .as_ref()
                .expect("prepared")
                .state(),
            JournalState::Prepared { .. }
        ));
    }

    #[test]
    fn already_committed_local_write_still_has_mandatory_reread() {
        let binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let external = FakeExternalControl::new(
            &binding,
            Some(enrolled_stable(binding, 1, b"old")),
            Rc::clone(&events),
        );
        let broker = FakeBroker { control: external };
        let local = FakeLocalDriver::new(initialized(1, b"old"), events);
        local.push_behavior(LocalBehavior::AlreadyCommitted);
        let loads_before = local.state.borrow().loads;

        run_with_driver(
            &local,
            &broker,
            &binding,
            &TestProtocol,
            |settled| settled.replace(2, b"new".to_vec(), ()),
            |_, ()| (),
        )
        .expect("already committed");

        assert!(local.state.borrow().loads >= loads_before + 4);
    }

    #[test]
    fn stable_absent_and_older_local_images_restore_before_use() {
        for local_image in [
            AuthenticatedNamespaceState::NeverInitialized,
            initialized(3, b"older"),
        ] {
            let binding = binding(RollbackProtectionClass::RemoteWitness);
            let events = Rc::new(RefCell::new(Vec::new()));
            let external = FakeExternalControl::new(
                &binding,
                Some(enrolled_stable(binding, 7, b"current")),
                Rc::clone(&events),
            );
            let broker = FakeBroker { control: external };
            let local = FakeLocalDriver::new(local_image, events);

            let evidence = run_with_driver(
                &local,
                &broker,
                &binding,
                &TestProtocol,
                |settled| settled.keep(()),
                |settled, ()| settled.revision(),
            )
            .expect("restored stable");

            assert_eq!(*evidence.value(), 7);
            assert_eq!(local.state.borrow().image, initialized(7, b"current"));
            assert_eq!(local.state.borrow().writes, 1);
        }
    }

    #[test]
    fn prepared_old_new_and_absent_recover_to_stable_new() {
        for (local_image, expected_writes) in [
            (initialized(5, b"old"), 1),
            (initialized(7, b"new"), 0),
            (AuthenticatedNamespaceState::NeverInitialized, 2),
            (initialized(3, b"older"), 2),
        ] {
            let binding = binding(RollbackProtectionClass::RemoteWitness);
            let events = Rc::new(RefCell::new(Vec::new()));
            let external = FakeExternalControl::new(
                &binding,
                Some(prepared_record(binding, 5, b"old", 7, b"new")),
                Rc::clone(&events),
            );
            let broker = FakeBroker {
                control: external.clone(),
            };
            let local = FakeLocalDriver::new(local_image, events);

            let evidence = run_with_driver(
                &local,
                &broker,
                &binding,
                &TestProtocol,
                |settled| settled.keep(()),
                |settled, ()| settled.revision(),
            )
            .expect("recover prepared");

            assert_eq!(*evidence.value(), 7);
            assert_eq!(local.state.borrow().image, initialized(7, b"new"));
            assert_eq!(local.state.borrow().writes, expected_writes);
            assert!(matches!(
                external.0.borrow().record.as_ref().expect("stable").state(),
                JournalState::Stable { .. }
            ));
        }
    }

    #[test]
    fn prepared_finalize_stable_outcomes_never_promote_ambiguity_or_conflict() {
        for case in ["retry", "unresolved", "conflict"] {
            let binding = binding(RollbackProtectionClass::RemoteWitness);
            let events = Rc::new(RefCell::new(Vec::new()));
            let prepared = prepared_record(binding, 5, b"old", 7, b"new");
            let external =
                FakeExternalControl::new(&binding, Some(prepared.clone()), Rc::clone(&events));
            match case {
                "retry" => {
                    external.push_attempt(Ok(ExternalWrite::OutcomeUnknown), false);
                    external.push_attempt(Ok(ExternalWrite::OutcomeUnknown), true);
                }
                "unresolved" => {
                    external.push_attempt(Ok(ExternalWrite::OutcomeUnknown), false);
                    external.push_attempt(Ok(ExternalWrite::OutcomeUnknown), false);
                }
                "conflict" => {
                    external.push_attempt(Ok(ExternalWrite::Conflict), false);
                }
                _ => unreachable!(),
            }
            let broker = FakeBroker {
                control: external.clone(),
            };
            let local = FakeLocalDriver::new(initialized(7, b"new"), events);

            let result = run_with_driver(
                &local,
                &broker,
                &binding,
                &TestProtocol,
                |settled| settled.keep(()),
                |settled, ()| {
                    assert_eq!(case, "retry", "failed recovery must not promote use");
                    settled.revision()
                },
            );

            let state = external.0.borrow();
            match case {
                "retry" => {
                    let evidence = result.expect("exact Stable recovery retry");
                    assert_eq!(*evidence.value(), 7);
                    assert!(matches!(
                        state.record.as_ref().expect("Stable installed").state(),
                        JournalState::Stable { .. }
                    ));
                    assert_eq!(state.mutation_bytes.len(), 2);
                    assert_eq!(state.mutation_bytes[0], state.mutation_bytes[1]);
                }
                "unresolved" => {
                    assert!(matches!(
                        result.expect_err("unresolved Stable recovery"),
                        JournaledNamespaceError::ExternalOutcomeUnresolved
                    ));
                    assert_eq!(state.record.as_ref(), Some(&prepared));
                    assert_eq!(state.mutation_bytes.len(), 2);
                    assert_eq!(state.mutation_bytes[0], state.mutation_bytes[1]);
                }
                "conflict" => {
                    assert!(matches!(
                        result.expect_err("definite Stable recovery conflict"),
                        JournaledNamespaceError::ExternalConflict
                    ));
                    assert_eq!(state.record.as_ref(), Some(&prepared));
                    assert_eq!(state.mutation_bytes.len(), 1);
                }
                _ => unreachable!(),
            }
            assert_eq!(local.state.borrow().writes, 0);
        }
    }

    #[test]
    fn missing_unenrolled_forks_ahead_and_intermediate_fail_closed() {
        let cases = [
            (
                None,
                initialized(1, b"state"),
                FailClosedReason::MissingJournalRecord,
            ),
            (
                Some(
                    privileged_provision(
                        binding(RollbackProtectionClass::RemoteWitness),
                        JournalLeaseContext::new(
                            &binding(RollbackProtectionClass::RemoteWitness),
                            token(EXTERNAL_TOKEN),
                        ),
                    )
                    .expect("marker")
                    .into_proposed(),
                ),
                initialized(1, b"state"),
                FailClosedReason::NotEnrolled,
            ),
            (
                Some(enrolled_stable(
                    binding(RollbackProtectionClass::RemoteWitness),
                    5,
                    b"old",
                )),
                initialized(5, b"fork"),
                FailClosedReason::SameRevisionFork,
            ),
            (
                Some(enrolled_stable(
                    binding(RollbackProtectionClass::RemoteWitness),
                    5,
                    b"old",
                )),
                initialized(6, b"ahead"),
                FailClosedReason::DatabaseAhead,
            ),
            (
                Some(prepared_record(
                    binding(RollbackProtectionClass::RemoteWitness),
                    5,
                    b"old",
                    7,
                    b"new",
                )),
                initialized(6, b"middle"),
                FailClosedReason::UnexpectedIntermediateState,
            ),
            (
                Some(prepared_record(
                    binding(RollbackProtectionClass::RemoteWitness),
                    5,
                    b"old",
                    7,
                    b"new",
                )),
                initialized(5, b"old-fork"),
                FailClosedReason::SameRevisionFork,
            ),
            (
                Some(prepared_record(
                    binding(RollbackProtectionClass::RemoteWitness),
                    5,
                    b"old",
                    7,
                    b"new",
                )),
                initialized(7, b"new-fork"),
                FailClosedReason::SameRevisionFork,
            ),
            (
                Some(prepared_record(
                    binding(RollbackProtectionClass::RemoteWitness),
                    5,
                    b"old",
                    7,
                    b"new",
                )),
                initialized(8, b"ahead"),
                FailClosedReason::DatabaseAhead,
            ),
        ];

        for (record, local_image, reason) in cases {
            let binding = binding(RollbackProtectionClass::RemoteWitness);
            let events = Rc::new(RefCell::new(Vec::new()));
            let external = FakeExternalControl::new(&binding, record, Rc::clone(&events));
            let broker = FakeBroker { control: external };
            let local = FakeLocalDriver::new(local_image, events);
            let error = run_with_driver(
                &local,
                &broker,
                &binding,
                &TestProtocol,
                |settled| settled.keep(()),
                |_, ()| (),
            )
            .expect_err("fail closed case");
            assert!(matches!(
                error,
                JournaledNamespaceError::FailClosed(actual) if actual == reason
            ));
        }
    }

    #[test]
    fn retired_and_misbound_records_fail_closed() {
        let expected = binding(RollbackProtectionClass::RemoteWitness);
        let stable = enrolled_stable(expected, 5, b"old");
        let observation = DatabaseObservation::from_plaintext(5, PROTOCOL_FINGERPRINT, b"old")
            .expect("observation");
        let retired = stable
            .privileged_retire(
                JournalLeaseContext::new(&expected, token(EXTERNAL_TOKEN)),
                observation,
            )
            .expect("retire")
            .into_proposed();

        let other_parts = JournalBindingParts {
            installation_lineage: [1; 32],
            network_magic: 0xfeed_beef,
            role_id: [2; 32],
            storage_namespace_id: [3; 32],
            logical_key: [9; 32],
            protocol_id: [5; 32],
            protocol_version: 1,
            aead_suite: 1,
            key_version: 1,
            key_id: [6; 32],
            protection: RollbackProtectionClass::RemoteWitness,
        };
        let other = JournalBinding::new(other_parts).expect("other binding");
        let misbound = enrolled_stable(other, 5, b"old");

        for (record, reason) in [
            (retired, FailClosedReason::Retired),
            (misbound, FailClosedReason::BindingMismatch),
        ] {
            let events = Rc::new(RefCell::new(Vec::new()));
            let external = FakeExternalControl::new(&expected, Some(record), Rc::clone(&events));
            let broker = FakeBroker { control: external };
            let local = FakeLocalDriver::new(initialized(5, b"old"), events);
            let error = run_with_driver(
                &local,
                &broker,
                &expected,
                &TestProtocol,
                |settled| settled.keep(()),
                |_, ()| (),
            )
            .expect_err("terminal record");
            assert!(matches!(
                error,
                JournaledNamespaceError::FailClosed(actual) if actual == reason
            ));
        }
    }

    #[test]
    fn proposal_bounds_and_fencing_change_fail_before_prepared() {
        let oversized = vec![0_u8; MAX_PLAINTEXT_SNAPSHOT_SIZE + 1];
        assert!(matches!(
            validate_bounds(&oversized),
            Err(JournaledNamespaceError::SnapshotTooLarge { .. })
        ));

        let oversized_binding = binding(RollbackProtectionClass::RemoteWitness);
        let oversized_events = Rc::new(RefCell::new(Vec::new()));
        let oversized_external = FakeExternalControl::new(
            &oversized_binding,
            Some(enrolled_stable(oversized_binding, 1, b"old")),
            Rc::clone(&oversized_events),
        );
        let oversized_broker = FakeBroker {
            control: oversized_external.clone(),
        };
        let oversized_local = FakeLocalDriver::new(initialized(1, b"old"), oversized_events);
        let error = run_with_driver(
            &oversized_local,
            &oversized_broker,
            &oversized_binding,
            &TestProtocol,
            |settled| settled.replace(2, oversized, ()),
            |_, ()| panic!("oversized proposal must never promote"),
        )
        .expect_err("oversized proposal through coordinator");
        assert!(matches!(
            error,
            JournaledNamespaceError::SnapshotTooLarge { .. }
        ));
        assert_eq!(oversized_external.0.borrow().seals, 0);
        assert!(oversized_external.0.borrow().mutation_bytes.is_empty());
        assert_eq!(oversized_local.state.borrow().writes, 0);

        let binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let external = FakeExternalControl::new(
            &binding,
            Some(enrolled_stable(binding, 1, b"old")),
            Rc::clone(&events),
        );
        let broker = FakeBroker {
            control: external.clone(),
        };
        let local = FakeLocalDriver::new(initialized(1, b"old"), events);
        let changed = external.clone();
        let error = run_with_driver(
            &local,
            &broker,
            &binding,
            &TestProtocol,
            move |settled| {
                changed.0.borrow_mut().fencing_token = token(EXTERNAL_TOKEN + 1);
                settled.replace(2, b"new".to_vec(), ())
            },
            |_, ()| panic!("changed fence must not promote"),
        )
        .expect_err("changed fencing token");
        assert!(matches!(
            error,
            JournaledNamespaceError::ExternalFencingMismatch
        ));
        let state = external.0.borrow();
        assert_eq!(state.seals, 0);
        assert!(state.mutation_bytes.is_empty());
    }

    #[test]
    fn invalid_open_and_invalid_proposals_never_promote() {
        let tampered_binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let external = FakeExternalControl::new(
            &tampered_binding,
            Some(enrolled_stable(tampered_binding, 1, b"old")),
            Rc::clone(&events),
        );
        external.0.borrow_mut().open_override = Some(b"tampered".to_vec());
        let broker = FakeBroker { control: external };
        let local = FakeLocalDriver::new(initialized(1, b"old"), events);
        let error = run_with_driver(
            &local,
            &broker,
            &tampered_binding,
            &TestProtocol,
            |settled| settled.keep(()),
            |_, ()| panic!("must not promote"),
        )
        .expect_err("tampered open");
        assert!(matches!(
            error,
            JournaledNamespaceError::SnapshotFingerprintMismatch
        ));

        for (revision, proposal) in [
            (1, b"new".to_vec()),
            (2, Vec::new()),
            (2, b"invalid".to_vec()),
        ] {
            let binding = binding(RollbackProtectionClass::RemoteWitness);
            let events = Rc::new(RefCell::new(Vec::new()));
            let external = FakeExternalControl::new(
                &binding,
                Some(enrolled_stable(binding, 1, b"old")),
                Rc::clone(&events),
            );
            let broker = FakeBroker { control: external };
            let local = FakeLocalDriver::new(initialized(1, b"old"), events);
            let result = run_with_driver(
                &local,
                &broker,
                &binding,
                &TestProtocol,
                |settled| settled.replace(revision, proposal, ()),
                |_, ()| panic!("invalid proposal must not promote"),
            );
            assert!(result.is_err());
        }
    }

    #[test]
    fn authenticated_load_open_and_seal_errors_fail_before_promotion() {
        for fault in ["load", "open", "seal"] {
            let binding = binding(RollbackProtectionClass::RemoteWitness);
            let events = Rc::new(RefCell::new(Vec::new()));
            let original = enrolled_stable(binding, 1, b"old");
            let external =
                FakeExternalControl::new(&binding, Some(original.clone()), Rc::clone(&events));
            match fault {
                "load" => external
                    .0
                    .borrow_mut()
                    .load_attempts
                    .push_back(Err(ExternalJournalError::AuthenticatedLoadFailed)),
                "open" => external.push_open_attempt(Err(ExternalJournalError::OpenFailed)),
                "seal" => external
                    .0
                    .borrow_mut()
                    .seal_attempts
                    .push_back(Err(ExternalJournalError::SealFailed)),
                _ => unreachable!(),
            }
            let broker = FakeBroker {
                control: external.clone(),
            };
            let local = FakeLocalDriver::new(initialized(1, b"old"), Rc::clone(&events));

            let error = run_with_driver(
                &local,
                &broker,
                &binding,
                &TestProtocol,
                |settled| {
                    if fault == "seal" {
                        settled.replace(2, b"new".to_vec(), ())
                    } else {
                        settled.keep(())
                    }
                },
                |_, ()| panic!("external boundary error must never promote"),
            )
            .expect_err("external boundary error");

            assert!(matches!(
                (fault, error),
                (
                    "load",
                    JournaledNamespaceError::External(
                        ExternalJournalError::AuthenticatedLoadFailed
                    )
                ) | (
                    "open",
                    JournaledNamespaceError::External(ExternalJournalError::OpenFailed)
                ) | (
                    "seal",
                    JournaledNamespaceError::External(ExternalJournalError::SealFailed)
                )
            ));
            let state = external.0.borrow();
            assert_eq!(state.record.as_ref(), Some(&original));
            assert!(state.mutation_bytes.is_empty());
            assert_eq!(local.state.borrow().writes, 0);
            assert_eq!(
                &events.borrow()[events.borrow().len() - 2..],
                ["local_drop", "external_drop"]
            );
        }
    }

    #[test]
    fn lease_loss_during_dependent_use_discards_the_result() {
        let binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let external = FakeExternalControl::new(
            &binding,
            Some(enrolled_stable(binding, 1, b"old")),
            Rc::clone(&events),
        );
        let broker = FakeBroker {
            control: external.clone(),
        };
        let local = FakeLocalDriver::new(initialized(1, b"old"), events);
        let control = external.clone();
        let error = run_with_driver(
            &local,
            &broker,
            &binding,
            &TestProtocol,
            |settled| settled.keep(()),
            move |settled, ()| {
                control.0.borrow_mut().held = false;
                assert!(settled.ensure_current().is_err());
                "unpromoted"
            },
        )
        .expect_err("lost external lease");
        assert!(matches!(
            error,
            JournaledNamespaceError::External(ExternalJournalError::LeaseLost)
        ));
    }

    #[test]
    fn either_lease_loss_before_prepared_prevents_every_write() {
        for lose_external in [true, false] {
            let binding = binding(RollbackProtectionClass::RemoteWitness);
            let events = Rc::new(RefCell::new(Vec::new()));
            let original = enrolled_stable(binding, 1, b"old");
            let external =
                FakeExternalControl::new(&binding, Some(original.clone()), Rc::clone(&events));
            let broker = FakeBroker {
                control: external.clone(),
            };
            let local = FakeLocalDriver::new(initialized(1, b"old"), events);
            let external_control = external.clone();
            let local_control = local.clone();

            let error = run_with_driver(
                &local,
                &broker,
                &binding,
                &TestProtocol,
                move |settled| {
                    if lose_external {
                        external_control.0.borrow_mut().held = false;
                    } else {
                        local_control.state.borrow_mut().held = false;
                    }
                    settled.replace(2, b"new".to_vec(), ())
                },
                |_, ()| panic!("lost pre-Prepared lease must never promote"),
            )
            .expect_err("pre-Prepared lease loss");

            if lose_external {
                assert!(matches!(
                    error,
                    JournaledNamespaceError::External(ExternalJournalError::LeaseLost)
                ));
            } else {
                assert!(matches!(
                    error,
                    JournaledNamespaceError::Local(AuthenticatedNamespaceError::LeaseLost)
                ));
            }
            let state = external.0.borrow();
            assert_eq!(state.record.as_ref(), Some(&original));
            assert_eq!(state.seals, 0);
            assert!(state.mutation_bytes.is_empty());
            assert_eq!(local.state.borrow().writes, 0);
        }
    }

    #[test]
    fn either_lease_loss_after_prepared_prevents_local_publication() {
        for lose_external in [true, false] {
            let binding = binding(RollbackProtectionClass::RemoteWitness);
            let events = Rc::new(RefCell::new(Vec::new()));
            let external = FakeExternalControl::new(
                &binding,
                Some(enrolled_stable(binding, 1, b"old")),
                Rc::clone(&events),
            );
            if lose_external {
                external.0.borrow_mut().lose_after_event = Some("external_write_prepared");
            }
            let broker = FakeBroker {
                control: external.clone(),
            };
            let local = FakeLocalDriver::new(initialized(1, b"old"), events);
            if !lose_external {
                local.state.borrow_mut().lose_on_event = Some("local_cas");
            }

            let error = run_with_driver(
                &local,
                &broker,
                &binding,
                &TestProtocol,
                |settled| settled.replace(2, b"new".to_vec(), ()),
                |_, ()| panic!("lost pre-local-CAS lease must never promote"),
            )
            .expect_err("lease loss after Prepared");

            if lose_external {
                assert!(matches!(
                    error,
                    JournaledNamespaceError::External(ExternalJournalError::LeaseLost)
                ));
            } else {
                assert!(matches!(
                    error,
                    JournaledNamespaceError::Local(AuthenticatedNamespaceError::LeaseLost)
                ));
            }
            assert_eq!(local.state.borrow().image, initialized(1, b"old"));
            assert_eq!(local.state.borrow().writes, 0);
            assert!(matches!(
                external
                    .0
                    .borrow()
                    .record
                    .as_ref()
                    .expect("Prepared retained")
                    .state(),
                JournalState::Prepared { .. }
            ));
        }
    }

    #[test]
    fn either_lease_loss_after_local_commit_prevents_stable_promotion() {
        for lose_external in [true, false] {
            let binding = binding(RollbackProtectionClass::RemoteWitness);
            let events = Rc::new(RefCell::new(Vec::new()));
            let external = FakeExternalControl::new(
                &binding,
                Some(enrolled_stable(binding, 1, b"old")),
                Rc::clone(&events),
            );
            if lose_external {
                external.0.borrow_mut().lose_on_event = Some("external_write_stable");
            }
            let broker = FakeBroker {
                control: external.clone(),
            };
            let local = FakeLocalDriver::new(initialized(1, b"old"), events);
            if !lose_external {
                local.state.borrow_mut().lose_after_event = Some("local_cas");
            }

            let error = run_with_driver(
                &local,
                &broker,
                &binding,
                &TestProtocol,
                |settled| settled.replace(2, b"new".to_vec(), ()),
                |_, ()| panic!("lost pre-Stable lease must never promote"),
            )
            .expect_err("lease loss after local commit");

            if lose_external {
                assert!(matches!(
                    error,
                    JournaledNamespaceError::External(ExternalJournalError::LeaseLost)
                ));
            } else {
                assert!(matches!(
                    error,
                    JournaledNamespaceError::Local(AuthenticatedNamespaceError::LeaseLost)
                ));
            }
            assert_eq!(local.state.borrow().image, initialized(2, b"new"));
            assert!(matches!(
                external
                    .0
                    .borrow()
                    .record
                    .as_ref()
                    .expect("Prepared retained")
                    .state(),
                JournalState::Prepared { .. }
            ));
        }
    }

    #[test]
    fn lease_loss_after_durable_stable_suppresses_dependent_use() {
        let binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let external = FakeExternalControl::new(
            &binding,
            Some(enrolled_stable(binding, 1, b"old")),
            Rc::clone(&events),
        );
        external.0.borrow_mut().lose_after_event = Some("external_write_stable");
        let broker = FakeBroker {
            control: external.clone(),
        };
        let local = FakeLocalDriver::new(initialized(1, b"old"), events);

        let error = run_with_driver(
            &local,
            &broker,
            &binding,
            &TestProtocol,
            |settled| settled.replace(2, b"new".to_vec(), ()),
            |_, ()| panic!("lost post-Stable lease must never permit dependent use"),
        )
        .expect_err("lease loss after durable Stable");

        assert!(matches!(
            error,
            JournaledNamespaceError::External(ExternalJournalError::LeaseLost)
        ));
        assert_eq!(local.state.borrow().image, initialized(2, b"new"));
        let state = external.0.borrow();
        assert!(matches!(
            state.record.as_ref().expect("Stable retained").state(),
            JournalState::Stable { .. }
        ));
        assert_eq!(state.mutation_bytes.len(), 2);
        assert!(JournalRecord::decode(&state.mutation_bytes[0])
            .is_ok_and(|record| matches!(record.state(), JournalState::Prepared { .. })));
        assert!(JournalRecord::decode(&state.mutation_bytes[1])
            .is_ok_and(|record| matches!(record.state(), JournalState::Stable { .. })));
    }

    #[test]
    fn local_lease_loss_during_dependent_use_discards_the_result() {
        let binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let external = FakeExternalControl::new(
            &binding,
            Some(enrolled_stable(binding, 1, b"old")),
            Rc::clone(&events),
        );
        let broker = FakeBroker { control: external };
        let local = FakeLocalDriver::new(initialized(1, b"old"), events);
        let control = local.clone();
        let error = run_with_driver(
            &local,
            &broker,
            &binding,
            &TestProtocol,
            |settled| settled.keep(()),
            move |settled, ()| {
                control.state.borrow_mut().held = false;
                assert!(settled.ensure_current().is_err());
                "unpromoted"
            },
        )
        .expect_err("lost local lease");
        assert!(matches!(
            error,
            JournaledNamespaceError::Local(AuthenticatedNamespaceError::LeaseLost)
        ));
    }

    #[test]
    fn panic_and_nested_run_preserve_drop_and_non_nesting_invariants() {
        let binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let external = FakeExternalControl::new(
            &binding,
            Some(enrolled_stable(binding, 1, b"old")),
            Rc::clone(&events),
        );
        let broker = FakeBroker { control: external };
        let local = FakeLocalDriver::new(initialized(1, b"old"), Rc::clone(&events));
        let panic = catch_unwind(AssertUnwindSafe(|| {
            let _ = run_with_driver(
                &local,
                &broker,
                &binding,
                &TestProtocol,
                |settled| settled.keep(()),
                |_, ()| panic!("injected use panic"),
            );
        }));
        assert!(panic.is_err());
        assert_eq!(
            &events.borrow()[events.borrow().len() - 2..],
            ["local_drop", "external_drop"]
        );

        let outer = RunSentinel::enter().expect("outer run");
        assert!(matches!(
            RunSentinel::enter(),
            Err(JournaledNamespaceError::NestedRun)
        ));
        drop(outer);
        RunSentinel::enter().expect("sentinel reset after drop");
    }

    #[test]
    fn production_entry_rejects_volatile_memory_store() {
        let binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let external =
            FakeExternalControl::new(&binding, Some(enrolled_stable(binding, 1, b"old")), events);
        let broker = FakeBroker { control: external };
        let coordinator = JournaledNamespace::new(StoreHandle::Memory(MemoryStore::new()));
        let error = coordinator
            .run_scoped(
                &broker,
                &binding,
                &TestProtocol,
                |settled| settled.keep(()),
                |_, ()| (),
            )
            .expect_err("memory store is volatile");
        assert!(matches!(
            error,
            JournaledNamespaceError::VolatileLocalBackend
        ));
    }

    #[test]
    fn production_boundary_requires_independence_and_live_broker_qualification() {
        let weak_binding = binding(RollbackProtectionClass::IntegrityOnlySameRollbackDomain);
        let weak_events = Rc::new(RefCell::new(Vec::new()));
        let weak_external = FakeExternalControl::new(&weak_binding, None, Rc::clone(&weak_events));
        let weak_broker = FakeBroker {
            control: weak_external,
        };
        let error = ensure_production_boundary(true, &weak_broker, &weak_binding)
            .expect_err("same-domain journal is not production anti-rollback");
        assert!(matches!(
            error,
            JournaledNamespaceError::UnqualifiedRollbackDomain
        ));
        assert!(weak_events.borrow().is_empty());

        let binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let external = FakeExternalControl::new(&binding, None, Rc::clone(&events));
        external.0.borrow_mut().qualification_error = Some(ExternalJournalError::Backend(
            "injected qualification failure",
        ));
        let broker = FakeBroker { control: external };
        let error = ensure_production_boundary(true, &broker, &binding)
            .expect_err("broker must attest its actual deployment");
        assert!(matches!(
            error,
            JournaledNamespaceError::External(ExternalJournalError::Backend(
                "injected qualification failure"
            ))
        ));
        assert_eq!(events.borrow().as_slice(), ["external_qualified"]);

        let error = ensure_production_boundary(false, &broker, &binding)
            .expect_err("volatile local backend");
        assert!(matches!(
            error,
            JournaledNamespaceError::VolatileLocalBackend
        ));
        assert_eq!(events.borrow().as_slice(), ["external_qualified"]);
    }

    #[test]
    fn crate_manifest_remains_inert_and_pins_the_exact_journal_source() {
        let manifest = include_str!("../Cargo.toml");
        let workspace = include_str!("../../../Cargo.toml");
        assert!(manifest.contains("hns-rollback-journal.workspace = true"));
        assert!(
            manifest.contains("hns-store = { path = \"../hns-store\", default-features = false }")
        );
        for forbidden in ["hns-node", "hsrd", "clap", "tokio", "rocksdb"] {
            assert!(
                !manifest.contains(forbidden),
                "forbidden dependency {forbidden}"
            );
        }
        assert!(workspace.contains(
            "hns-rollback-journal = { version = \"=0.3.0\", git = \"https://github.com/handshake-rs/hns-rs.git\", rev = \"88ed7c64db52a6fcfce4146a8fc17b1377dfcc8e\" }"
        ));
    }

    #[test]
    fn local_conflict_never_finalizes_or_promotes() {
        let binding = binding(RollbackProtectionClass::RemoteWitness);
        let events = Rc::new(RefCell::new(Vec::new()));
        let external = FakeExternalControl::new(
            &binding,
            Some(enrolled_stable(binding, 1, b"old")),
            Rc::clone(&events),
        );
        let broker = FakeBroker {
            control: external.clone(),
        };
        let local = FakeLocalDriver::new(initialized(1, b"old"), events);
        local.push_behavior(LocalBehavior::Conflict);
        let error = run_with_driver(
            &local,
            &broker,
            &binding,
            &TestProtocol,
            |settled| settled.replace(2, b"new".to_vec(), ()),
            |_, ()| panic!("conflict must not promote"),
        )
        .expect_err("local conflict");
        assert!(matches!(error, JournaledNamespaceError::LocalConflict));
        assert!(matches!(
            external
                .0
                .borrow()
                .record
                .as_ref()
                .expect("prepared")
                .state(),
            JournalState::Prepared { .. }
        ));
        assert_eq!(
            external
                .0
                .borrow()
                .events
                .borrow()
                .iter()
                .filter(|event| **event == "external_write_stable")
                .count(),
            0
        );
    }
}
