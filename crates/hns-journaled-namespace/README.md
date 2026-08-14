# hns-journaled-namespace

`hns-journaled-namespace` is an inert native coordinator for one external
anti-rollback journal namespace and one `hns-store` authenticated namespace.
It supplies no journal backend, key storage, provisioning, enrollment,
retirement, node role, RPC method, CLI flag, or default feature.

An ordinary run:

1. requires a broker to attest production qualification for the exact
   binding and rejects `IntegrityOnlySameRollbackDomain`;
2. acquires the external broker guard before the local namespace lease;
3. authenticates and rereads both complete states under those guards;
4. recovers any prior `Prepared` transition to `Stable`;
5. derives a least-privilege typed projection and validates complete semantic,
   monotonic, and retention invariants across an optional old-to-new proposal;
6. seals the proposal exactly once, durably acknowledges external `Prepared`,
   performs the exact local CAS and mandatory reread, then durably acknowledges
   external `Stable`; and
7. invokes dependent use only after the selected state is exactly reread as
   Stable, while both guards remain held.

The returned `HistoricalEvidence` is revision- and fingerprint-tagged evidence
of the state under which dependent use completed. It is not a transferable
current-authorization capability. A later authority-dependent operation must
enter a new guarded scope or use a broker-owned session whose establishment
completed inside that scope.

The protocol adapter is trusted boundary code. Snapshot validation returns two
separate typed values: coordinator-internal transition state and a narrower
callback projection. Transition state must retain every security-relevant
high-water, tombstone, retained key, and whole-aggregate invariant regardless
of the resource selected for the current operation. The projection must not
copy out the raw complete snapshot or broker secrets. Fingerprinting,
validation, projection, and transition checks must be deterministic and
side-effect-free for the same inputs plus immutable adapter configuration and
evidence. Evidence needed to accept a transition must be reconstructible after
restart—durably encoded in the complete snapshot or available as immutable,
recoverable adapter evidence—because crash recovery revalidates both sides of
`Prepared`. The planning callback may only compute the owned proposal/context
and must perform no irreversible or externally visible effect; `use_settled`
is the sole dependent-effect phase.

This primitive is deliberately synchronous and requires an external guard
that cannot silently expire or be superseded while held. The broker owns
authentication, AEAD key custody, nonce allocation, external fencing, durable
CAS, and exact outcome reconciliation. A binding's protection enum is only a
claim; `ensure_production_qualified` must reflect actual backend qualification.
The local database must be restart-durable and synchronously published.

## Composition boundary

`run_scoped` coordinates exactly one pair and rejects same-thread nesting. It
must not be wired directly as the complete HNSA/HNSR requester operation:
those roles need authority-subject and requester-storage namespaces held
together. Their future multi-namespace coordinator must:

1. derive and sort one canonical set of namespace identities;
2. acquire **all external guards first** in that order;
3. acquire **all local guards second** in the same order;
4. load no state until every required guard is held; and
5. retain every guard through both commits and complete dependent use or
   session establishment.

Nesting external-A/local-A around external-B/local-B is forbidden because it
does not provide that order and can deadlock or expose mixed-current state.

Browser, extension, and mobile adapters need the same state machine through a
trusted native/platform broker or qualified remote witness. IndexedDB,
extension storage, ordinary mobile databases, and a journal stored beside the
protected snapshot are not by themselves production anti-rollback roots.
JavaScript-facing projections must keep leases, fencing tokens, journal
records, snapshots, keys, nonces, and raw `u64` values inside the trusted
broker; counters and times use lossless strings, `BigInt`, or exact bytes.
