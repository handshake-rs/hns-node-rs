//! Isolated allocation qualification for the actual store overlay and caches.
//!
//! Run with `cargo test --release -p hns-store --test staging_allocations --
//! --ignored --nocapture --test-threads=1`. Requested live allocation bytes are
//! not RSS: the Rust allocator's metadata, fragmentation, native RocksDB
//! allocations, and resident input/base-store buffers are outside this probe.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;
use std::hint::black_box;

use hns_store::{
    AccountedWriteBatch, CheckpointWriteBatch, ColumnFamily, MemoryBatch, MemoryStore,
    ReadSnapshot, RocksBatch, ScanEntry, SharedBytes, StagingOverlay, Store, StoreError,
    WriteBatch,
};

#[derive(Clone, Copy, Default)]
struct Allocations {
    active: bool,
    calls: usize,
    requested_bytes: usize,
    live_bytes: usize,
    peak_bytes: usize,
}

thread_local! {
    static ALLOCATIONS: Cell<Allocations> = const { Cell::new(Allocations {
        active: false, calls: 0, requested_bytes: 0, live_bytes: 0, peak_bytes: 0,
    }) };
}

struct MeasuredAllocator;

fn record_allocation(old_bytes: usize, new_bytes: usize, allocation: bool) {
    // A thread-local probe excludes unrelated test runner allocations. This
    // callback uses only inline Cell operations and cannot allocate recursively.
    let _ = ALLOCATIONS.try_with(|counter| {
        let mut stats = counter.get();
        if stats.active {
            stats.calls += usize::from(allocation);
            if allocation {
                stats.requested_bytes += new_bytes;
            }
            stats.live_bytes = stats.live_bytes - old_bytes + new_bytes;
            stats.peak_bytes = stats.peak_bytes.max(stats.live_bytes);
            counter.set(stats);
        }
    });
}

// SAFETY: every operation forwards its pointer and layout unchanged to System;
// accounting only observes successful allocation sizes and never owns pointers.
unsafe impl GlobalAlloc for MeasuredAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            record_allocation(0, layout.size(), true);
        }
        pointer
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc_zeroed(layout) };
        if !pointer.is_null() {
            record_allocation(0, layout.size(), true);
        }
        pointer
    }

    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        record_allocation(layout.size(), 0, false);
        unsafe { System.dealloc(pointer, layout) };
    }

    unsafe fn realloc(&self, pointer: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let next = unsafe { System.realloc(pointer, layout, new_size) };
        if !next.is_null() {
            record_allocation(layout.size(), new_size, true);
        }
        next
    }
}

#[global_allocator]
static ALLOCATOR: MeasuredAllocator = MeasuredAllocator;

fn measure(name: &str, workload: impl FnOnce()) -> Allocations {
    ALLOCATIONS.with(|counter| {
        assert!(!counter.get().active);
        counter.set(Allocations {
            active: true,
            ..Allocations::default()
        });
    });
    workload();
    let stats = ALLOCATIONS.with(|counter| {
        let stats = counter.get();
        counter.set(Allocations::default());
        stats
    });
    assert_eq!(stats.live_bytes, 0, "workload must release all owned data");
    println!(
        "staging_allocations workload={name} calls={} requested_bytes={} peak_live_bytes={}",
        stats.calls, stats.requested_bytes, stats.peak_bytes
    );
    stats
}

fn key(index: usize) -> [u8; 36] {
    let mut key = [0x75; 36];
    key[..8].copy_from_slice(&(index as u64).to_le_bytes());
    key
}

struct GeneratedSnapshot {
    value_bytes: usize,
    reads: Cell<usize>,
}

impl ReadSnapshot for GeneratedSnapshot {
    fn get(&self, _: ColumnFamily, _: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        self.reads.set(self.reads.get() + 1);
        Ok(Some(vec![0x5a; self.value_bytes]))
    }

    fn scan_prefix(&self, _: ColumnFamily, _: &[u8]) -> Result<Vec<ScanEntry>, StoreError> {
        unreachable!("allocation workloads perform only point reads")
    }
}

fn replay_workload() {
    let store = MemoryStore::new();
    let overlay = StagingOverlay::new();
    let mut batch = overlay.batch_with_deferred_writes(store.batch());
    let base = GeneratedSnapshot {
        value_bytes: 128,
        reads: Cell::new(0),
    };
    let snapshot = overlay.snapshot(&base);
    for index in 0..16_384 {
        batch
            .put(ColumnFamily::Utxo, &key(index), &[0x31; 128])
            .unwrap();
    }
    for chunk in 0..64 {
        batch.begin_checkpoint().unwrap();
        for index in chunk * 128..(chunk + 1) * 128 {
            batch
                .put(ColumnFamily::Utxo, &key(index), &[0x32; 192])
                .unwrap();
            batch
                .delete(ColumnFamily::Utxo, &key(index + 8192))
                .unwrap();
        }
        if chunk % 2 == 0 {
            batch.rollback_checkpoint().unwrap();
        } else {
            batch.commit_checkpoint().unwrap();
        }
    }
    for index in 0..16_384 {
        let value = snapshot.get(ColumnFamily::Utxo, &key(index)).unwrap();
        let changed = (index % 8192 / 128) % 2 == 1;
        let expected = if changed && index >= 8192 {
            None
        } else if changed {
            Some(192)
        } else {
            Some(128)
        };
        assert_eq!(value.as_ref().map(Vec::len), expected);
        black_box(value);
    }
    assert_eq!(base.reads.get(), 0);
    drop(snapshot);
    black_box(batch.into_materialized_inner().unwrap());
}

fn checkpoint_workload(commit: bool) {
    let store = MemoryStore::new();
    let overlay = StagingOverlay::new();
    let mut batch = overlay.batch_with_deferred_writes(store.batch());
    batch
        .put(ColumnFamily::Snapshots, &key(1), &[0x31; 128])
        .unwrap();
    batch.begin_checkpoint().unwrap();
    for index in 0..128 {
        // The caller's encoding remains live while it is submitted. Tracking
        // it catches peak overlap with prior checkpoint-retained versions.
        let input = vec![index as u8; 65_536];
        batch.put(ColumnFamily::Snapshots, &key(1), &input).unwrap();
        black_box(input);
    }
    if commit {
        batch.commit_checkpoint().unwrap();
    } else {
        batch.rollback_checkpoint().unwrap();
    }
    let base = GeneratedSnapshot {
        value_bytes: 0,
        reads: Cell::new(0),
    };
    let snapshot = overlay.snapshot(&base);
    let value = snapshot
        .get(ColumnFamily::Snapshots, &key(1))
        .unwrap()
        .unwrap();
    assert_eq!(value.len(), if commit { 65_536 } else { 128 });
    drop(value);
    drop(snapshot);
    black_box(batch.into_materialized_inner().unwrap());
}

fn cache_workload(family: ColumnFamily) {
    let base = GeneratedSnapshot {
        value_bytes: 8192,
        reads: Cell::new(0),
    };
    let overlay = StagingOverlay::new();
    let snapshot = overlay.snapshot(&base);
    for index in 0..8192 {
        let key = key(index);
        let bytes = if family == ColumnFamily::NameTreeNodes {
            &key[..32]
        } else {
            &key[..]
        };
        let value = snapshot.get(family, bytes).unwrap().unwrap();
        assert_eq!(value.len(), 8192);
        black_box(value);
    }
    assert_eq!(base.reads.get(), 8192);
}

#[test]
#[ignore = "isolated allocation qualification; run explicitly with --ignored --nocapture"]
fn staging_allocation_profile() {
    measure("replay_16384", replay_workload);
    measure("checkpoint_128_rollback", || checkpoint_workload(false));
    measure("checkpoint_128_commit", || checkpoint_workload(true));
    measure("state_cache_8192x8192", || {
        cache_workload(ColumnFamily::Utxo)
    });
    measure("name_cache_8192x8192", || {
        cache_workload(ColumnFamily::NameTreeNodes)
    });
}

#[test]
fn shared_overlay_and_cache_reads_do_not_allocate_payload_copies() {
    let store = MemoryStore::new();
    let overlay = StagingOverlay::new();
    let mut batch = overlay.batch_with_deferred_writes(store.batch());
    let payload = vec![0x31; 262_144];
    let original_pointer = payload.as_ptr();
    batch
        .put_shared(ColumnFamily::Utxo, &key(1), SharedBytes::from(payload))
        .unwrap();
    let base = GeneratedSnapshot {
        value_bytes: 262_144,
        reads: Cell::new(0),
    };
    let snapshot = overlay.snapshot(&base);
    assert_eq!(
        snapshot
            .get_shared(ColumnFamily::Utxo, &key(1))
            .unwrap()
            .unwrap()
            .as_ptr(),
        original_pointer,
        "owned input allocation must survive staging without a byte copy"
    );
    drop(snapshot.get_shared(ColumnFamily::Utxo, &key(2)).unwrap());
    let stats = measure("shared_reads_4096x262144", || {
        for index in 0..4096 {
            let value = snapshot
                .get_shared(ColumnFamily::Utxo, &key(1 + index % 2))
                .unwrap()
                .unwrap();
            assert_eq!(value.len(), 262_144);
            black_box(value);
        }
    });
    assert_eq!(
        stats.calls, 0,
        "shared overlay/cache hits must not allocate"
    );
    assert_eq!(stats.peak_bytes, 0);
    assert_eq!(base.reads.get(), 1);
}

fn replacement_workload(shared_capacity: bool, peak_value_capacity: &Cell<usize>) {
    let store = MemoryStore::new();
    let overlay = StagingOverlay::new();
    let mut batch = overlay.batch_with_deferred_writes(store.batch());
    for index in 0..128 {
        let value_bytes = [65_536, 131_072, 1024, 65_536][index % 4];
        if shared_capacity {
            // This capacity remains owned even when only a small prefix is
            // serialized. Admission must not confuse logical length with it.
            let mut input = Vec::with_capacity(1_048_576);
            input.resize(value_bytes, 0x5a);
            batch
                .put_shared(ColumnFamily::Snapshots, &key(1), SharedBytes::from(input))
                .unwrap();
        } else {
            let input = vec![0x5a; value_bytes];
            batch.put(ColumnFamily::Snapshots, &key(1), &input).unwrap();
            black_box(input);
        }
        let usage = overlay.memory_usage();
        assert_eq!(usage.operations, 1);
        assert_eq!(usage.key_heap_bytes, 0);
        peak_value_capacity.set(peak_value_capacity.get().max(usage.value_capacity_bytes));
    }
    black_box(batch.into_materialized_inner().unwrap());
}

#[test]
#[ignore = "current-only replacement/capacity qualification; no historical baseline"]
fn staging_replacement_allocation_profile() {
    let peak_capacity = Cell::new(0);
    let ordinary = measure("replace_128_varying_sizes", || {
        replacement_workload(false, &peak_capacity)
    });
    assert_eq!(peak_capacity.get(), 131_072);
    assert!(ordinary.peak_bytes < 1_048_576);
    peak_capacity.set(0);
    let shared = measure("replace_128_shared_capacity_1m", || {
        replacement_workload(true, &peak_capacity)
    });
    assert_eq!(peak_capacity.get(), 1_048_576);
    assert!(shared.peak_bytes < 4 * 1_048_576);
}

#[test]
#[ignore = "current-only adversarial materialization framing qualification"]
fn staging_short_key_materialization_profile() {
    // One row beyond the previous table capacity makes the source table and
    // both the old and resized backend tables coexist during materialization.
    const ROWS: usize = 14_337;
    // Qualified node model: two representations, each with 192B framing.
    // This test compares the model with allocations, not with another copy of
    // the store's internal ownership counters.
    const OPERATION_FRAMING_BYTES: usize = 192;
    for key_bytes in [4, 8, 36] {
        for value_bytes in [0, 32] {
            let stats = measure("short_key_materialization", || {
                let store = MemoryStore::new();
                let overlay = StagingOverlay::new();
                let mut batch = overlay.batch_with_deferred_writes(store.batch());
                let value = [0x5a; 32];
                for index in 0..ROWS {
                    let key = key(index);
                    batch
                        .put_accounted(
                            ColumnFamily::HeightIndex,
                            &key[..key_bytes],
                            &value[..value_bytes],
                            (2 * (key_bytes + value_bytes + OPERATION_FRAMING_BYTES)) as u64,
                        )
                        .unwrap();
                }
                assert_eq!(overlay.memory_usage().operations, ROWS);
                black_box(batch.into_materialized_inner().unwrap());
            });
            let admitted = 2 * (key_bytes + value_bytes + OPERATION_FRAMING_BYTES) * ROWS;
            assert!(
                stats.peak_bytes <= admitted,
                "materialization peak {} exceeds admitted effect bytes {admitted}",
                stats.peak_bytes
            );
            println!(
                "staging_framing rows={ROWS} key_bytes={key_bytes} value_bytes={value_bytes} \
                 peak_live_bytes={} model128={} model192={} model224={} model256={}",
                stats.peak_bytes,
                2 * (key_bytes + value_bytes + 128) * ROWS,
                2 * (key_bytes + value_bytes + 192) * ROWS,
                2 * (key_bytes + value_bytes + 224) * ROWS,
                2 * (key_bytes + value_bytes + 256) * ROWS,
            );
        }
    }
}

fn allocation_free_long_key_accounting<B: AccountedWriteBatch + CheckpointWriteBatch + Default>(
    name: &str,
) {
    let mut batch = B::default();
    let existing = [0x51; 96];
    let missing = [0x52; 96];
    batch
        .put_accounted(ColumnFamily::WalletState, &existing, &[0x31; 32], 123)
        .unwrap();
    batch.begin_checkpoint().unwrap();
    let stats = measure(name, || {
        for _ in 0..4096 {
            assert_eq!(
                batch.operation_charge(ColumnFamily::WalletState, &existing),
                123
            );
            assert_eq!(
                batch.operation_charge(ColumnFamily::WalletState, &missing),
                0
            );
            assert_eq!(
                batch.operation_charge(ColumnFamily::WalletHistory, &existing),
                0
            );
            assert!(batch.checkpoint_replacement_charge(ColumnFamily::WalletState, &existing) > 0);
            assert!(batch.checkpoint_replacement_charge(ColumnFamily::WalletState, &missing) > 0);
        }
    });
    assert_eq!(stats.calls, 0, "admission lookup must precede allocations");
    assert_eq!(stats.peak_bytes, 0);
    batch
        .put_accounted(ColumnFamily::WalletState, &existing, &[0x32; 32], 124)
        .unwrap();
    let stats = measure(name, || {
        for _ in 0..4096 {
            assert_eq!(
                batch.operation_charge(ColumnFamily::WalletState, &existing),
                124
            );
            assert_eq!(
                batch.checkpoint_replacement_charge(ColumnFamily::WalletState, &existing),
                0
            );
        }
    });
    assert_eq!(stats.calls, 0);
    assert_eq!(stats.peak_bytes, 0);
    batch.rollback_checkpoint().unwrap();
    assert_eq!(
        batch.operation_charge(ColumnFamily::WalletState, &existing),
        123
    );
}

#[test]
fn long_key_accounting_lookups_do_not_allocate() {
    allocation_free_long_key_accounting::<MemoryBatch>("memory_long_key_accounting");
    allocation_free_long_key_accounting::<RocksBatch>("rocks_long_key_accounting");
}
