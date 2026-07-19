#![no_main]

use hns_primitives::Transaction;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(transaction) = Transaction::decode(data) {
        let _ = transaction.txid();
        let _ = transaction.witness_hash();
    }
});
