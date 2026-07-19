#![no_main]

use hns_primitives::Block;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(block) = Block::decode(data) {
        let _ = block.hash();
    }
});
