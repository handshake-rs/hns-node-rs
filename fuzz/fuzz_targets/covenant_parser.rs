#![no_main]

use hns_primitives::Covenant;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Covenant::decode(data);
});
