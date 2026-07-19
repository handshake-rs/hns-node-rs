#![no_main]

use hns_primitives::Resource;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = Resource::decode(data);
});
