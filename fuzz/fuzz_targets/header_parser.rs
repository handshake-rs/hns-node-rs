#![no_main]

use hns_primitives::Header;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(header) = Header::decode(data) {
        let _ = header.hash();
        let _ = header.share_hash();
        let _ = header.verify_pow();
    }
});
