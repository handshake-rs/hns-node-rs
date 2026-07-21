#![no_main]

use hns_testkit::FixtureManifest;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(manifest) = serde_json::from_slice::<FixtureManifest>(data) {
        let _ = manifest.validate();
    }
});
