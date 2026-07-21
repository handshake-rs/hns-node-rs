#![no_main]

use hns_primitives::{AirdropKey, AirdropProof, UnavailableAirdropSignatureVerifier};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(key) = AirdropKey::decode(data) {
        let _ = key.encode();
        let _ = key.is_weak();
    }
    if let Ok(proof) = AirdropProof::decode(data) {
        let _ = proof.encode();
        let _ = proof.hash();
        let _ = proof.signature_hash();
        let _ = proof.verify_merkle();
        let _ = proof.verify(&UnavailableAirdropSignatureVerifier);
    }
});
