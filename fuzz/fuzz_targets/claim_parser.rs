#![no_main]

use hns_primitives::{Claim, OwnershipClaimData, OwnershipProof};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(claim) = Claim::decode(data) {
        let _ = claim.hash();
        let _ = claim.encode();
        let _ = OwnershipProof::decode(&claim.blob);
    }
    if let Ok(proof) = OwnershipProof::decode(data) {
        let _ = proof.encode();
        let _ = proof.is_sane();
        let _ = proof.name();
        let _ = proof.target();
        let _ = proof.window();
    }
    if let Ok(claim_data) = OwnershipClaimData::decode(data) {
        let _ = claim_data.encode();
    }
});
