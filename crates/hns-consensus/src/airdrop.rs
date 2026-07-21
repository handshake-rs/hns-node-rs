use hns_primitives::{
    AirdropError, AirdropProof, AirdropSignatureVerifier, Amount, CovenantKind, Output,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AirdropFlags {
    /// The active airstop deployment disables every airdrop/faucet issuance.
    pub airstop: bool,
    /// The hardening deployment rejects RSA keys below HSD's 2041-bit floor.
    pub hardening: bool,
    /// The network-height GooSig cutoff rejects Goo commitments independently
    /// of versionbits deployment state.
    pub goosig_disabled: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedAirdrop {
    pub position: u32,
    /// The full allocation added to HSD's conjured-value accounting. The
    /// transaction output receives this amount minus the proof fee.
    pub value: Amount,
}

/// Verify one special coinbase input and its same-index output using HSD's
/// airdrop rules. Duplicate-position handling is intentionally stateful and is
/// performed by `hns-state` after this pure proof check succeeds.
pub fn verify_airdrop_output(
    proof_raw: &[u8],
    output: &Output,
    flags: AirdropFlags,
    signatures: &dyn AirdropSignatureVerifier,
) -> Result<VerifiedAirdrop, AirdropConsensusError> {
    if flags.airstop {
        return Err(AirdropConsensusError::Disabled);
    }
    if output.covenant.kind != CovenantKind::None || !output.covenant.items.is_empty() {
        return Err(AirdropConsensusError::OutputCovenant);
    }

    let proof = AirdropProof::decode(proof_raw)?;
    if !proof.is_sane() {
        return Err(AirdropConsensusError::Insane);
    }

    if flags.goosig_disabled || flags.hardening {
        let key = proof.key()?;
        if flags.goosig_disabled && key.is_goo() {
            return Err(AirdropConsensusError::GooDisabled);
        }
        if flags.hardening && key.is_weak() {
            return Err(AirdropConsensusError::WeakKey);
        }
    }

    if !proof.verify(signatures)? {
        return Err(AirdropConsensusError::InvalidProof);
    }

    let value = proof.value();
    let expected_output = value
        .checked_sub(proof.fee)
        .ok_or(AirdropConsensusError::Insane)?;
    if output.value != expected_output {
        return Err(AirdropConsensusError::OutputValue {
            expected: expected_output,
            actual: output.value,
        });
    }
    if output.address.version != proof.version || output.address.hash != proof.address {
        return Err(AirdropConsensusError::OutputAddress);
    }

    Ok(VerifiedAirdrop {
        position: proof.position()?,
        value,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum AirdropConsensusError {
    #[error("airdrop issuance is disabled by the active airstop deployment")]
    Disabled,
    #[error("airdrop output must use an empty NONE covenant")]
    OutputCovenant,
    #[error("airdrop proof codec or key validation failed: {0}")]
    Proof(#[from] AirdropError),
    #[error("airdrop proof is structurally non-sane")]
    Insane,
    #[error("GooSig airdrop keys are disabled at this height")]
    GooDisabled,
    #[error("weak RSA airdrop key is disabled by hardening")]
    WeakKey,
    #[error("airdrop Merkle or signature proof is invalid")]
    InvalidProof,
    #[error("airdrop output value {actual} does not equal required value {expected}")]
    OutputValue { expected: Amount, actual: Amount },
    #[error("airdrop output address does not match its proof")]
    OutputAddress,
}

#[cfg(test)]
mod tests {
    use hns_primitives::{
        Address, AirdropKey, Covenant, UnavailableAirdropSignatureVerifier, AIRDROP_RECIPIENT_FEE,
    };
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct Fixture {
        proofs: Vec<FixtureProof>,
        faucet: FixtureProof,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FixtureProof {
        id: String,
        raw: String,
        value: u64,
        version: u8,
        address: String,
        fee: u64,
    }

    fn fixture() -> Fixture {
        serde_json::from_str(include_str!("../../../fixtures/hsd/airdrops/codec-v1.json"))
            .expect("HSD airdrop fixture")
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
            .collect()
    }

    fn nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid fixture hex"),
        }
    }

    fn output_for(proof: &FixtureProof) -> Output {
        Output {
            value: proof.value - proof.fee,
            address: Address {
                version: proof.version,
                hash: decode_hex(&proof.address),
            },
            covenant: Covenant {
                kind: CovenantKind::None,
                items: Vec::new(),
            },
        }
    }

    #[test]
    fn valid_hsd_faucet_output_verifies() {
        let proof = fixture().faucet;
        let verified = verify_airdrop_output(
            &decode_hex(&proof.raw),
            &output_for(&proof),
            AirdropFlags::default(),
            &UnavailableAirdropSignatureVerifier,
        )
        .expect("HSD faucet proof");
        assert_eq!(verified.position, 216_503);
        assert_eq!(verified.value, 8_493_988_628);
        assert_eq!(proof.id, "upstream-valid-faucet");
    }

    #[test]
    fn faucet_output_binding_and_airstop_are_enforced() {
        let proof = fixture().faucet;
        let raw = decode_hex(&proof.raw);
        let mut output = output_for(&proof);
        output.value += 1;
        assert!(matches!(
            verify_airdrop_output(
                &raw,
                &output,
                AirdropFlags::default(),
                &UnavailableAirdropSignatureVerifier
            ),
            Err(AirdropConsensusError::OutputValue { .. })
        ));

        let output = output_for(&proof);
        assert!(matches!(
            verify_airdrop_output(
                &raw,
                &output,
                AirdropFlags {
                    airstop: true,
                    ..AirdropFlags::default()
                },
                &UnavailableAirdropSignatureVerifier
            ),
            Err(AirdropConsensusError::Disabled)
        ));
    }

    #[test]
    fn deployment_key_restrictions_precede_crypto_verification() {
        let expected = fixture();
        let goo = &expected.proofs[1];
        assert!(matches!(
            verify_airdrop_output(
                &decode_hex(&goo.raw),
                &output_for(goo),
                AirdropFlags {
                    goosig_disabled: true,
                    ..AirdropFlags::default()
                },
                &UnavailableAirdropSignatureVerifier
            ),
            Err(AirdropConsensusError::GooDisabled)
        ));

        let rsa = &expected.proofs[0];
        let mut proof = AirdropProof::decode(&decode_hex(&rsa.raw)).expect("synthetic RSA proof");
        proof.key = AirdropKey::Rsa {
            modulus: vec![1; 128],
            exponent: vec![1, 0, 1],
            nonce: [0x12; 32],
        }
        .encode()
        .expect("weak RSA key");
        assert!(matches!(
            verify_airdrop_output(
                &proof.encode().expect("weak proof"),
                &output_for(rsa),
                AirdropFlags {
                    hardening: true,
                    ..AirdropFlags::default()
                },
                &UnavailableAirdropSignatureVerifier
            ),
            Err(AirdropConsensusError::WeakKey)
        ));
    }

    #[test]
    fn address_key_fee_is_authenticated() {
        let proof = fixture().faucet;
        let mut decoded = AirdropProof::decode(&decode_hex(&proof.raw)).expect("faucet proof");
        decoded.fee = AIRDROP_RECIPIENT_FEE + 1;
        let output = output_for(&proof);
        assert!(matches!(
            verify_airdrop_output(
                &decoded.encode().expect("mutated faucet proof"),
                &output,
                AirdropFlags::default(),
                &UnavailableAirdropSignatureVerifier
            ),
            Err(AirdropConsensusError::InvalidProof)
        ));
    }
}
