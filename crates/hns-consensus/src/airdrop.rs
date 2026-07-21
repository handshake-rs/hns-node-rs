use hns_goosig::GooSigVerifier;
use hns_primitives::{
    AirdropError, AirdropKey, AirdropProof, AirdropSignatureVerifier, Amount, CovenantKind, Output,
};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    md::Md,
    nid::Nid,
    pkey::{Id, PKey},
    pkey_ctx::PkeyCtx,
    rsa::{Padding, Rsa},
    sign::Verifier,
};

/// Native verifier for every HSD airdrop key type. RSA wraps HSD's 32-byte
/// digest in the SHA-256 PKCS#1 v1.5 `DigestInfo`, while P-256, Ed25519, and
/// GooSig consume those bytes directly, matching `AirdropKey.verify` in the
/// pinned oracle.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeAirdropSignatureVerifier {
    goo: GooSigVerifier,
}

impl NativeAirdropSignatureVerifier {
    pub fn new() -> Result<Self, AirdropError> {
        let goo = GooSigVerifier::new()
            .map_err(|error| AirdropError::SignatureBackendFailure(error.to_string()))?;
        Ok(Self { goo })
    }
}

impl AirdropSignatureVerifier for NativeAirdropSignatureVerifier {
    fn verify(
        &self,
        key: &AirdropKey,
        message: &[u8; 32],
        signature: &[u8],
    ) -> Result<bool, AirdropError> {
        Ok(match key {
            AirdropKey::Rsa {
                modulus, exponent, ..
            } => verify_rsa(message, signature, modulus, exponent),
            AirdropKey::Goo { commitment } => self
                .goo
                .verify(message, signature, commitment)
                .map_err(|error| AirdropError::SignatureBackendFailure(error.to_string()))?,
            AirdropKey::P256 { point, .. } => verify_p256(message, signature, point),
            AirdropKey::Ed25519 { point, .. } => verify_ed25519(message, signature, point),
            // Address allocations are bound directly by `AirdropProof` and
            // never delegated to this backend.
            AirdropKey::Address { .. } => false,
        })
    }
}

fn verify_rsa(message: &[u8], signature: &[u8], modulus: &[u8], exponent: &[u8]) -> bool {
    let key = (|| {
        let modulus = BigNum::from_slice(modulus)?;
        let exponent = BigNum::from_slice(exponent)?;
        let rsa = Rsa::from_public_components(modulus, exponent)?;
        PKey::from_rsa(rsa)
    })();
    let Ok(key) = key else {
        return false;
    };
    let Ok(mut verifier) = PkeyCtx::new(&key) else {
        return false;
    };
    if verifier.verify_init().is_err()
        || verifier.set_rsa_padding(Padding::PKCS1).is_err()
        || verifier.set_signature_md(Md::sha256()).is_err()
    {
        return false;
    }
    verifier.verify(message, signature).unwrap_or(false)
}

fn verify_p256(message: &[u8], signature: &[u8], point: &[u8; 33]) -> bool {
    if signature.len() != 64 {
        return false;
    }
    let key = (|| {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let mut context = BigNumContext::new()?;
        let point = EcPoint::from_bytes(&group, point, &mut context)?;
        EcKey::from_public_key(&group, &point)
    })();
    let Ok(key) = key else {
        return false;
    };
    let compact = (|| {
        let r = BigNum::from_slice(&signature[..32])?;
        let s = BigNum::from_slice(&signature[32..])?;
        EcdsaSig::from_private_components(r, s)
    })();
    let Ok(compact) = compact else {
        return false;
    };
    compact.verify(message, &key).unwrap_or(false)
}

fn verify_ed25519(message: &[u8], signature: &[u8], point: &[u8; 32]) -> bool {
    let Ok(key) = PKey::public_key_from_raw_bytes(point, Id::ED25519) else {
        return false;
    };
    let Ok(mut verifier) = Verifier::new_without_digest(&key) else {
        return false;
    };
    verifier.verify_oneshot(signature, message).unwrap_or(false)
}

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
    #[serde(rename_all = "camelCase")]
    struct Fixture {
        proofs: Vec<FixtureProof>,
        signature_cases: Vec<FixtureSignatureCase>,
        airdrop: FixtureProof,
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

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FixtureSignatureCase {
        r#type: String,
        key_raw: String,
        message: String,
        signature: String,
        valid: bool,
        altered_message_valid: bool,
        altered_signature_valid: bool,
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
    fn native_signatures_match_every_hsd_airdrop_key_type() {
        let verifier = NativeAirdropSignatureVerifier::new().expect("native airdrop verifier");
        for case in fixture().signature_cases {
            let key = AirdropKey::decode(&decode_hex(&case.key_raw)).expect("fixture key");
            let message: [u8; 32] = decode_hex(&case.message)
                .try_into()
                .expect("32-byte fixture message");
            let signature = decode_hex(&case.signature);
            assert_eq!(
                verifier
                    .verify(&key, &message, &signature)
                    .unwrap_or_else(|error| panic!("{} verifier failed: {error}", case.r#type)),
                case.valid,
                "{} valid signature",
                case.r#type
            );

            let mut altered_message = message;
            altered_message[0] ^= 1;
            assert_eq!(
                verifier
                    .verify(&key, &altered_message, &signature)
                    .expect("altered message verification"),
                case.altered_message_valid,
                "{} altered message",
                case.r#type
            );

            let mut altered_signature = signature;
            altered_signature[0] ^= 1;
            assert_eq!(
                verifier
                    .verify(&key, &message, &altered_signature)
                    .expect("altered signature verification"),
                case.altered_signature_valid,
                "{} altered signature",
                case.r#type
            );
        }
    }

    #[test]
    fn native_goosig_verifies_upstream_production_airdrop() {
        let proof = fixture().airdrop;
        let verifier = NativeAirdropSignatureVerifier::new().expect("native airdrop verifier");
        let verified = verify_airdrop_output(
            &decode_hex(&proof.raw),
            &output_for(&proof),
            AirdropFlags::default(),
            &verifier,
        )
        .expect("HSD GooSig airdrop proof");
        assert_eq!(verified.position, 213_572);
        assert_eq!(verified.value, 4_246_994_314);
        assert_eq!(proof.id, "upstream-valid-goosig-airdrop");
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
