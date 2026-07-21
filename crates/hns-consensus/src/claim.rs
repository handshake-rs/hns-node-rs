use hns_primitives::{
    hash_name, Amount, CovenantKind, DnssecVerifier, Height, NameHash, Output, OwnershipProof,
    OwnershipProofError,
};
use openssl::{
    bn::{BigNum, BigNumContext},
    ec::{EcGroup, EcKey, EcPoint},
    ecdsa::EcdsaSig,
    hash::{hash, MessageDigest},
    nid::Nid,
    pkey::{Id, PKey, Public},
    rsa::{Padding, Rsa},
    sign::Verifier,
};

use crate::{reserved_name, Network, COIN};

const ALG_RSASHA1: u8 = 5;
const ALG_RSASHA1_NSEC3: u8 = 7;
const ALG_RSASHA256: u8 = 8;
const ALG_RSASHA512: u8 = 10;
const ALG_ECDSA_P256_SHA256: u8 = 13;
const ALG_ECDSA_P384_SHA384: u8 = 14;
const ALG_ED25519: u8 = 15;
const ALG_ED448: u8 = 16;

/// DNSSEC cryptography for HSD ownership proofs. OpenSSL is used only through
/// its verification APIs; DNS wire parsing, canonicalization, trust-chain
/// selection, algorithm policy, and root anchoring remain explicit Rust code
/// in `hns-primitives`. SHA-1, SHA-256, SHA-384, and SHA-512 DS digests are
/// supported; GOST R 34.11-94 DS records fail closed because OpenSSL does not
/// expose that legacy digest without an external provider.
#[derive(Clone, Copy, Debug, Default)]
pub struct OpenSslDnssecVerifier;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ClaimFlags {
    pub hardened: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedClaim {
    pub name_hash: NameHash,
    pub name: Vec<u8>,
    pub weak: bool,
    pub commit_hash: [u8; 32],
    pub commit_height: Height,
    pub value: Amount,
    pub fee: Amount,
    pub conjured: Amount,
}

pub fn verify_claim_output(
    proof_raw: &[u8],
    output: &Output,
    height: Height,
    parent_median_time: u64,
    network: Network,
    flags: ClaimFlags,
    dnssec: &dyn DnssecVerifier,
) -> Result<VerifiedClaim, ClaimConsensusError> {
    if output.covenant.kind != CovenantKind::Claim || output.covenant.items.len() != 6 {
        return Err(ClaimConsensusError::OutputCovenant);
    }
    if output.covenant.item_u32(1) != Some(height) {
        return Err(ClaimConsensusError::ClaimHeight);
    }

    let proof = OwnershipProof::decode(proof_raw)?;
    if !proof.is_sane() {
        return Err(ClaimConsensusError::Insane);
    }
    if !proof.verify_signatures(dnssec) {
        return Err(ClaimConsensusError::InvalidSignatures);
    }
    if !proof.verify_time(parent_median_time) {
        return Err(ClaimConsensusError::InvalidTime);
    }

    let name = proof.name().ok_or(ClaimConsensusError::MissingTarget)?;
    let reserved = reserved_name(name).ok_or(ClaimConsensusError::NotReserved)?;
    if network.params().names.no_reserved || height >= network.params().names.claim_period {
        return Err(ClaimConsensusError::NotReserved);
    }
    let target = proof
        .target()
        .and_then(|name| name.to_ascii_fqdn())
        .ok_or(ClaimConsensusError::MissingTarget)?;
    if target.as_bytes() != reserved.target {
        return Err(ClaimConsensusError::ReservedTarget);
    }

    let data = proof
        .claim_data(network.claim_prefix())?
        .ok_or(ClaimConsensusError::MissingData)?;
    if data.fee > reserved.value {
        return Err(ClaimConsensusError::FeeExceedsValue);
    }
    let (inception, expiration) = proof.window();
    if inception == 0 && expiration == 0 {
        return Err(ClaimConsensusError::InvalidTime);
    }

    let covenant_name = output
        .covenant
        .item(2)
        .ok_or(ClaimConsensusError::OutputCovenant)?;
    if covenant_name != reserved.name {
        return Err(ClaimConsensusError::NameBinding);
    }
    let covenant_name =
        std::str::from_utf8(covenant_name).map_err(|_| ClaimConsensusError::NameBinding)?;
    let name_hash = hash_name(covenant_name).map_err(|_| ClaimConsensusError::NameBinding)?;
    if output.covenant.item_hash(0) != Some(*name_hash.as_bytes()) {
        return Err(ClaimConsensusError::NameBinding);
    }

    let weak = proof.is_weak();
    if output.covenant.item_u8(3).map(|value| value & 1 != 0) != Some(weak) {
        return Err(ClaimConsensusError::WeakBinding);
    }
    if flags.hardened && weak {
        return Err(ClaimConsensusError::WeakDisabled);
    }
    if output.covenant.item_hash(4) != Some(data.commit_hash)
        || output.covenant.item_u32(5) != Some(data.commit_height)
    {
        return Err(ClaimConsensusError::CommitBinding);
    }
    if data.commit_height == 0 {
        return Err(ClaimConsensusError::ZeroCommitHeight);
    }
    if output.address.version != data.version || output.address.hash != data.address {
        return Err(ClaimConsensusError::OutputAddress);
    }
    let expected_output = reserved
        .value
        .checked_sub(data.fee)
        .ok_or(ClaimConsensusError::FeeExceedsValue)?;
    if output.value != expected_output {
        return Err(ClaimConsensusError::OutputValue {
            expected: expected_output,
            actual: output.value,
        });
    }

    let conjured = if height >= network.params().deflation_height {
        if data.commit_height == 1 {
            if data.fee > 1_000 * COIN {
                return Err(ClaimConsensusError::InitialFee);
            }
            reserved.value
        } else {
            output.value
        }
    } else {
        reserved.value
    };

    Ok(VerifiedClaim {
        name_hash,
        name: reserved.name,
        weak,
        commit_hash: data.commit_hash,
        commit_height: data.commit_height,
        value: reserved.value,
        fee: data.fee,
        conjured,
    })
}

#[derive(Debug, thiserror::Error)]
pub enum ClaimConsensusError {
    #[error("claim output covenant is malformed")]
    OutputCovenant,
    #[error("claim covenant height does not equal the containing block height")]
    ClaimHeight,
    #[error("ownership proof codec failed: {0}")]
    Proof(#[from] OwnershipProofError),
    #[error("ownership TXT data codec failed: {0}")]
    Data(#[from] hns_primitives::ClaimError),
    #[error("ownership proof is structurally non-sane")]
    Insane,
    #[error("ownership proof DNSSEC signature chain is invalid")]
    InvalidSignatures,
    #[error("ownership proof signatures do not cover the parent median time")]
    InvalidTime,
    #[error("ownership proof has no valid target")]
    MissingTarget,
    #[error("ownership proof target is not claimable in the reserved-name database")]
    NotReserved,
    #[error("ownership proof target does not match the reserved-name target")]
    ReservedTarget,
    #[error("ownership proof has no network-matching claim TXT data")]
    MissingData,
    #[error("ownership claim fee exceeds its reserved allocation")]
    FeeExceedsValue,
    #[error("claim covenant name/hash does not match its DNSSEC proof")]
    NameBinding,
    #[error("claim covenant weak-key flag does not match its DNSSEC proof")]
    WeakBinding,
    #[error("weak DNSSEC claim keys are disabled by covenant hardening")]
    WeakDisabled,
    #[error("claim covenant commit does not match its TXT data")]
    CommitBinding,
    #[error("claim commit height must be nonzero")]
    ZeroCommitHeight,
    #[error("claim output address does not match its TXT data")]
    OutputAddress,
    #[error("claim output value {actual} does not equal required value {expected}")]
    OutputValue { expected: Amount, actual: Amount },
    #[error("initial post-deflation claim fee exceeds 1000 HNS")]
    InitialFee,
}

impl DnssecVerifier for OpenSslDnssecVerifier {
    fn digest(&self, digest_type: u8, data: &[u8]) -> Option<Vec<u8>> {
        let digest = match digest_type {
            1 => MessageDigest::sha1(),
            2 => MessageDigest::sha256(),
            4 => MessageDigest::sha384(),
            5 => MessageDigest::sha512(),
            _ => return None,
        };
        hash(digest, data).ok().map(|value| value.to_vec())
    }

    fn verify(&self, algorithm: u8, public_key: &[u8], data: &[u8], signature: &[u8]) -> bool {
        match algorithm {
            ALG_RSASHA1 | ALG_RSASHA1_NSEC3 => {
                verify_rsa(MessageDigest::sha1(), public_key, data, signature)
            }
            ALG_RSASHA256 => verify_rsa(MessageDigest::sha256(), public_key, data, signature),
            ALG_RSASHA512 => verify_rsa(MessageDigest::sha512(), public_key, data, signature),
            ALG_ECDSA_P256_SHA256 => verify_ecdsa(
                Nid::X9_62_PRIME256V1,
                32,
                MessageDigest::sha256(),
                public_key,
                data,
                signature,
            ),
            ALG_ECDSA_P384_SHA384 => verify_ecdsa(
                Nid::SECP384R1,
                48,
                MessageDigest::sha384(),
                public_key,
                data,
                signature,
            ),
            ALG_ED25519 => verify_ed(Id::ED25519, public_key, data, signature),
            ALG_ED448 => verify_ed(Id::ED448, public_key, data, signature),
            _ => false,
        }
    }
}

fn verify_rsa(digest: MessageDigest, public_key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    let Some((exponent, modulus)) = rsa_components(public_key) else {
        return false;
    };
    let key = (|| {
        let exponent = BigNum::from_slice(exponent)?;
        let modulus = BigNum::from_slice(modulus)?;
        let rsa = Rsa::from_public_components(modulus, exponent)?;
        PKey::from_rsa(rsa)
    })();
    let Ok(key) = key else {
        return false;
    };
    verify_digest(digest, &key, data, signature, true)
}

fn rsa_components(raw: &[u8]) -> Option<(&[u8], &[u8])> {
    let first = *raw.first()?;
    let (exponent_size, offset) = if first == 0 {
        let size = usize::from(u16::from_be_bytes([*raw.get(1)?, *raw.get(2)?]));
        (size, 3usize)
    } else {
        (usize::from(first), 1usize)
    };
    if exponent_size == 0 {
        return None;
    }
    let exponent_end = offset.checked_add(exponent_size)?;
    let exponent = raw.get(offset..exponent_end)?;
    let modulus = raw.get(exponent_end..)?;
    (!modulus.is_empty()).then_some((exponent, modulus))
}

fn verify_ecdsa(
    curve: Nid,
    coordinate_size: usize,
    digest: MessageDigest,
    public_key: &[u8],
    data: &[u8],
    signature: &[u8],
) -> bool {
    if public_key.len() != coordinate_size * 2 || signature.len() != coordinate_size * 2 {
        return false;
    }
    let key = (|| {
        let group = EcGroup::from_curve_name(curve)?;
        let mut context = BigNumContext::new()?;
        let mut encoded = Vec::with_capacity(1 + public_key.len());
        encoded.push(4);
        encoded.extend_from_slice(public_key);
        let point = EcPoint::from_bytes(&group, &encoded, &mut context)?;
        let key = EcKey::from_public_key(&group, &point)?;
        PKey::from_ec_key(key)
    })();
    let Ok(key) = key else {
        return false;
    };
    let der = (|| {
        let r = BigNum::from_slice(&signature[..coordinate_size])?;
        let s = BigNum::from_slice(&signature[coordinate_size..])?;
        EcdsaSig::from_private_components(r, s)?.to_der()
    })();
    let Ok(der) = der else {
        return false;
    };
    verify_digest(digest, &key, data, &der, false)
}

fn verify_ed(id: Id, public_key: &[u8], data: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = PKey::public_key_from_raw_bytes(public_key, id) else {
        return false;
    };
    let Ok(mut verifier) = Verifier::new_without_digest(&key) else {
        return false;
    };
    verifier.verify_oneshot(signature, data).unwrap_or(false)
}

fn verify_digest(
    digest: MessageDigest,
    key: &PKey<Public>,
    data: &[u8],
    signature: &[u8],
    rsa: bool,
) -> bool {
    let Ok(mut verifier) = Verifier::new(digest, key) else {
        return false;
    };
    if rsa && verifier.set_rsa_padding(Padding::PKCS1).is_err() {
        return false;
    }
    verifier
        .update(data)
        .and_then(|()| verifier.verify(signature))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use hns_primitives::{DnsRecord, DnsRecordData, DnssecAnchor, OwnershipProof, DNS_TYPE_TXT};
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Fixture {
        proof: ProofFixture,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProofFixture {
        raw: String,
        signatures_valid: bool,
        signatures_valid_with_historical_test_policy: bool,
        proof_root_anchor: AnchorFixture,
        name: String,
        reserved_target: String,
        reserved_value: u64,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AnchorFixture {
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: String,
    }

    fn fixture() -> Fixture {
        serde_json::from_str(include_str!("../../../fixtures/hsd/claims/codec-v1.json"))
            .expect("HSD ownership proof fixture")
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

    fn is_hsd_test_claim(record: &DnsRecord) -> bool {
        if record.record_type != DNS_TYPE_TXT {
            return false;
        }
        let DnsRecordData::Txt(items) = &record.data else {
            return false;
        };
        let Some(item) = items.first() else {
            return false;
        };
        let Some(suffix) = item.strip_prefix(b"hns-") else {
            return false;
        };
        let Some(colon) = suffix.iter().position(|byte| *byte == b':') else {
            return false;
        };
        colon > 0
            && suffix[..colon]
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    }

    #[test]
    fn openssl_dnssec_matches_hsd_historical_proof_policy() {
        let expected = fixture().proof;
        let mut proof = OwnershipProof::decode(&decode_hex(&expected.raw)).expect("proof");
        let reserved = crate::reserved_name(expected.name.as_bytes()).expect("reserved name");
        assert_eq!(reserved.name, expected.name.as_bytes());
        assert_eq!(reserved.target, expected.reserved_target.as_bytes());
        assert_eq!(reserved.value, expected.reserved_value);
        assert_eq!(
            proof.verify_signatures(&OpenSslDnssecVerifier),
            expected.signatures_valid
        );

        proof
            .zones
            .last_mut()
            .expect("target zone")
            .claim
            .retain(|record| !is_hsd_test_claim(record));
        let anchor = DnssecAnchor {
            key_tag: expected.proof_root_anchor.key_tag,
            algorithm: expected.proof_root_anchor.algorithm,
            digest_type: expected.proof_root_anchor.digest_type,
            digest: decode_hex(&expected.proof_root_anchor.digest),
        };
        assert_eq!(
            proof.verify_signatures_with_anchors(
                &OpenSslDnssecVerifier,
                std::slice::from_ref(&anchor),
            ),
            expected.signatures_valid_with_historical_test_policy
        );

        let DnsRecordData::Rrsig(signature) =
            &mut proof.zones[0].keys.last_mut().expect("root signature").data
        else {
            panic!("root signature record");
        };
        signature.signature[0] ^= 1;
        assert!(!proof.verify_signatures_with_anchors(&OpenSslDnssecVerifier, &[anchor]));
    }
}
