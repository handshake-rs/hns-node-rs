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
/// in `hns-primitives`. SHA-1, SHA-256, SHA-384, and SHA-512 use OpenSSL;
/// DNSSEC digest type 3 uses the exact GOST R 34.11-94 CryptoPro construction
/// selected by HSD's pinned `bns` dependency.
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
    parent_time: u64,
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
    if !proof.verify_time(parent_time) {
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
    #[error("ownership proof signatures do not cover the parent block time")]
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
        if digest_type == 3 {
            return Some(crate::gost94::digest(data).to_vec());
        }
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
    use hns_primitives::{
        Block, DnsRecord, DnsRecordData, DnssecAnchor, OwnershipProof, Transaction, DNS_TYPE_TXT,
    };
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Fixture {
        proofs: Vec<ProofFixture>,
        gost94_digests: Vec<GostDigestFixture>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProofFixture {
        raw: String,
        signatures_valid: bool,
        root_anchors: Vec<AnchorFixture>,
        name: String,
        reserved_target: String,
        reserved_value: u64,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct AnchorFixture {
        name: String,
        key_tag: u16,
        algorithm: u8,
        digest_type: u8,
        digest: String,
        signatures_valid_with_historical_test_policy: bool,
    }

    #[derive(Deserialize)]
    struct GostDigestFixture {
        id: String,
        data: String,
        digest: String,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetHistoryFixture {
        canonical_context: MainnetContextFixture,
        block: MainnetBlockFixture,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetReplacementFixture {
        schema: u32,
        canonical_context: MainnetReplacementContextFixture,
        lifecycle: MainnetClaimLifecycleFixture,
        blocks: Vec<MainnetBlockFixture>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetClaimLifecycleFixture {
        claim_period_height: u32,
        lineage: MainnetClaimLineageFixture,
        terminal: MainnetTerminalClaimFixture,
        boundary: MainnetClaimBoundaryFixture,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetClaimLineageFixture {
        name: String,
        name_hash: String,
        points: Vec<MainnetClaimPointFixture>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetTerminalClaimFixture {
        name: String,
        name_hash: String,
        blocks_before_claim_period: u32,
        point: MainnetClaimPointFixture,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetClaimBoundaryFixture {
        block_height: u32,
        block_hash: String,
        parent_time: u64,
        coinbase_txid: String,
        coinbase_raw: String,
        claim_count: usize,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetClaimPointFixture {
        block_height: u32,
        coinbase_txid: String,
        output_index: usize,
        output_value: u64,
        reserved_value: u64,
        fee: u64,
        commit_hash: String,
        commit_height: u32,
        weak: bool,
        conjured: u64,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetReplacementContextFixture {
        blocks: Vec<MainnetReplacementBlockContextFixture>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetReplacementBlockContextFixture {
        block_height: u32,
        parent_time: u64,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetContextFixture {
        parent_time: u64,
        parent_median_time: u64,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetBlockFixture {
        #[serde(default)]
        role: String,
        height: u32,
        hash: String,
        raw: String,
        size: usize,
        base_size: usize,
        weight: usize,
        transaction_count: usize,
        claims: Vec<MainnetClaimFixture>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct MainnetClaimFixture {
        output_index: usize,
        name: String,
        target: String,
        name_hash: String,
        weak: bool,
        proof_raw: String,
        commit_hash: String,
        commit_height: u32,
        version: u8,
        address: String,
        reserved_value: u64,
        fee: u64,
        output_value: u64,
        conjured: u64,
    }

    fn fixture() -> Fixture {
        serde_json::from_str(include_str!("../../../fixtures/hsd/claims/codec-v1.json"))
            .expect("HSD ownership proof fixture")
    }

    fn mainnet_history_fixture() -> MainnetHistoryFixture {
        serde_json::from_str(include_str!(
            "../../../fixtures/hsd/claims/mainnet-history-v1.json"
        ))
        .expect("HSD canonical mainnet claim fixture")
    }

    fn mainnet_replacement_fixture() -> MainnetReplacementFixture {
        serde_json::from_str(include_str!(
            "../../../fixtures/hsd/claims/mainnet-replacements-v1.json"
        ))
        .expect("HSD canonical mainnet replacement fixture")
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
    fn native_dnssec_matches_complete_hsd_historical_proof_corpus() {
        for expected in fixture().proofs {
            let mut proof = OwnershipProof::decode(&decode_hex(&expected.raw)).expect("proof");
            let reserved = crate::reserved_name(expected.name.as_bytes()).expect("reserved name");
            assert_eq!(reserved.name, expected.name.as_bytes());
            assert_eq!(reserved.target, expected.reserved_target.as_bytes());
            assert_eq!(reserved.value, expected.reserved_value);
            assert_eq!(
                proof.verify_signatures(&OpenSslDnssecVerifier),
                expected.signatures_valid,
                "{} current anchor policy",
                expected.name
            );

            proof
                .zones
                .last_mut()
                .expect("target zone")
                .claim
                .retain(|record| !is_hsd_test_claim(record));
            for expected_anchor in expected.root_anchors {
                let anchor = DnssecAnchor {
                    key_tag: expected_anchor.key_tag,
                    algorithm: expected_anchor.algorithm,
                    digest_type: expected_anchor.digest_type,
                    digest: decode_hex(&expected_anchor.digest),
                };
                assert_eq!(
                    proof.verify_signatures_with_anchors(
                        &OpenSslDnssecVerifier,
                        std::slice::from_ref(&anchor),
                    ),
                    expected_anchor.signatures_valid_with_historical_test_policy,
                    "{} {} historical anchor policy",
                    expected.name,
                    expected_anchor.name
                );

                let mut altered = proof.clone();
                let DnsRecordData::Rrsig(signature) = &mut altered.zones[0]
                    .keys
                    .last_mut()
                    .expect("root signature")
                    .data
                else {
                    panic!("root signature record");
                };
                signature.signature[0] ^= 1;
                assert!(!altered.verify_signatures_with_anchors(&OpenSslDnssecVerifier, &[anchor]));
            }
        }
    }

    #[test]
    fn gost94_ds_digests_match_hsds_pinned_bcrypto() {
        for expected in fixture().gost94_digests {
            assert_eq!(
                OpenSslDnssecVerifier.digest(3, &decode_hex(&expected.data)),
                Some(decode_hex(&expected.digest)),
                "{}",
                expected.id
            );
        }
        assert_eq!(OpenSslDnssecVerifier.digest(0, b"unsupported"), None);
        assert_eq!(OpenSslDnssecVerifier.digest(6, b"unsupported"), None);
    }

    #[test]
    fn native_claim_validation_matches_canonical_mainnet_block() {
        let fixture = mainnet_history_fixture();
        let block = Block::decode(&decode_hex(&fixture.block.raw)).expect("mainnet block");
        assert_eq!(block.encode(), decode_hex(&fixture.block.raw));
        assert_eq!(block.hash().to_hex(), fixture.block.hash);
        assert_eq!(block.transactions.len(), fixture.block.transaction_count);
        let validation = crate::validate_block_body(&block).expect("mainnet block body");
        assert_eq!(validation.base_size, fixture.block.base_size);
        assert_eq!(validation.weight, fixture.block.weight);
        assert_eq!(block.encode().len(), fixture.block.size);

        let coinbase = &block.transactions[0];
        assert_eq!(coinbase.locktime, fixture.block.height);
        assert_eq!(fixture.block.claims.len(), 2);
        for expected in fixture.block.claims {
            let proof_raw = &coinbase.inputs[expected.output_index].witness.items[0];
            let output = &coinbase.outputs[expected.output_index];
            assert_eq!(proof_raw, &decode_hex(&expected.proof_raw));
            assert_eq!(output.value, expected.output_value);

            let verified = verify_claim_output(
                proof_raw,
                output,
                fixture.block.height,
                fixture.canonical_context.parent_time,
                Network::Mainnet,
                ClaimFlags { hardened: false },
                &OpenSslDnssecVerifier,
            )
            .expect("canonical mainnet claim");
            assert_eq!(verified.name, expected.name.as_bytes());
            assert_eq!(verified.name_hash.to_hex(), expected.name_hash);
            assert_eq!(verified.weak, expected.weak);
            assert_eq!(
                verified.commit_hash.to_vec(),
                decode_hex(&expected.commit_hash)
            );
            assert_eq!(verified.commit_height, expected.commit_height);
            assert_eq!(verified.value, expected.reserved_value);
            assert_eq!(verified.fee, expected.fee);
            assert_eq!(verified.conjured, expected.conjured);
            assert_eq!(output.address.version, expected.version);
            assert_eq!(output.address.hash, decode_hex(&expected.address));
            let proof = OwnershipProof::decode(proof_raw).expect("ownership proof");
            assert_eq!(
                proof.target().expect("claim target").to_ascii_fqdn(),
                Some(expected.target)
            );

            assert!(matches!(
                verify_claim_output(
                    proof_raw,
                    output,
                    fixture.block.height,
                    fixture.canonical_context.parent_median_time,
                    Network::Mainnet,
                    ClaimFlags { hardened: false },
                    &OpenSslDnssecVerifier,
                ),
                Err(ClaimConsensusError::InvalidTime)
            ));
            assert!(matches!(
                verify_claim_output(
                    proof_raw,
                    output,
                    fixture.block.height,
                    fixture.canonical_context.parent_time,
                    Network::Mainnet,
                    ClaimFlags { hardened: true },
                    &OpenSslDnssecVerifier,
                ),
                Err(ClaimConsensusError::WeakDisabled)
            ));

            let mut altered = proof;
            let DnsRecordData::Rrsig(signature) = &mut altered.zones[0]
                .keys
                .last_mut()
                .expect("root signature")
                .data
            else {
                panic!("root signature record");
            };
            signature.signature[0] ^= 1;
            let altered_raw = altered.encode().expect("altered ownership proof");
            assert!(matches!(
                verify_claim_output(
                    &altered_raw,
                    output,
                    fixture.block.height,
                    fixture.canonical_context.parent_time,
                    Network::Mainnet,
                    ClaimFlags { hardened: false },
                    &OpenSslDnssecVerifier,
                ),
                Err(ClaimConsensusError::InvalidSignatures)
            ));
        }
    }

    #[test]
    fn native_claim_validation_matches_canonical_mainnet_replacements() {
        let fixture = mainnet_replacement_fixture();
        let expected = fixture
            .blocks
            .into_iter()
            .find(|block| block.role == "replacement")
            .expect("replacement block");
        let context = fixture
            .canonical_context
            .blocks
            .into_iter()
            .find(|context| context.block_height == expected.height)
            .expect("replacement context");
        let block = Block::decode(&decode_hex(&expected.raw)).expect("replacement block");
        assert_eq!(block.encode(), decode_hex(&expected.raw));
        assert_eq!(block.hash().to_hex(), expected.hash);
        assert_eq!(block.transactions.len(), expected.transaction_count);
        let validation = crate::validate_block_body(&block).expect("replacement block body");
        assert_eq!(validation.base_size, expected.base_size);
        assert_eq!(validation.weight, expected.weight);
        assert_eq!(block.encode().len(), expected.size);

        let coinbase = &block.transactions[0];
        assert_eq!(coinbase.locktime, expected.height);
        assert_eq!(expected.claims.len(), 10);
        for claim in expected.claims {
            let proof_raw = &coinbase.inputs[claim.output_index].witness.items[0];
            let output = &coinbase.outputs[claim.output_index];
            assert_eq!(proof_raw, &decode_hex(&claim.proof_raw));
            assert_eq!(output.value, claim.output_value);

            let verified = verify_claim_output(
                proof_raw,
                output,
                expected.height,
                context.parent_time,
                Network::Mainnet,
                ClaimFlags { hardened: false },
                &OpenSslDnssecVerifier,
            )
            .expect("canonical replacement claim");
            assert_eq!(verified.name, claim.name.as_bytes());
            assert_eq!(verified.name_hash.to_hex(), claim.name_hash);
            assert_eq!(verified.weak, claim.weak);
            assert_eq!(
                verified.commit_hash.to_vec(),
                decode_hex(&claim.commit_hash)
            );
            assert_eq!(verified.commit_height, 2);
            assert_eq!(verified.value, claim.reserved_value);
            assert_eq!(verified.fee, claim.fee);
            assert_eq!(verified.conjured, claim.output_value);
            assert_eq!(claim.conjured, claim.output_value);
            assert_eq!(output.address.version, claim.version);
            assert_eq!(output.address.hash, decode_hex(&claim.address));
            let proof = OwnershipProof::decode(proof_raw).expect("replacement ownership proof");
            assert_eq!(
                proof.target().expect("replacement target").to_ascii_fqdn(),
                Some(claim.target)
            );
        }
    }

    #[test]
    fn native_claim_validation_matches_terminal_and_third_generation_history() {
        let fixture = mainnet_replacement_fixture();
        assert_eq!(fixture.schema, 2);
        assert_eq!(
            fixture.lifecycle.claim_period_height,
            Network::Mainnet.params().names.claim_period
        );
        assert_eq!(fixture.lifecycle.lineage.name, "mylinksfree");
        assert_eq!(fixture.lifecycle.lineage.points.len(), 3);
        assert_eq!(
            fixture
                .lifecycle
                .lineage
                .points
                .iter()
                .map(|point| point.commit_height)
                .collect::<Vec<_>>(),
            vec![1, 2, 3]
        );

        let verify_point = |name: &str, name_hash: &str, point: &MainnetClaimPointFixture| {
            let expected_block = fixture
                .blocks
                .iter()
                .find(|block| block.height == point.block_height)
                .expect("claim lifecycle block");
            let context = fixture
                .canonical_context
                .blocks
                .iter()
                .find(|context| context.block_height == point.block_height)
                .expect("claim lifecycle context");
            let expected_claim = expected_block
                .claims
                .iter()
                .find(|claim| claim.output_index == point.output_index && claim.name == name)
                .expect("claim lifecycle output");
            let block =
                Block::decode(&decode_hex(&expected_block.raw)).expect("claim lifecycle block");
            assert_eq!(block.hash().to_hex(), expected_block.hash);
            assert_eq!(block.transactions.len(), expected_block.transaction_count);
            let validation = crate::validate_block_body(&block).expect("claim lifecycle body");
            assert_eq!(validation.base_size, expected_block.base_size);
            assert_eq!(validation.weight, expected_block.weight);
            assert_eq!(block.encode().len(), expected_block.size);

            let coinbase = &block.transactions[0];
            assert_eq!(coinbase.locktime, point.block_height);
            assert_eq!(coinbase.txid().to_hex(), point.coinbase_txid);
            let proof_raw = &coinbase.inputs[point.output_index].witness.items[0];
            let output = &coinbase.outputs[point.output_index];
            assert_eq!(proof_raw, &decode_hex(&expected_claim.proof_raw));
            assert_eq!(output.value, point.output_value);
            assert_eq!(point.output_value, expected_claim.output_value);
            assert_eq!(point.reserved_value, expected_claim.reserved_value);
            assert_eq!(point.fee, expected_claim.fee);
            assert_eq!(point.commit_hash, expected_claim.commit_hash);
            assert_eq!(point.commit_height, expected_claim.commit_height);
            assert_eq!(point.weak, expected_claim.weak);
            assert_eq!(point.conjured, expected_claim.conjured);

            let verified = verify_claim_output(
                proof_raw,
                output,
                point.block_height,
                context.parent_time,
                Network::Mainnet,
                ClaimFlags { hardened: false },
                &OpenSslDnssecVerifier,
            )
            .expect("canonical lifecycle claim");
            assert_eq!(verified.name, name.as_bytes());
            assert_eq!(verified.name_hash.to_hex(), expected_claim.name_hash);
            assert_eq!(verified.name_hash.to_hex(), name_hash);
            assert_eq!(
                verified.commit_hash.to_vec(),
                decode_hex(&point.commit_hash)
            );
            assert_eq!(verified.commit_height, point.commit_height);
            assert_eq!(verified.value, point.reserved_value);
            assert_eq!(verified.fee, point.fee);
            assert_eq!(verified.conjured, point.conjured);
        };

        for point in &fixture.lifecycle.lineage.points {
            verify_point(
                &fixture.lifecycle.lineage.name,
                &fixture.lifecycle.lineage.name_hash,
                point,
            );
        }
        assert!(fixture.lifecycle.lineage.points[1..]
            .iter()
            .all(|point| point.output_value == fixture.lifecycle.lineage.points[0].output_value));
        assert!(fixture.lifecycle.lineage.points[1..]
            .iter()
            .all(|point| point.conjured == point.output_value));

        let terminal = &fixture.lifecycle.terminal;
        assert_eq!(terminal.name, "vcel");
        assert_eq!(terminal.blocks_before_claim_period, 3);
        assert_eq!(
            terminal.point.block_height + terminal.blocks_before_claim_period,
            fixture.lifecycle.claim_period_height
        );
        verify_point(&terminal.name, &terminal.name_hash, &terminal.point);

        let terminal_block = fixture
            .blocks
            .iter()
            .find(|block| block.height == terminal.point.block_height)
            .expect("terminal claim block");
        let terminal_decoded =
            Block::decode(&decode_hex(&terminal_block.raw)).expect("terminal claim block");
        let proof_raw = &terminal_decoded.transactions[0].inputs[terminal.point.output_index]
            .witness
            .items[0];
        let mut output =
            terminal_decoded.transactions[0].outputs[terminal.point.output_index].clone();
        output.covenant.items[1] = fixture.lifecycle.claim_period_height.to_le_bytes().to_vec();
        assert!(matches!(
            verify_claim_output(
                proof_raw,
                &output,
                fixture.lifecycle.claim_period_height,
                fixture.lifecycle.boundary.parent_time,
                Network::Mainnet,
                ClaimFlags { hardened: false },
                &OpenSslDnssecVerifier,
            ),
            Err(ClaimConsensusError::NotReserved)
        ));

        let boundary = &fixture.lifecycle.boundary;
        assert_eq!(boundary.block_height, fixture.lifecycle.claim_period_height);
        assert_eq!(boundary.claim_count, 0);
        let boundary_coinbase =
            Transaction::decode(&decode_hex(&boundary.coinbase_raw)).expect("boundary coinbase");
        assert_eq!(boundary_coinbase.locktime, boundary.block_height);
        assert_eq!(boundary_coinbase.txid().to_hex(), boundary.coinbase_txid);
        assert!(boundary_coinbase
            .outputs
            .iter()
            .all(|output| output.covenant.kind != CovenantKind::Claim));
        assert_eq!(terminal.name_hash, terminal_block.claims[0].name_hash);
        assert_eq!(boundary.block_hash.len(), 64);
    }
}
