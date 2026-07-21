use serde::{Deserialize, Serialize};

use crate::{blake2b_256, blake2b_256_many, sha256, PrimitiveError, Reader, Writer};

pub const AIRDROP_CONTEXT: [u8; 32] =
    hex32("5b21ff4a0fcf78123915eaa0003d2a3e1855a9b15e3441da2ef5a4c01eaf4ff3");
pub const AIRDROP_ROOT: [u8; 32] =
    hex32("10d748eda1b9c67b94d3244e0211677618a9b4b329e896ad90431f9f48034bad");
pub const FAUCET_ROOT: [u8; 32] =
    hex32("e2c0299a1e466773516655f09a64b1e16b2579530de6c4a59ce5654dea45180f");
pub const AIRDROP_REWARD: u64 = 4_246_994_314;
pub const AIRDROP_DEPTH: usize = 18;
pub const AIRDROP_SUBDEPTH: usize = 3;
pub const AIRDROP_LEAVES: u32 = 216_199;
pub const AIRDROP_SUBLEAVES: u8 = 8;
pub const FAUCET_DEPTH: usize = 11;
pub const FAUCET_LEAVES: u32 = 1_358;
pub const AIRDROP_TREE_LEAVES: u32 = AIRDROP_LEAVES + FAUCET_LEAVES;
pub const MAX_AIRDROP_PROOF_SIZE: usize = 3_400;
pub const GOO_COMMITMENT_SIZE: usize = 256;
pub const AIRDROP_SPONSOR_FEE: u64 = 500_000_000;
pub const AIRDROP_RECIPIENT_FEE: u64 = 100_000_000;

const MAX_MONEY: u64 = 2_040_000_000 * 1_000_000;
const MAX_SAFE_INTEGER: u64 = (1u64 << 53) - 1;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AirdropKeyType {
    Rsa,
    Goo,
    P256,
    Ed25519,
    Address,
}

impl AirdropKeyType {
    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Rsa => 0,
            Self::Goo => 1,
            Self::P256 => 2,
            Self::Ed25519 => 3,
            Self::Address => 4,
        }
    }

    fn from_u8(value: u8) -> Result<Self, AirdropError> {
        match value {
            0 => Ok(Self::Rsa),
            1 => Ok(Self::Goo),
            2 => Ok(Self::P256),
            3 => Ok(Self::Ed25519),
            4 => Ok(Self::Address),
            _ => Err(AirdropError::UnknownKeyType(value)),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AirdropKey {
    Rsa {
        modulus: Vec<u8>,
        exponent: Vec<u8>,
        nonce: [u8; 32],
    },
    Goo {
        commitment: [u8; GOO_COMMITMENT_SIZE],
    },
    P256 {
        point: [u8; 33],
        nonce: [u8; 32],
    },
    Ed25519 {
        point: [u8; 32],
        nonce: [u8; 32],
    },
    Address {
        version: u8,
        address: Vec<u8>,
        value: u64,
        sponsor: bool,
    },
}

impl AirdropKey {
    pub const fn key_type(&self) -> AirdropKeyType {
        match self {
            Self::Rsa { .. } => AirdropKeyType::Rsa,
            Self::Goo { .. } => AirdropKeyType::Goo,
            Self::P256 { .. } => AirdropKeyType::P256,
            Self::Ed25519 { .. } => AirdropKeyType::Ed25519,
            Self::Address { .. } => AirdropKeyType::Address,
        }
    }

    pub const fn is_address(&self) -> bool {
        matches!(self, Self::Address { .. })
    }

    pub const fn is_goo(&self) -> bool {
        matches!(self, Self::Goo { .. })
    }

    pub fn is_weak(&self) -> bool {
        match self {
            Self::Rsa { modulus, .. } => bit_length(modulus) < 2_041,
            _ => false,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, AirdropError> {
        let mut writer = Writer::new();
        writer.write_u8(self.key_type().as_u8());
        match self {
            Self::Rsa {
                modulus,
                exponent,
                nonce,
            } => {
                let modulus_len = u16::try_from(modulus.len())
                    .map_err(|_| AirdropError::KeyFieldTooLarge("RSA modulus"))?;
                let exponent_len = u8::try_from(exponent.len())
                    .map_err(|_| AirdropError::KeyFieldTooLarge("RSA exponent"))?;
                writer.write_u16(modulus_len);
                writer.write_bytes(modulus);
                writer.write_u8(exponent_len);
                writer.write_bytes(exponent);
                writer.write_bytes(nonce);
            }
            Self::Goo { commitment } => writer.write_bytes(commitment),
            Self::P256 { point, nonce } => {
                writer.write_bytes(point);
                writer.write_bytes(nonce);
            }
            Self::Ed25519 { point, nonce } => {
                writer.write_bytes(point);
                writer.write_bytes(nonce);
            }
            Self::Address {
                version,
                address,
                value,
                sponsor,
            } => {
                if *value > MAX_SAFE_INTEGER {
                    return Err(AirdropError::UnsafeInteger("address-key value", *value));
                }
                let address_len = u8::try_from(address.len())
                    .map_err(|_| AirdropError::KeyFieldTooLarge("address"))?;
                writer.write_u8(*version);
                writer.write_u8(address_len);
                writer.write_bytes(address);
                writer.write_u64(*value);
                writer.write_u8(u8::from(*sponsor));
            }
        }
        Ok(writer.finish())
    }

    pub fn decode(raw: &[u8]) -> Result<Self, AirdropError> {
        let mut reader = Reader::new(raw, raw.len())?;
        let key_type = AirdropKeyType::from_u8(reader.read_u8()?)?;
        let key = match key_type {
            AirdropKeyType::Rsa => {
                let modulus_len = usize::from(reader.read_u16()?);
                let modulus = reader.read_vec(modulus_len)?;
                let exponent_len = usize::from(reader.read_u8()?);
                let exponent = reader.read_vec(exponent_len)?;
                let nonce = read_array::<32>(&mut reader)?;
                Self::Rsa {
                    modulus,
                    exponent,
                    nonce,
                }
            }
            AirdropKeyType::Goo => Self::Goo {
                commitment: read_array::<GOO_COMMITMENT_SIZE>(&mut reader)?,
            },
            AirdropKeyType::P256 => Self::P256 {
                point: read_array::<33>(&mut reader)?,
                nonce: read_array::<32>(&mut reader)?,
            },
            AirdropKeyType::Ed25519 => Self::Ed25519 {
                point: read_array::<32>(&mut reader)?,
                nonce: read_array::<32>(&mut reader)?,
            },
            AirdropKeyType::Address => {
                let version = reader.read_u8()?;
                let address_len = usize::from(reader.read_u8()?);
                let address = reader.read_vec(address_len)?;
                let value = reader.read_u64()?;
                if value > MAX_SAFE_INTEGER {
                    return Err(AirdropError::UnsafeInteger("address-key value", value));
                }
                let sponsor = reader.read_u8()? == 1;
                Self::Address {
                    version,
                    address,
                    value,
                    sponsor,
                }
            }
        };
        reader.ensure_finished()?;
        Ok(key)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AirdropProof {
    pub index: u32,
    pub proof: Vec<[u8; 32]>,
    pub subindex: u8,
    pub subproof: Vec<[u8; 32]>,
    pub key: Vec<u8>,
    pub version: u8,
    pub address: Vec<u8>,
    pub fee: u64,
    pub signature: Vec<u8>,
}

impl AirdropProof {
    pub fn decode(raw: &[u8]) -> Result<Self, AirdropError> {
        if raw.len() > MAX_AIRDROP_PROOF_SIZE {
            return Err(AirdropError::ProofTooLarge(raw.len()));
        }
        let mut reader = Reader::new(raw, MAX_AIRDROP_PROOF_SIZE)?;
        let index = reader.read_u32()?;
        if index >= AIRDROP_LEAVES {
            return Err(AirdropError::IndexOutOfRange(index));
        }

        let proof_count = usize::from(reader.read_u8()?);
        if proof_count > AIRDROP_DEPTH {
            return Err(AirdropError::ProofDepth(proof_count));
        }
        let mut proof = Vec::with_capacity(proof_count);
        for _ in 0..proof_count {
            proof.push(read_array::<32>(&mut reader)?);
        }

        let subindex = reader.read_u8()?;
        if subindex >= AIRDROP_SUBLEAVES {
            return Err(AirdropError::SubindexOutOfRange(subindex));
        }
        let subproof_count = usize::from(reader.read_u8()?);
        if subproof_count > AIRDROP_SUBDEPTH {
            return Err(AirdropError::SubproofDepth(subproof_count));
        }
        let mut subproof = Vec::with_capacity(subproof_count);
        for _ in 0..subproof_count {
            subproof.push(read_array::<32>(&mut reader)?);
        }

        let key = reader.read_varbytes(MAX_AIRDROP_PROOF_SIZE, "airdrop key")?;
        if key.is_empty() {
            return Err(AirdropError::EmptyKey);
        }
        let version = reader.read_u8()?;
        if version > 31 {
            return Err(AirdropError::AddressVersion(version));
        }
        let address_len = usize::from(reader.read_u8()?);
        if !(2..=40).contains(&address_len) {
            return Err(AirdropError::AddressLength(address_len));
        }
        let address = reader.read_vec(address_len)?;
        let fee = reader.read_varint()?;
        if fee > MAX_SAFE_INTEGER {
            return Err(AirdropError::UnsafeInteger("proof fee", fee));
        }
        let signature = reader.read_varbytes(MAX_AIRDROP_PROOF_SIZE, "airdrop signature")?;
        reader.ensure_finished()?;

        Ok(Self {
            index,
            proof,
            subindex,
            subproof,
            key,
            version,
            address,
            fee,
            signature,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, AirdropError> {
        self.write(false)
    }

    pub fn signature_data(&self) -> Result<Vec<u8>, AirdropError> {
        self.write(true)
    }

    fn write(&self, sighash: bool) -> Result<Vec<u8>, AirdropError> {
        if self.fee > MAX_SAFE_INTEGER {
            return Err(AirdropError::UnsafeInteger("proof fee", self.fee));
        }
        let proof_count = u8::try_from(self.proof.len())
            .map_err(|_| AirdropError::ProofDepth(self.proof.len()))?;
        let subproof_count = u8::try_from(self.subproof.len())
            .map_err(|_| AirdropError::SubproofDepth(self.subproof.len()))?;
        let address_len = u8::try_from(self.address.len())
            .map_err(|_| AirdropError::AddressLength(self.address.len()))?;
        let mut writer = Writer::new();
        if sighash {
            writer.write_bytes(&AIRDROP_CONTEXT);
        }
        writer.write_u32(self.index);
        writer.write_u8(proof_count);
        for hash in &self.proof {
            writer.write_bytes(hash);
        }
        writer.write_u8(self.subindex);
        writer.write_u8(subproof_count);
        for hash in &self.subproof {
            writer.write_bytes(hash);
        }
        writer.write_varbytes(&self.key);
        writer.write_u8(self.version);
        writer.write_u8(address_len);
        writer.write_bytes(&self.address);
        writer.write_varint(self.fee);
        if !sighash {
            writer.write_varbytes(&self.signature);
        }
        let raw = writer.finish();
        if !sighash && raw.len() > MAX_AIRDROP_PROOF_SIZE {
            return Err(AirdropError::ProofTooLarge(raw.len()));
        }
        Ok(raw)
    }

    pub fn hash(&self) -> Result<[u8; 32], AirdropError> {
        Ok(blake2b_256(&self.encode()?))
    }

    pub fn signature_hash(&self) -> Result<[u8; 32], AirdropError> {
        Ok(sha256(&self.signature_data()?))
    }

    pub fn key(&self) -> Result<AirdropKey, AirdropError> {
        AirdropKey::decode(&self.key)
    }

    /// HSD distinguishes faucet proofs by the first raw key byte even if the
    /// key itself is malformed. Preserve that ordering for sanity/error parity.
    pub fn is_address(&self) -> bool {
        self.key.first() == Some(&AirdropKeyType::Address.as_u8())
    }

    pub fn value(&self) -> u64 {
        if !self.is_address() {
            return AIRDROP_REWARD;
        }
        match self.key() {
            Ok(AirdropKey::Address { value, .. }) => value,
            _ => 0,
        }
    }

    pub fn position(&self) -> Result<u32, AirdropError> {
        let position = if self.is_address() {
            if self.index >= FAUCET_LEAVES {
                return Err(AirdropError::FaucetIndexOutOfRange(self.index));
            }
            AIRDROP_LEAVES
                .checked_add(self.index)
                .ok_or(AirdropError::PositionOverflow)?
        } else {
            self.index
        };
        if position >= AIRDROP_TREE_LEAVES {
            return Err(AirdropError::PositionOverflow);
        }
        Ok(position)
    }

    pub fn is_sane(&self) -> bool {
        if self.key.is_empty()
            || self.version > 31
            || !(2..=40).contains(&self.address.len())
            || self.value() > MAX_MONEY
            || self.fee > self.value()
        {
            return false;
        }

        if self.is_address() {
            self.subproof.is_empty()
                && self.subindex == 0
                && self.proof.len() <= FAUCET_DEPTH
                && self.index < FAUCET_LEAVES
        } else {
            self.subproof.len() <= AIRDROP_SUBDEPTH
                && self.subindex < AIRDROP_SUBLEAVES
                && self.proof.len() <= AIRDROP_DEPTH
                && self.index < AIRDROP_LEAVES
                && self
                    .encode()
                    .is_ok_and(|raw| raw.len() <= MAX_AIRDROP_PROOF_SIZE)
        }
    }

    pub fn verify_merkle(&self) -> bool {
        let leaf = blake2b_256(&self.key);
        if self.is_address() {
            derive_merkle_root(leaf, &self.proof, self.index) == FAUCET_ROOT
        } else {
            let subroot = derive_merkle_root(leaf, &self.subproof, u32::from(self.subindex));
            derive_merkle_root(subroot, &self.proof, self.index) == AIRDROP_ROOT
        }
    }

    pub fn verify_signature(
        &self,
        verifier: &dyn AirdropSignatureVerifier,
    ) -> Result<bool, AirdropError> {
        let key = self.key()?;
        if let AirdropKey::Address {
            version,
            address,
            sponsor,
            ..
        } = &key
        {
            let required_fee = if *sponsor {
                AIRDROP_SPONSOR_FEE
            } else {
                AIRDROP_RECIPIENT_FEE
            };
            return Ok(self.version == *version
                && self.address == *address
                && self.fee == required_fee
                && self.signature.is_empty());
        }
        verifier.verify(&key, &self.signature_hash()?, &self.signature)
    }

    pub fn verify(&self, verifier: &dyn AirdropSignatureVerifier) -> Result<bool, AirdropError> {
        if !self.is_sane() || !self.verify_merkle() {
            return Ok(false);
        }
        self.verify_signature(verifier)
    }
}

pub trait AirdropSignatureVerifier: Send + Sync {
    fn verify(
        &self,
        key: &AirdropKey,
        message: &[u8; 32],
        signature: &[u8],
    ) -> Result<bool, AirdropError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableAirdropSignatureVerifier;

impl AirdropSignatureVerifier for UnavailableAirdropSignatureVerifier {
    fn verify(
        &self,
        _key: &AirdropKey,
        _message: &[u8; 32],
        _signature: &[u8],
    ) -> Result<bool, AirdropError> {
        Err(AirdropError::SignatureBackendUnavailable)
    }
}

fn derive_merkle_root(mut root: [u8; 32], branch: &[[u8; 32]], mut index: u32) -> [u8; 32] {
    root = blake2b_256_many([&[0x00], root.as_slice()]);
    for hash in branch {
        root = if index & 1 != 0 {
            blake2b_256_many([&[0x01], hash.as_slice(), root.as_slice()])
        } else {
            blake2b_256_many([&[0x01], root.as_slice(), hash.as_slice()])
        };
        index >>= 1;
    }
    root
}

fn bit_length(bytes: &[u8]) -> usize {
    let Some((index, first)) = bytes.iter().enumerate().find(|(_, byte)| **byte != 0) else {
        return 0;
    };
    (bytes.len() - index - 1) * 8 + (u8::BITS - first.leading_zeros()) as usize
}

fn read_array<const N: usize>(reader: &mut Reader<'_>) -> Result<[u8; N], PrimitiveError> {
    let bytes = reader.read_vec(N)?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| PrimitiveError::InvalidLength {
            context: "airdrop fixed-width field",
            expected: N,
            actual: bytes.len(),
        })
}

const fn hex32(value: &str) -> [u8; 32] {
    let bytes = value.as_bytes();
    assert!(bytes.len() == 64);
    let mut output = [0u8; 32];
    let mut index = 0;
    while index < 32 {
        output[index] = (hex_nibble(bytes[index * 2]) << 4) | hex_nibble(bytes[index * 2 + 1]);
        index += 1;
    }
    output
}

const fn hex_nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        b'A'..=b'F' => value - b'A' + 10,
        _ => panic!("invalid hexadecimal airdrop constant"),
    }
}

#[derive(Debug, thiserror::Error)]
pub enum AirdropError {
    #[error("airdrop codec failed: {0}")]
    Codec(#[from] PrimitiveError),
    #[error("airdrop proof exceeds {MAX_AIRDROP_PROOF_SIZE} bytes: {0}")]
    ProofTooLarge(usize),
    #[error("unknown airdrop key type {0}")]
    UnknownKeyType(u8),
    #[error("airdrop {0} is too large")]
    KeyFieldTooLarge(&'static str),
    #[error("airdrop {0} value {1} exceeds JavaScript's exact integer range")]
    UnsafeInteger(&'static str, u64),
    #[error("airdrop index {0} is outside the airdrop tree")]
    IndexOutOfRange(u32),
    #[error("airdrop proof depth {0} exceeds {AIRDROP_DEPTH}")]
    ProofDepth(usize),
    #[error("airdrop subindex {0} is outside the subtree")]
    SubindexOutOfRange(u8),
    #[error("airdrop subproof depth {0} exceeds {AIRDROP_SUBDEPTH}")]
    SubproofDepth(usize),
    #[error("airdrop key is empty")]
    EmptyKey,
    #[error("airdrop address version {0} exceeds 31")]
    AddressVersion(u8),
    #[error("airdrop address length {0} is outside 2..=40")]
    AddressLength(usize),
    #[error("faucet index {0} is outside the faucet tree")]
    FaucetIndexOutOfRange(u32),
    #[error("airdrop bitfield position overflow")]
    PositionOverflow,
    #[error("airdrop signature backend is unavailable")]
    SignatureBackendUnavailable,
    #[error("airdrop signature backend failed: {0}")]
    SignatureBackendFailure(String),
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct Fixture {
        constants: FixtureConstants,
        keys: Vec<FixtureKey>,
        proofs: Vec<FixtureProof>,
        faucet: FixtureProof,
        #[serde(rename = "decodeMutations")]
        decode_mutations: Vec<DecodeMutation>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FixtureConstants {
        airdrop_root: String,
        faucet_root: String,
        tree_leaves: u32,
        airdrop_leaves: u32,
        faucet_leaves: u32,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FixtureKey {
        #[serde(rename = "type")]
        key_type: String,
        raw: String,
        weak: bool,
        is_goo: bool,
        is_address: bool,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FixtureProof {
        id: String,
        raw: String,
        hash: String,
        signature_data: String,
        signature_hash: String,
        key_raw: String,
        key_type: String,
        sane: bool,
        merkle: bool,
        signature: bool,
        verify: bool,
        position: u32,
        value: u64,
        version: u8,
        address: String,
        fee: u64,
        sponsor: bool,
    }

    #[derive(Deserialize)]
    struct DecodeMutation {
        id: String,
        raw: String,
        accepted: bool,
    }

    struct RejectSignatures;

    impl AirdropSignatureVerifier for RejectSignatures {
        fn verify(
            &self,
            _key: &AirdropKey,
            _message: &[u8; 32],
            _signature: &[u8],
        ) -> Result<bool, AirdropError> {
            Ok(false)
        }
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
            .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
            .collect()
    }

    fn key_type_name(key_type: AirdropKeyType) -> &'static str {
        match key_type {
            AirdropKeyType::Rsa => "RSA",
            AirdropKeyType::Goo => "GOO",
            AirdropKeyType::P256 => "P256",
            AirdropKeyType::Ed25519 => "ED25519",
            AirdropKeyType::Address => "ADDRESS",
        }
    }

    fn assert_proof_vector(expected: &FixtureProof) {
        let raw = decode_hex(&expected.raw);
        let proof = AirdropProof::decode(&raw)
            .unwrap_or_else(|error| panic!("{} did not decode: {error}", expected.id));
        assert_eq!(
            proof.encode().expect("proof encoding"),
            raw,
            "{}",
            expected.id
        );
        assert_eq!(
            proof.hash().expect("proof hash").as_slice(),
            decode_hex(&expected.hash),
            "{} hash",
            expected.id
        );
        assert_eq!(
            proof.signature_data().expect("signature data"),
            decode_hex(&expected.signature_data),
            "{} signature data",
            expected.id
        );
        assert_eq!(
            proof.signature_hash().expect("signature hash").as_slice(),
            decode_hex(&expected.signature_hash),
            "{} signature hash",
            expected.id
        );
        assert_eq!(
            proof.key,
            decode_hex(&expected.key_raw),
            "{} key",
            expected.id
        );
        let key = proof.key().expect("fixture key");
        assert_eq!(
            key_type_name(key.key_type()),
            expected.key_type,
            "{} key type",
            expected.id
        );
        assert_eq!(proof.is_sane(), expected.sane, "{} sanity", expected.id);
        assert_eq!(
            proof.verify_merkle(),
            expected.merkle,
            "{} merkle proof",
            expected.id
        );
        assert_eq!(
            proof
                .verify_signature(&RejectSignatures)
                .expect("fixture signature check"),
            expected.signature,
            "{} signature",
            expected.id
        );
        assert_eq!(
            proof
                .verify(&RejectSignatures)
                .expect("fixture proof check"),
            expected.verify,
            "{} full proof",
            expected.id
        );
        assert_eq!(
            proof.position().expect("fixture position"),
            expected.position,
            "{} position",
            expected.id
        );
        assert_eq!(proof.value(), expected.value, "{} value", expected.id);
        assert_eq!(proof.version, expected.version, "{} version", expected.id);
        assert_eq!(
            proof.address,
            decode_hex(&expected.address),
            "{} address",
            expected.id
        );
        assert_eq!(proof.fee, expected.fee, "{} fee", expected.id);
        let sponsor = matches!(key, AirdropKey::Address { sponsor: true, .. });
        assert_eq!(sponsor, expected.sponsor, "{} sponsor", expected.id);
    }

    #[test]
    fn constants_match_hsd() {
        let expected = fixture().constants;
        assert_eq!(AIRDROP_ROOT.as_slice(), decode_hex(&expected.airdrop_root));
        assert_eq!(FAUCET_ROOT.as_slice(), decode_hex(&expected.faucet_root));
        assert_eq!(AIRDROP_TREE_LEAVES, expected.tree_leaves);
        assert_eq!(AIRDROP_LEAVES, expected.airdrop_leaves);
        assert_eq!(FAUCET_LEAVES, expected.faucet_leaves);
    }

    #[test]
    fn key_codecs_match_hsd() {
        for expected in fixture().keys {
            let raw = decode_hex(&expected.raw);
            let key = AirdropKey::decode(&raw).expect("fixture key must decode");
            assert_eq!(key.encode().expect("fixture key must encode"), raw);
            assert_eq!(key_type_name(key.key_type()), expected.key_type);
            assert_eq!(key.is_weak(), expected.weak);
            assert_eq!(key.is_goo(), expected.is_goo);
            assert_eq!(key.is_address(), expected.is_address);
        }
    }

    #[test]
    fn proof_codecs_and_hashes_match_hsd() {
        let expected = fixture();
        for proof in &expected.proofs {
            assert_proof_vector(proof);
        }
        assert_proof_vector(&expected.faucet);
    }

    #[test]
    fn valid_hsd_faucet_proof_verifies_without_external_crypto() {
        let expected = fixture().faucet;
        let proof = AirdropProof::decode(&decode_hex(&expected.raw)).expect("faucet proof");
        assert!(proof
            .verify(&UnavailableAirdropSignatureVerifier)
            .expect("address-key proof does not need a signature backend"));
        assert_eq!(proof.position().expect("faucet position"), 216_503);
        assert_eq!(proof.value(), 8_493_988_628);
    }

    #[test]
    fn malformed_proof_decode_matches_hsd() {
        for mutation in fixture().decode_mutations {
            let accepted = AirdropProof::decode(&decode_hex(&mutation.raw)).is_ok();
            assert_eq!(accepted, mutation.accepted, "{}", mutation.id);
        }
    }

    #[test]
    fn malformed_address_key_is_fail_closed() {
        let proof = AirdropProof {
            index: 0,
            proof: Vec::new(),
            subindex: 0,
            subproof: Vec::new(),
            key: vec![AirdropKeyType::Address.as_u8()],
            version: 0,
            address: vec![0; 20],
            fee: 0,
            signature: Vec::new(),
        };
        assert!(proof.is_address());
        assert_eq!(proof.value(), 0);
        // HSD's structural sanity check classifies faucet proofs from the raw
        // type byte. Full verification still fails when the key cannot decode.
        assert!(proof.is_sane());
        assert!(proof
            .verify_signature(&UnavailableAirdropSignatureVerifier)
            .is_err());
        assert!(proof
            .verify(&UnavailableAirdropSignatureVerifier)
            .is_ok_and(|verified| !verified));
    }
}
