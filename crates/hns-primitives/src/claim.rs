use serde::{Deserialize, Serialize};

use crate::{blake2b_256, PrimitiveError, Reader, Writer};

pub const MAX_OWNERSHIP_PROOF_SIZE: usize = 10_000;
pub const MAX_CLAIM_ENVELOPE_SIZE: usize = MAX_OWNERSHIP_PROOF_SIZE + 2;
pub const MAX_OWNERSHIP_CLAIM_DATA_SIZE: usize = 1 + 1 + 40 + 9 + 32 + 4 + 4;

const MAX_MONEY: u64 = 2_040_000_000 * 1_000_000;
const MAX_SAFE_INTEGER: u64 = (1u64 << 53) - 1;
const BASE32_ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";

/// HSD's inventory/mempool Claim wrapper. The blob is the complete DNSSEC
/// OwnershipProof wire payload; parsing and authenticating its DNS records is
/// a separate consensus layer.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    pub blob: Vec<u8>,
}

impl Claim {
    pub fn decode(raw: &[u8]) -> Result<Self, ClaimError> {
        if raw.len() > MAX_CLAIM_ENVELOPE_SIZE {
            return Err(ClaimError::EnvelopeTooLarge(raw.len()));
        }
        let mut reader = Reader::new(raw, MAX_CLAIM_ENVELOPE_SIZE)?;
        let size = usize::from(reader.read_u16()?);
        if size > MAX_OWNERSHIP_PROOF_SIZE {
            return Err(ClaimError::ProofTooLarge(size));
        }
        let blob = reader.read_vec(size)?;
        reader.ensure_finished()?;
        Ok(Self { blob })
    }

    pub fn encode(&self) -> Result<Vec<u8>, ClaimError> {
        if self.blob.len() > MAX_OWNERSHIP_PROOF_SIZE {
            return Err(ClaimError::ProofTooLarge(self.blob.len()));
        }
        let size = u16::try_from(self.blob.len())
            .map_err(|_| ClaimError::ProofTooLarge(self.blob.len()))?;
        let mut writer = Writer::with_capacity(2 + self.blob.len());
        writer.write_u16(size);
        writer.write_bytes(&self.blob);
        Ok(writer.finish())
    }

    /// HSD identifies a Claim by BLAKE2b-256 of the ownership-proof blob,
    /// excluding the two-byte envelope length.
    pub fn hash(&self) -> [u8; 32] {
        blake2b_256(&self.blob)
    }
}

/// The checksummed binary value carried after a network's `hns-*:` TXT
/// prefix. Reserved-name lookup and proof-derived target/time/weakness fields
/// are deliberately outside this codec.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OwnershipClaimData {
    pub version: u8,
    pub address: Vec<u8>,
    pub fee: u64,
    pub commit_hash: [u8; 32],
    pub commit_height: u32,
}

impl OwnershipClaimData {
    pub fn decode(raw: &[u8]) -> Result<Self, ClaimError> {
        if raw.len() > MAX_OWNERSHIP_CLAIM_DATA_SIZE {
            return Err(ClaimError::DataTooLarge(raw.len()));
        }
        if raw.len() < 4 {
            return Err(ClaimError::Checksum);
        }
        let body_len = raw.len() - 4;
        let expected = blake2b_256(&raw[..body_len]);
        if raw[body_len..] != expected[..4] {
            return Err(ClaimError::Checksum);
        }

        let mut reader = Reader::new(&raw[..body_len], MAX_OWNERSHIP_CLAIM_DATA_SIZE - 4)?;
        let version = reader.read_u8()?;
        if version > 31 {
            return Err(ClaimError::AddressVersion(version));
        }
        let address_len = usize::from(reader.read_u8()?);
        if !(2..=40).contains(&address_len) {
            return Err(ClaimError::AddressLength(address_len));
        }
        let address = reader.read_vec(address_len)?;
        let fee = reader.read_varint()?;
        if fee > MAX_SAFE_INTEGER {
            return Err(ClaimError::UnsafeInteger(fee));
        }
        if fee > MAX_MONEY {
            return Err(ClaimError::FeeExceedsMaxMoney(fee));
        }
        let commit_hash = reader.read_hash()?;
        let commit_height = reader.read_u32()?;
        reader.ensure_finished()?;

        Ok(Self {
            version,
            address,
            fee,
            commit_hash,
            commit_height,
        })
    }

    pub fn encode(&self) -> Result<Vec<u8>, ClaimError> {
        if self.version > 31 {
            return Err(ClaimError::AddressVersion(self.version));
        }
        if !(2..=40).contains(&self.address.len()) {
            return Err(ClaimError::AddressLength(self.address.len()));
        }
        if self.fee > MAX_SAFE_INTEGER {
            return Err(ClaimError::UnsafeInteger(self.fee));
        }
        if self.fee > MAX_MONEY {
            return Err(ClaimError::FeeExceedsMaxMoney(self.fee));
        }

        let mut writer = Writer::with_capacity(MAX_OWNERSHIP_CLAIM_DATA_SIZE);
        writer.write_u8(self.version);
        writer.write_u8(self.address.len() as u8);
        writer.write_bytes(&self.address);
        writer.write_varint(self.fee);
        writer.write_bytes(&self.commit_hash);
        writer.write_u32(self.commit_height);
        let mut raw = writer.finish();
        let checksum = blake2b_256(&raw);
        raw.extend_from_slice(&checksum[..4]);
        Ok(raw)
    }

    pub fn decode_txt(txt: &str, prefix: &str) -> Result<Self, ClaimError> {
        let encoded = txt.strip_prefix(prefix).ok_or(ClaimError::ClaimPrefix)?;
        Self::decode(&decode_base32(encoded)?)
    }

    pub fn encode_txt(&self, prefix: &str) -> Result<String, ClaimError> {
        if prefix.is_empty() {
            return Err(ClaimError::ClaimPrefix);
        }
        Ok(format!("{prefix}{}", encode_base32(&self.encode()?)))
    }
}

fn encode_base32(raw: &[u8]) -> String {
    let mut output = String::with_capacity((raw.len() * 8).div_ceil(5));
    let mut bits = 0usize;
    let mut value = 0u32;
    for byte in raw {
        value = (value << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(BASE32_ALPHABET[((value >> bits) & 31) as usize] as char);
        }
        value &= (1u32 << bits).wrapping_sub(1);
    }
    if bits != 0 {
        output.push(BASE32_ALPHABET[((value << (5 - bits)) & 31) as usize] as char);
    }
    output
}

fn decode_base32(encoded: &str) -> Result<Vec<u8>, ClaimError> {
    let first_padding = encoded.find('=').unwrap_or(encoded.len());
    if !encoded.as_bytes()[first_padding..]
        .iter()
        .all(|byte| *byte == b'=')
    {
        return Err(ClaimError::Base32);
    }
    let core = &encoded[..first_padding];
    let remainder = core.len() & 7;
    if !matches!(remainder, 0 | 2 | 4 | 5 | 7) {
        return Err(ClaimError::Base32);
    }
    let padding = encoded.len() - first_padding;
    let required_padding = match remainder {
        0 => 0,
        2 => 6,
        4 => 4,
        5 => 3,
        7 => 1,
        _ => unreachable!(),
    };
    if padding != 0 && (padding != required_padding || encoded.len() & 7 != 0) {
        return Err(ClaimError::Base32);
    }

    let mut output = Vec::with_capacity(core.len() * 5 / 8);
    let mut bits = 0usize;
    let mut value = 0u32;
    for byte in core.bytes() {
        let digit = match byte {
            b'a'..=b'z' => byte - b'a',
            b'A'..=b'Z' => byte - b'A',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return Err(ClaimError::Base32),
        };
        value = (value << 5) | u32::from(digit);
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push(((value >> bits) & 0xff) as u8);
            value &= (1u32 << bits).wrapping_sub(1);
        }
    }
    if value != 0 {
        return Err(ClaimError::Base32);
    }
    Ok(output)
}

#[derive(Debug, thiserror::Error)]
pub enum ClaimError {
    #[error("claim codec failed: {0}")]
    Codec(#[from] PrimitiveError),
    #[error("claim envelope exceeds {MAX_CLAIM_ENVELOPE_SIZE} bytes: {0}")]
    EnvelopeTooLarge(usize),
    #[error("ownership proof exceeds {MAX_OWNERSHIP_PROOF_SIZE} bytes: {0}")]
    ProofTooLarge(usize),
    #[error("ownership claim data exceeds {MAX_OWNERSHIP_CLAIM_DATA_SIZE} bytes: {0}")]
    DataTooLarge(usize),
    #[error("ownership claim checksum mismatch")]
    Checksum,
    #[error("ownership claim address version {0} exceeds 31")]
    AddressVersion(u8),
    #[error("ownership claim address length {0} is outside 2..=40")]
    AddressLength(usize),
    #[error("ownership claim fee {0} exceeds JavaScript's exact integer range")]
    UnsafeInteger(u64),
    #[error("ownership claim fee {0} exceeds HNS MAX_MONEY")]
    FeeExceedsMaxMoney(u64),
    #[error("ownership claim TXT prefix does not match the selected network")]
    ClaimPrefix,
    #[error("invalid ownership claim base32 payload")]
    Base32,
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    struct Fixture {
        #[serde(rename = "knownRegtest")]
        known_regtest: FixtureKnownData,
        claims: Vec<FixtureClaim>,
        data: Vec<FixtureData>,
        #[serde(rename = "claimDecodeMutations")]
        claim_decode_mutations: Vec<FixtureMutation>,
        #[serde(rename = "dataDecodeMutations")]
        data_decode_mutations: Vec<FixtureMutation>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FixtureKnownData {
        txt: String,
        version: u8,
        address: String,
        fee: u64,
        commit_hash: String,
        commit_height: u32,
    }

    #[derive(Deserialize)]
    struct FixtureClaim {
        id: String,
        blob: String,
        raw: String,
        hash: String,
        size: usize,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FixtureData {
        network: String,
        prefix: String,
        txt: String,
        raw: String,
        version: u8,
        address: String,
        fee: u64,
        commit_hash: String,
        commit_height: u32,
    }

    #[derive(Deserialize)]
    struct FixtureMutation {
        id: String,
        raw: String,
        accepted: bool,
    }

    fn fixture() -> Fixture {
        serde_json::from_str(include_str!("../../../fixtures/hsd/claims/codec-v1.json"))
            .expect("HSD claim fixture")
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]))
            .collect()
    }

    fn hex_nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            b'A'..=b'F' => value - b'A' + 10,
            _ => panic!("invalid hexadecimal digit"),
        }
    }

    fn assert_data(expected: &FixtureData, data: &OwnershipClaimData) {
        assert_eq!(data.version, expected.version, "{}", expected.network);
        assert_eq!(
            data.address,
            decode_hex(&expected.address),
            "{}",
            expected.network
        );
        assert_eq!(data.fee, expected.fee, "{}", expected.network);
        assert_eq!(
            data.commit_hash.as_slice(),
            decode_hex(&expected.commit_hash)
        );
        assert_eq!(
            data.commit_height, expected.commit_height,
            "{}",
            expected.network
        );
    }

    #[test]
    fn claim_envelope_and_hash_match_hsd() {
        for expected in fixture().claims {
            let raw = decode_hex(&expected.raw);
            let claim = Claim::decode(&raw).expect("fixture claim");
            assert_eq!(claim.blob, decode_hex(&expected.blob), "{}", expected.id);
            assert_eq!(
                claim.encode().expect("claim encoding"),
                raw,
                "{}",
                expected.id
            );
            assert_eq!(
                claim.hash().as_slice(),
                decode_hex(&expected.hash),
                "{}",
                expected.id
            );
            assert_eq!(raw.len(), expected.size, "{}", expected.id);
        }
    }

    #[test]
    fn ownership_txt_data_matches_every_hsd_network() {
        for expected in fixture().data {
            let raw = decode_hex(&expected.raw);
            let data = OwnershipClaimData::decode(&raw).expect("fixture ownership data");
            assert_data(&expected, &data);
            assert_eq!(data.encode().expect("ownership data encoding"), raw);
            assert_eq!(
                data.encode_txt(&expected.prefix).expect("ownership TXT"),
                expected.txt
            );
            let decoded = OwnershipClaimData::decode_txt(&expected.txt, &expected.prefix)
                .expect("ownership TXT decode");
            assert_eq!(decoded, data);
        }
    }

    #[test]
    fn known_hsd_regtest_ownership_txt_decodes() {
        let expected = fixture().known_regtest;
        let data = OwnershipClaimData::decode_txt(&expected.txt, "hns-regtest:")
            .expect("known HSD ownership TXT");
        assert_eq!(data.version, expected.version);
        assert_eq!(data.address, decode_hex(&expected.address));
        assert_eq!(data.fee, expected.fee);
        assert_eq!(
            data.commit_hash.as_slice(),
            decode_hex(&expected.commit_hash)
        );
        assert_eq!(data.commit_height, expected.commit_height);
    }

    #[test]
    fn malformed_claim_and_data_decode_match_hsd() {
        let expected = fixture();
        for mutation in expected.claim_decode_mutations {
            assert_eq!(
                Claim::decode(&decode_hex(&mutation.raw)).is_ok(),
                mutation.accepted,
                "{}",
                mutation.id
            );
        }
        for mutation in expected.data_decode_mutations {
            assert_eq!(
                OwnershipClaimData::decode(&decode_hex(&mutation.raw)).is_ok(),
                mutation.accepted,
                "{}",
                mutation.id
            );
        }
    }

    #[test]
    fn ownership_txt_rejects_wrong_network_and_noncanonical_base32() {
        let expected = fixture().known_regtest;
        assert!(matches!(
            OwnershipClaimData::decode_txt(&expected.txt, "hns-claim:"),
            Err(ClaimError::ClaimPrefix)
        ));
        assert!(matches!(
            OwnershipClaimData::decode_txt("hns-regtest:a", "hns-regtest:"),
            Err(ClaimError::Base32)
        ));
    }
}
