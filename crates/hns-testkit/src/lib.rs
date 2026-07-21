#![forbid(unsafe_code)]

use std::{
    collections::HashSet,
    fs,
    path::{Component, Path, PathBuf},
};

use hns_primitives::{blake2b_256, Block, Header, PrimitiveError, Transaction};
use serde::{Deserialize, Serialize};

pub const HSD_FIXTURE_MANIFEST_SCHEMA: u32 = 1;

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum FixtureCategory {
    Headers,
    Blocks,
    Transactions,
    Scripts,
    Covenants,
    Resources,
    Rpc,
    NameStates,
    Chains,
    Network,
    Snapshots,
}

impl FixtureCategory {
    pub const fn as_dir(self) -> &'static str {
        match self {
            Self::Headers => "headers",
            Self::Blocks => "blocks",
            Self::Transactions => "transactions",
            Self::Scripts => "scripts",
            Self::Covenants => "covenants",
            Self::Resources => "resources",
            Self::Rpc => "rpc",
            Self::NameStates => "name-states",
            Self::Chains => "chains",
            Self::Network => "network",
            Self::Snapshots => "snapshots",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FixtureManifest {
    pub schema: u32,
    pub oracle: FixtureOracle,
    pub cases: Vec<FixtureCase>,
}

impl FixtureManifest {
    pub fn validate(&self) -> Result<(), FixtureError> {
        if self.schema != HSD_FIXTURE_MANIFEST_SCHEMA {
            return Err(FixtureError::InvalidManifest(format!(
                "unsupported fixture manifest schema {}; expected {}",
                self.schema, HSD_FIXTURE_MANIFEST_SCHEMA
            )));
        }
        self.oracle.validate()?;
        if self.cases.is_empty() {
            return Err(FixtureError::InvalidManifest(
                "fixture manifest contains no cases".to_owned(),
            ));
        }

        let mut ids = HashSet::with_capacity(self.cases.len());
        for case in &self.cases {
            case.validate()?;
            if !ids.insert(case.id.as_str()) {
                return Err(FixtureError::InvalidManifest(format!(
                    "duplicate fixture case id `{}`",
                    case.id
                )));
            }
        }

        Ok(())
    }

    pub fn validate_files(&self, root: &Path) -> Result<(), FixtureError> {
        self.validate()?;
        for case in &self.cases {
            let path = root.join(&case.path);
            if !path.is_file() {
                return Err(FixtureError::MissingFixture {
                    id: case.id.clone(),
                    path,
                });
            }

            let bytes = fs::read(&path).map_err(|source| FixtureError::Read {
                path: path.clone(),
                source,
            })?;
            let actual = encode_hex(&blake2b_256(&bytes));
            if actual != case.blake2b256 {
                return Err(FixtureError::DigestMismatch {
                    id: case.id.clone(),
                    path,
                    expected: case.blake2b256.clone(),
                    actual,
                });
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FixtureOracle {
    pub repository: String,
    pub revision: String,
}

impl FixtureOracle {
    fn validate(&self) -> Result<(), FixtureError> {
        if self.repository.trim().is_empty() {
            return Err(FixtureError::InvalidManifest(
                "oracle repository is empty".to_owned(),
            ));
        }
        if self.revision.len() != 40 || !self.revision.as_bytes().iter().all(u8::is_ascii_hexdigit)
        {
            return Err(FixtureError::InvalidManifest(
                "oracle revision must be a 40-character hexadecimal commit id".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FixtureCase {
    pub id: String,
    pub network: String,
    pub kind: FixtureKind,
    pub path: PathBuf,
    pub expectation: FixtureExpectation,
    /// BLAKE2b-256 of the exact committed fixture bytes, encoded as lowercase
    /// hexadecimal. This prevents a fixture file from drifting independently
    /// of its pinned HSD oracle metadata.
    pub blake2b256: String,
    #[serde(default)]
    pub tags: Vec<String>,
}

impl FixtureCase {
    fn validate(&self) -> Result<(), FixtureError> {
        if self.id.trim().is_empty() {
            return Err(FixtureError::InvalidManifest(
                "fixture case id is empty".to_owned(),
            ));
        }
        if self.network.trim().is_empty() {
            return Err(FixtureError::InvalidManifest(format!(
                "fixture `{}` has no network declaration",
                self.id
            )));
        }
        validate_relative_path(&self.id, &self.path)?;
        validate_digest(&self.id, &self.blake2b256)?;
        self.expectation.validate(&self.id)
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FixtureKind {
    Header,
    Transaction,
    Script,
    Covenant,
    Claim,
    Airdrop,
    Block,
    NameState,
    Urkel,
    Undo,
    Deployment,
    Difficulty,
    Reorganization,
    Resource,
    Rpc,
    Network,
    Snapshot,
    P2pWire,
    MiningTemplate,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FixtureExpectation {
    pub outcome: FixtureOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl FixtureExpectation {
    fn validate(&self, id: &str) -> Result<(), FixtureError> {
        if self.outcome == FixtureOutcome::Rejected
            && self
                .error
                .as_deref()
                .is_none_or(|error| error.trim().is_empty())
        {
            return Err(FixtureError::InvalidManifest(format!(
                "rejected fixture `{id}` must declare the oracle rejection"
            )));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FixtureOutcome {
    Reference,
    Accepted,
    Rejected,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HsdFixtureLoader {
    root: PathBuf,
}

impl HsdFixtureLoader {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn workspace_default() -> Self {
        Self::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/hsd"))
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn path(&self, category: FixtureCategory, name: &str) -> PathBuf {
        self.root.join(category.as_dir()).join(name)
    }

    pub fn load_manifest(&self, name: &str) -> Result<FixtureManifest, FixtureError> {
        let path = self.root.join(name);
        let bytes = fs::read(&path).map_err(|source| FixtureError::Read {
            path: path.clone(),
            source,
        })?;
        let manifest = serde_json::from_slice::<FixtureManifest>(&bytes).map_err(|source| {
            FixtureError::Json {
                path: path.clone(),
                source,
            }
        })?;
        manifest.validate_files(&self.root)?;
        Ok(manifest)
    }

    pub fn load_bytes(
        &self,
        category: FixtureCategory,
        name: &str,
    ) -> Result<Vec<u8>, FixtureError> {
        let path = self.path(category, name);
        fs::read(&path).map_err(|source| FixtureError::Read { path, source })
    }

    pub fn load_header(&self, name: &str) -> Result<Header, FixtureError> {
        let raw = self.load_raw_vector(FixtureCategory::Headers, name)?;
        Header::from_raw(raw).map_err(FixtureError::Primitive)
    }

    pub fn load_transaction(&self, name: &str) -> Result<Transaction, FixtureError> {
        let raw = self.load_raw_vector(FixtureCategory::Transactions, name)?;
        Transaction::from_raw(raw).map_err(FixtureError::Primitive)
    }

    pub fn load_block(&self, name: &str) -> Result<Block, FixtureError> {
        let raw = self.load_raw_vector(FixtureCategory::Blocks, name)?;
        Block::from_raw(raw).map_err(FixtureError::Primitive)
    }

    fn load_raw_vector(
        &self,
        category: FixtureCategory,
        name: &str,
    ) -> Result<Vec<u8>, FixtureError> {
        let path = self.path(category, name);
        let bytes = fs::read(&path).map_err(|source| FixtureError::Read {
            path: path.clone(),
            source,
        })?;
        let vector =
            serde_json::from_slice::<RawVector>(&bytes).map_err(|source| FixtureError::Json {
                path: path.clone(),
                source,
            })?;
        decode_hex(&vector.raw).map_err(|message| FixtureError::Hex { path, message })
    }
}

#[derive(Deserialize)]
struct RawVector {
    raw: String,
}

fn validate_relative_path(id: &str, path: &Path) -> Result<(), FixtureError> {
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err(FixtureError::InvalidManifest(format!(
            "fixture `{id}` path must be non-empty and relative"
        )));
    }
    if path.components().any(|component| {
        matches!(
            component,
            Component::ParentDir | Component::RootDir | Component::Prefix(_)
        )
    }) {
        return Err(FixtureError::InvalidManifest(format!(
            "fixture `{id}` path escapes the fixture root"
        )));
    }
    Ok(())
}

fn validate_digest(id: &str, digest: &str) -> Result<(), FixtureError> {
    if digest.len() != 64
        || !digest
            .as_bytes()
            .iter()
            .all(|byte| matches!(*byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return Err(FixtureError::InvalidManifest(format!(
            "fixture `{id}` BLAKE2b-256 digest must be 64 lowercase hexadecimal characters"
        )));
    }
    Ok(())
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(*byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(*byte & 0x0f)]));
    }
    encoded
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    if value.len() % 2 != 0 {
        return Err("hex string has odd length".to_owned());
    }

    value
        .as_bytes()
        .chunks_exact(2)
        .enumerate()
        .map(|(index, pair)| {
            let high = decode_nibble(pair[0]);
            let low = decode_nibble(pair[1]);
            match (high, low) {
                (Some(high), Some(low)) => Ok((high << 4) | low),
                _ => Err(format!("invalid hexadecimal byte at offset {}", index * 2)),
            }
        })
        .collect()
}

const fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    #[error("failed to read fixture `{path}`: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse fixture JSON `{path}`: {source}")]
    Json {
        path: PathBuf,
        source: serde_json::Error,
    },
    #[error("failed to decode fixture hex `{path}`: {message}")]
    Hex { path: PathBuf, message: String },
    #[error("fixture manifest is invalid: {0}")]
    InvalidManifest(String),
    #[error("fixture `{id}` is missing at `{path}`")]
    MissingFixture { id: String, path: PathBuf },
    #[error(
        "fixture `{id}` digest mismatch at `{path}`: expected {expected}, calculated {actual}"
    )]
    DigestMismatch {
        id: String,
        path: PathBuf,
        expected: String,
        actual: String,
    },
    #[error("failed to parse primitive fixture: {0}")]
    Primitive(PrimitiveError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn committed_manifest_is_versioned_pinned_and_complete() {
        let loader = HsdFixtureLoader::workspace_default();
        let manifest = loader
            .load_manifest("manifest-v1.json")
            .expect("fixture manifest");

        assert_eq!(manifest.schema, HSD_FIXTURE_MANIFEST_SCHEMA);
        assert_eq!(manifest.oracle.repository, "handshake-org/hsd");
        assert_eq!(manifest.oracle.revision.len(), 40);
        assert!(manifest.cases.len() >= 7);
    }

    #[test]
    fn primitive_json_vectors_decode_into_hns_types() {
        let loader = HsdFixtureLoader::workspace_default();
        let header = loader.load_header("codec-v1.json").expect("header fixture");
        let transaction = loader
            .load_transaction("codec-v1.json")
            .expect("transaction fixture");
        let block = loader.load_block("codec-v1.json").expect("block fixture");

        assert_eq!(
            header.hash().to_hex(),
            "96af952b1f233c767c183faf8efc3e1801bc75e137e218627ae16c3196abf590"
        );
        assert_eq!(
            transaction.txid().to_hex(),
            "420f91c753c7ad480b3359f47ccbcab9e058a59d15fcd5e10bec66e04a55f274"
        );
        assert_eq!(block.hash(), header.hash());
    }

    #[test]
    fn manifest_rejects_path_traversal_and_duplicate_ids() {
        let case = FixtureCase {
            id: "same".to_owned(),
            network: "agnostic".to_owned(),
            kind: FixtureKind::Header,
            path: PathBuf::from("../outside.json"),
            expectation: FixtureExpectation {
                outcome: FixtureOutcome::Reference,
                error: None,
            },
            blake2b256: "0".repeat(64),
            tags: Vec::new(),
        };
        let manifest = FixtureManifest {
            schema: HSD_FIXTURE_MANIFEST_SCHEMA,
            oracle: FixtureOracle {
                repository: "handshake-org/hsd".to_owned(),
                revision: "0".repeat(40),
            },
            cases: vec![case.clone(), case],
        };

        assert!(manifest.validate().is_err());
    }
}
