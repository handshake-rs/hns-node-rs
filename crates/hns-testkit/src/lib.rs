#![forbid(unsafe_code)]

use std::{fs, path::PathBuf};

use hns_primitives::{Block, Header, PrimitiveError, Transaction};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum FixtureCategory {
    Headers,
    Blocks,
    Transactions,
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

    pub fn path(&self, category: FixtureCategory, name: &str) -> PathBuf {
        self.root.join(category.as_dir()).join(name)
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
        let bytes = self.load_bytes(FixtureCategory::Headers, name)?;
        Header::from_raw(bytes).map_err(FixtureError::Primitive)
    }

    pub fn load_transaction(&self, name: &str) -> Result<Transaction, FixtureError> {
        let bytes = self.load_bytes(FixtureCategory::Transactions, name)?;
        Transaction::from_raw(bytes).map_err(FixtureError::Primitive)
    }

    pub fn load_block(&self, name: &str) -> Result<Block, FixtureError> {
        let bytes = self.load_bytes(FixtureCategory::Blocks, name)?;
        Block::from_raw(bytes).map_err(FixtureError::Primitive)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FixtureError {
    #[error("failed to read fixture `{path}`: {source}")]
    Read {
        path: PathBuf,
        source: std::io::Error,
    },
    #[error("failed to parse primitive fixture: {0}")]
    Primitive(PrimitiveError),
}
