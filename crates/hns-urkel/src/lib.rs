#![forbid(unsafe_code)]

use hns_primitives::NameHash;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum ProofKind {
    Inclusion,
    NonInclusion,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct UrkelProof {
    pub name_hash: NameHash,
    pub kind: ProofKind,
    pub raw: Vec<u8>,
}

pub trait UrkelVerifier {
    fn verify(&self, proof: &UrkelProof, root: &[u8; 32]) -> Result<(), UrkelError>;
}

#[derive(Debug, thiserror::Error)]
pub enum UrkelError {
    #[error("urkel proof verifier is not implemented in the scaffold")]
    Unimplemented,
    #[error("invalid urkel proof: {0}")]
    InvalidProof(String),
}
