#![forbid(unsafe_code)]

use std::{collections::HashSet, fmt, str::FromStr};

use hns_primitives::{
    blake2b_256, blake2b_256_many, hash_name, Amount, Block, BlockHash, Coin, CompactTarget,
    CovenantKind, Header, Height, Outpoint, Transaction, Txid, Uint256, Witness, Writer,
    HEADER_SIZE, MAX_BLOCK_WEIGHT, MAX_RESOURCE_SIZE, MAX_SCRIPT_STACK, MAX_TX_SIZE,
};
use serde::{Deserialize, Serialize};

mod airdrop;
mod claim;
mod covenant;
mod deployment;
mod gost94;
mod locks;
mod name;
mod script;
mod sighash;

pub use airdrop::{
    verify_airdrop_output, AirdropConsensusError, AirdropFlags, NativeAirdropSignatureVerifier,
    VerifiedAirdrop,
};
pub use claim::{
    verify_claim_output, ClaimConsensusError, ClaimFlags, OpenSslDnssecVerifier, VerifiedClaim,
};
pub use covenant::{
    blind_bid, verify_transaction_covenant_links, CovenantLinkError, CovenantLinkSummary,
};
pub use deployment::{
    advance_threshold_state, compute_block_version, compute_block_version_from_state,
    deployment_state, is_hsd_historical_block, is_hsd_historical_height, threshold_state,
    verify_checkpoint, Checkpoint, Deployment, DeploymentError, DeploymentHistoryEntry,
    DeploymentId, DeploymentPeriod, DeploymentState, HistoricalScriptPolicy,
    HistoricalValidationPlan, ThresholdState,
};
pub use locks::{
    calculate_sequence_locks, verify_locktime_predicate, verify_sequence_locks,
    verify_sequence_predicate, SequenceLock, SequenceLockView,
};
pub use name::{
    has_rollout, is_locked_up, is_name_claimable, is_name_expired, is_reserved, maybe_expire_name,
    name_lifecycle, reserved_name, rollout_height, verify_and_apply_name_covenant,
    verify_renewal_commitment, NameContext, NameFlags, NameMutation, NameParams, ReservedName,
};
pub use script::{
    verify_witness_program, NativeSignatureVerifier, ScriptError, ScriptFlags, SignatureVerifier,
    UnavailableSignatureVerifier, WitnessProgramVerifier,
};
pub use sighash::{
    is_valid_signature_hash_type, signature_hash, SIGHASH_ALL, SIGHASH_ANYONE_CAN_PAY,
    SIGHASH_BASE_MASK, SIGHASH_NOINPUT, SIGHASH_NONE, SIGHASH_SINGLE, SIGHASH_SINGLE_REVERSE,
};

pub const COIN: Amount = 1_000_000;
pub const MAX_CREATORS: Amount = 102_000_000 * COIN;
pub const MAX_SPONSORS: Amount = 102_000_000 * COIN;
pub const MAX_TLD: Amount = 51_000_000 * COIN;
pub const MAX_DOMAIN: Amount = 51_000_000 * COIN;
pub const MAX_CA_NAMING: Amount = 102_000_000 * COIN;
pub const MAX_AIRDROP: Amount = 952_000_000 * COIN;
pub const MAX_INITIAL: Amount = 1_360_000_000 * COIN;
pub const MAX_SUBSIDY: Amount = 680_000_000 * COIN;
pub const MAX_MONEY: Amount = 2_040_000_000 * COIN;
pub const BASE_REWARD: Amount = 2_000 * COIN;
pub const GENESIS_REWARD: Amount = BASE_REWARD + 2_210_000;
pub const MAX_BLOCK_BASE_SIZE: usize = 1_000_000;
pub const MAX_BLOCK_SIGOPS: u32 = 80_000;
pub const MAX_BLOCK_OPENS: u32 = 300;
pub const MAX_BLOCK_UPDATES: u32 = 600;
pub const MAX_BLOCK_RENEWALS: u32 = 600;
pub const MAX_COVENANT_SIZE: usize = 585;
pub const MEDIAN_TIMESPAN: usize = 11;
pub const MAX_FUTURE_BLOCK_TIME: u64 = 2 * 60 * 60;
pub const MAX_TX_WEIGHT: usize = MAX_BLOCK_WEIGHT;
pub const WITNESS_SCALE_FACTOR: usize = 4;
pub const MAX_COINBASE_WITNESS_SIZE: usize = 1_000;
pub const MAX_COINBASE_CLAIM_WITNESS_ITEM_SIZE: usize = 10_000;
pub const LOCKTIME_FLAG: u32 = 1 << 31;
pub const LOCKTIME_MASK: u32 = LOCKTIME_FLAG - 1;
pub const LOCKTIME_GRANULARITY: u32 = 9;
pub const LOCKTIME_MULTIPLIER: u32 = 1 << LOCKTIME_GRANULARITY;
pub const SEQUENCE_DISABLE_FLAG: u32 = 1 << 31;
pub const SEQUENCE_TYPE_FLAG: u32 = 1 << 22;
pub const SEQUENCE_GRANULARITY: u32 = 9;
pub const SEQUENCE_MASK: u32 = 0x0000_ffff;
pub const MAX_SCRIPT_SIZE: usize = 10_000;
pub const MAX_SCRIPT_PUSH: usize = 520;
pub const MAX_SCRIPT_OPS: usize = 201;
pub const MAX_MULTISIG_PUBKEYS: usize = 20;

pub const fn block_subsidy(height: Height, halving_interval: u32) -> Amount {
    assert!(halving_interval != 0);
    let halvings = height / halving_interval;
    if halvings >= 52 {
        0
    } else {
        BASE_REWARD >> halvings
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    #[default]
    Mainnet,
    Testnet,
    Regtest,
    Simnet,
}

impl fmt::Display for Network {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Regtest => "regtest",
            Self::Simnet => "simnet",
        };
        formatter.write_str(name)
    }
}

impl Network {
    /// Stable HNS network discriminator used by durable node metadata and
    /// native mining identities. This matches MeshMine's 0..=3 network map.
    pub const fn canonical_id(self) -> u8 {
        match self {
            Self::Mainnet => 0,
            Self::Testnet => 1,
            Self::Regtest => 2,
            Self::Simnet => 3,
        }
    }

    pub const fn from_canonical_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(Self::Mainnet),
            1 => Some(Self::Testnet),
            2 => Some(Self::Regtest),
            3 => Some(Self::Simnet),
            _ => None,
        }
    }

    pub const fn claim_prefix(self) -> &'static str {
        match self {
            Self::Mainnet => "hns-claim:",
            Self::Testnet => "hns-testnet:",
            Self::Regtest => "hns-regtest:",
            Self::Simnet => "hns-simnet:",
        }
    }

    pub const fn params(self) -> NetworkParams {
        match self {
            Self::Mainnet => NetworkParams {
                network_id: 0,
                packet_magic: 0x5b6e_f2d3,
                port: 12_038,
                brontide_port: 44_806,
                halving_interval: 170_000,
                coinbase_maturity: 100,
                goosig_stop: 56_880,
                deflation_height: 61_043,
                activation_threshold: 1_916,
                miner_window: 2_016,
                block: BlockRetentionParams {
                    prune_after_height: 1_000,
                    keep_blocks: 288,
                },
                names: NameParams {
                    auction_start: 2_016,
                    rollout_interval: 1_008,
                    lockup_period: 4_320,
                    renewal_window: 105_120,
                    renewal_period: 26_208,
                    renewal_maturity: 4_320,
                    claim_period: 210_240,
                    alexa_lockup_period: 420_480,
                    claim_frequency: 288,
                    bidding_period: 720,
                    reveal_period: 1_440,
                    tree_interval: 36,
                    transfer_lockup: 288,
                    auction_maturity: 4_176,
                    no_rollout: false,
                    no_reserved: false,
                },
                pow: PowParams {
                    limit: hex32(
                        "0000000000ffff00000000000000000000000000000000000000000000000000",
                    ),
                    bits: 0x1c00_ffff,
                    target_window: 144,
                    target_spacing: 600,
                    target_timespan: 86_400,
                    minimum_actual_timespan: 21_600,
                    maximum_actual_timespan: 345_600,
                    target_reset: false,
                    no_retargeting: false,
                },
                genesis_hash: BlockHash::new(hex32(
                    "5b6ef2d3c1f3cdcadfd9a030ba1811efdd17740f14e166489760741d075992e0",
                )),
                genesis_time: 1_580_745_078,
            },
            Self::Testnet => NetworkParams {
                network_id: 1,
                packet_magic: 0xb152_0dd2,
                port: 13_038,
                brontide_port: 45_806,
                halving_interval: 170_000,
                coinbase_maturity: 100,
                goosig_stop: 2_880,
                deflation_height: 0,
                activation_threshold: 1_512,
                miner_window: 2_016,
                block: BlockRetentionParams {
                    prune_after_height: 1_000,
                    keep_blocks: 10_000,
                },
                names: NameParams {
                    auction_start: 36,
                    rollout_interval: 36,
                    lockup_period: 36,
                    renewal_window: 4_320,
                    renewal_period: 1_008,
                    renewal_maturity: 144,
                    claim_period: 12_960,
                    alexa_lockup_period: 25_920,
                    claim_frequency: 288,
                    bidding_period: 144,
                    reveal_period: 288,
                    tree_interval: 36,
                    transfer_lockup: 288,
                    auction_maturity: 1_008,
                    no_rollout: false,
                    no_reserved: false,
                },
                pow: PowParams {
                    limit: hex32(
                        "00000000ffff0000000000000000000000000000000000000000000000000000",
                    ),
                    bits: 0x1d00_ffff,
                    target_window: 144,
                    target_spacing: 600,
                    target_timespan: 86_400,
                    minimum_actual_timespan: 21_600,
                    maximum_actual_timespan: 345_600,
                    target_reset: true,
                    no_retargeting: false,
                },
                genesis_hash: BlockHash::new(hex32(
                    "b1520dd24372f82ec94ebf8cf9d9b037d419c4aa3575d05dec70aedd1b427901",
                )),
                genesis_time: 1_580_745_079,
            },
            Self::Regtest => NetworkParams {
                network_id: 2,
                packet_magic: 0xae38_95cf,
                port: 14_038,
                brontide_port: 46_806,
                halving_interval: 2_500,
                coinbase_maturity: 2,
                goosig_stop: u32::MAX,
                deflation_height: 200,
                activation_threshold: 108,
                miner_window: 144,
                block: BlockRetentionParams {
                    prune_after_height: 1_000,
                    keep_blocks: 10_000,
                },
                names: NameParams {
                    auction_start: 0,
                    rollout_interval: 2,
                    lockup_period: 2,
                    renewal_window: 5_000,
                    renewal_period: 2_500,
                    renewal_maturity: 50,
                    claim_period: 250_000,
                    alexa_lockup_period: 500_000,
                    claim_frequency: 0,
                    bidding_period: 5,
                    reveal_period: 10,
                    tree_interval: 5,
                    transfer_lockup: 10,
                    auction_maturity: 65,
                    no_rollout: false,
                    no_reserved: false,
                },
                pow: PowParams {
                    limit: hex32(
                        "7fffff0000000000000000000000000000000000000000000000000000000000",
                    ),
                    bits: 0x207f_ffff,
                    target_window: 144,
                    target_spacing: 600,
                    target_timespan: 86_400,
                    minimum_actual_timespan: 21_600,
                    maximum_actual_timespan: 345_600,
                    target_reset: true,
                    no_retargeting: true,
                },
                genesis_hash: BlockHash::new(hex32(
                    "ae3895cf597eff05b19e02a70ceeeecb9dc72dbfe6504a50e9343a72f06a87c5",
                )),
                genesis_time: 1_580_745_080,
            },
            Self::Simnet => NetworkParams {
                network_id: 3,
                packet_magic: 0x0e64_8edc,
                port: 15_038,
                brontide_port: 47_806,
                halving_interval: 170_000,
                coinbase_maturity: 6,
                goosig_stop: u32::MAX,
                deflation_height: 0,
                activation_threshold: 75,
                miner_window: 100,
                block: BlockRetentionParams {
                    prune_after_height: 1_000,
                    keep_blocks: 10_000,
                },
                names: NameParams {
                    auction_start: 0,
                    rollout_interval: 1,
                    lockup_period: 1,
                    renewal_window: 2_500,
                    renewal_period: 1_250,
                    renewal_maturity: 25,
                    claim_period: 75_000,
                    alexa_lockup_period: 150_000,
                    claim_frequency: 0,
                    bidding_period: 25,
                    reveal_period: 50,
                    tree_interval: 2,
                    transfer_lockup: 5,
                    auction_maturity: 100,
                    no_rollout: false,
                    no_reserved: false,
                },
                pow: PowParams {
                    limit: hex32(
                        "7fffff0000000000000000000000000000000000000000000000000000000000",
                    ),
                    bits: 0x207f_ffff,
                    target_window: 144,
                    target_spacing: 600,
                    target_timespan: 86_400,
                    minimum_actual_timespan: 21_600,
                    maximum_actual_timespan: 345_600,
                    target_reset: false,
                    no_retargeting: false,
                },
                genesis_hash: BlockHash::new(hex32(
                    "0e648edc9cddb179014658061ea3f666a45cf44881877ae506e6babefbef6992",
                )),
                genesis_time: 1_580_745_081,
            },
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PowParams {
    pub limit: [u8; 32],
    pub bits: u32,
    pub target_window: u32,
    pub target_spacing: u32,
    pub target_timespan: u32,
    pub minimum_actual_timespan: u32,
    pub maximum_actual_timespan: u32,
    pub target_reset: bool,
    pub no_retargeting: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockRetentionParams {
    pub prune_after_height: Height,
    pub keep_blocks: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NetworkParams {
    pub network_id: u8,
    pub packet_magic: u32,
    pub port: u16,
    pub brontide_port: u16,
    pub halving_interval: u32,
    pub coinbase_maturity: u32,
    pub goosig_stop: Height,
    pub deflation_height: Height,
    pub activation_threshold: u32,
    pub miner_window: u32,
    pub block: BlockRetentionParams,
    pub names: NameParams,
    pub pow: PowParams,
    pub genesis_hash: BlockHash,
    pub genesis_time: u64,
}

impl NetworkParams {
    pub fn genesis_header(self) -> Header {
        Header {
            time: self.genesis_time,
            merkle_root: hex32("8e4c9756fef2ad10375f360e0560fcc7587eb5223ddf8cd7c7e06e60a1140b15"),
            witness_root: hex32("1a2c60b9439206938f8d7823782abdb8b211a57431e9c9b6a6365d8d42893351"),
            bits: self.pow.bits,
            ..Header::default()
        }
    }

    pub const fn block_subsidy(self, height: Height) -> Amount {
        block_subsidy(height, self.halving_interval)
    }

    /// Maximum protocol reward before transaction fees and any independently
    /// verified claim or airdrop issuance. Handshake's genesis coinbase carries
    /// the fixed genesis reward; later blocks follow the halving schedule.
    pub const fn block_reward(self, height: Height) -> Amount {
        if height == 0 {
            GENESIS_REWARD
        } else {
            self.block_subsidy(height)
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DifficultyPoint {
    pub height: Height,
    pub time: u64,
    pub bits: u32,
    pub chainwork: Uint256,
}

pub fn expected_next_bits(
    pow: PowParams,
    next_time: u64,
    previous: DifficultyPoint,
    first_suitable: Option<DifficultyPoint>,
    last_suitable: Option<DifficultyPoint>,
) -> Result<u32, ConsensusError> {
    if pow.no_retargeting {
        return Ok(pow.bits);
    }
    if pow.target_reset
        && next_time
            > previous
                .time
                .saturating_add(u64::from(pow.target_spacing).saturating_mul(2))
    {
        return Ok(pow.bits);
    }
    if previous.height < pow.target_window.saturating_add(2) {
        if previous.bits != pow.bits {
            return Err(ConsensusError::InvalidHeader(
                "unexpected early-chain difficulty bits",
            ));
        }
        return Ok(pow.bits);
    }

    let first = first_suitable.ok_or(ConsensusError::InvalidHeader(
        "missing first suitable difficulty block",
    ))?;
    let last = last_suitable.ok_or(ConsensusError::InvalidHeader(
        "missing last suitable difficulty block",
    ))?;
    retarget_bits(pow, first, last)
}

pub fn retarget_bits(
    pow: PowParams,
    first: DifficultyPoint,
    last: DifficultyPoint,
) -> Result<u32, ConsensusError> {
    if last.height <= first.height {
        return Err(ConsensusError::InvalidHeader(
            "difficulty points are not height ordered",
        ));
    }
    let Some(work_delta) = last.chainwork.checked_sub(first.chainwork) else {
        return Err(ConsensusError::InvalidHeader(
            "difficulty chainwork regressed",
        ));
    };
    let Some(scaled_work) = work_delta.checked_mul_u64(u64::from(pow.target_spacing)) else {
        return Err(ConsensusError::InvalidHeader(
            "difficulty work calculation overflowed",
        ));
    };
    let actual_timespan = last.time.saturating_sub(first.time).clamp(
        u64::from(pow.minimum_actual_timespan),
        u64::from(pow.maximum_actual_timespan),
    );
    let work = scaled_work
        .div_u64(actual_timespan)
        .ok_or(ConsensusError::InvalidHeader("invalid difficulty timespan"))?;
    if work == Uint256::ZERO {
        return Ok(pow.bits);
    }
    let target = Uint256::target_for_work(work).ok_or(ConsensusError::InvalidHeader(
        "invalid difficulty work target",
    ))?;
    if target > Uint256::from_be_bytes(pow.limit) {
        return Ok(pow.bits);
    }
    Ok(CompactTarget::from_target(target))
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
        _ => panic!("invalid hexadecimal network constant"),
    }
}

impl FromStr for Network {
    type Err = NetworkParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "main" | "mainnet" => Ok(Self::Mainnet),
            "test" | "testnet" => Ok(Self::Testnet),
            "regtest" => Ok(Self::Regtest),
            "sim" | "simnet" => Ok(Self::Simnet),
            other => Err(NetworkParseError {
                value: other.to_owned(),
            }),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ConsensusParams {
    pub network: Network,
}

impl ConsensusParams {
    pub fn for_network(network: Network) -> Self {
        Self { network }
    }

    pub const fn network_params(&self) -> NetworkParams {
        self.network.params()
    }
}

pub trait TransactionInputVerifier: Send + Sync {
    fn verify_input(
        &self,
        transaction: &Transaction,
        input_index: usize,
        coin: &Coin,
    ) -> Result<(), ConsensusError>;

    /// Whether this verifier represents a complete production consensus path.
    /// Fail-closed placeholders and test doubles must retain the default `false`.
    fn is_consensus_complete(&self) -> bool {
        false
    }
}

/// Production-safe default for compositions that have not explicitly installed
/// the native script verifier. It deliberately rejects every non-coinbase spend
/// rather than allowing the UTXO engine to connect an unauthorized transaction.
#[derive(Clone, Copy, Debug, Default)]
pub struct RejectUnverifiedInputs;

impl TransactionInputVerifier for RejectUnverifiedInputs {
    fn verify_input(
        &self,
        _transaction: &Transaction,
        _input_index: usize,
        _coin: &Coin,
    ) -> Result<(), ConsensusError> {
        Err(ConsensusError::Authorization(
            "transaction authorization backend is not configured".to_owned(),
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HeaderValidationContext {
    pub height: Height,
    pub previous: Option<HeaderParent>,
    /// Enforce the selected network's pinned HSD checkpoint hash when this
    /// height has one. HSD exposes this as an optional synchronization policy.
    pub enforce_checkpoints: bool,
    pub expected_bits: Option<u32>,
    pub median_time_past: Option<u64>,
    pub maximum_time: Option<u64>,
    pub require_pow: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HeaderParent {
    pub hash: BlockHash,
    pub height: Height,
    pub bits: u32,
    pub chainwork: Uint256,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct HeaderConsensus {
    params: ConsensusParams,
}

impl HeaderConsensus {
    pub fn new(params: ConsensusParams) -> Self {
        Self { params }
    }

    pub fn params(&self) -> &ConsensusParams {
        &self.params
    }

    pub fn validate_header(
        &self,
        header: &Header,
        context: &HeaderValidationContext,
    ) -> Result<(), ConsensusError> {
        if context.height == 0 {
            let network = self.params.network_params();
            if header != &network.genesis_header() || header.hash() != network.genesis_hash {
                return Err(ConsensusError::InvalidHeader(
                    "genesis header does not match the selected HNS network",
                ));
            }
        } else {
            let previous = context
                .previous
                .as_ref()
                .ok_or(ConsensusError::InvalidHeader("missing previous header"))?;

            if previous.height.checked_add(1) != Some(context.height) {
                return Err(ConsensusError::InvalidHeader(
                    "previous header height is not contiguous",
                ));
            }

            if header.prev_block != previous.hash {
                return Err(ConsensusError::InvalidHeader(
                    "previous header hash mismatch",
                ));
            }
        }

        if !verify_checkpoint(
            self.params.network,
            context.enforce_checkpoints,
            context.height,
            &header.hash(),
        ) {
            return Err(ConsensusError::InvalidHeader("checkpoint mismatch"));
        }

        if let Some(expected_bits) = context.expected_bits {
            if header.bits != expected_bits {
                return Err(ConsensusError::InvalidHeader("unexpected difficulty bits"));
            }
        }

        if context
            .median_time_past
            .is_some_and(|median| header.time <= median)
        {
            return Err(ConsensusError::InvalidHeader(
                "header time is not above median time past",
            ));
        }

        if context
            .maximum_time
            .is_some_and(|maximum| header.time > maximum)
        {
            return Err(ConsensusError::InvalidHeader(
                "header time is too far in the future",
            ));
        }

        if context.require_pow && !header.verify_pow() {
            return Err(ConsensusError::InvalidHeader("proof of work failed"));
        }

        Ok(())
    }

    pub fn validate_transaction_sanity(
        &self,
        transaction: &Transaction,
    ) -> Result<(), ConsensusError> {
        validate_transaction_sanity(transaction)
    }

    pub fn validate_block_body(&self, block: &Block) -> Result<BlockValidation, ConsensusError> {
        validate_block_body(block)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BlockValidation {
    pub base_size: usize,
    pub witness_size: usize,
    pub weight: usize,
    pub merkle_root: [u8; 32],
    pub witness_root: [u8; 32],
}

pub fn validate_block_body(block: &Block) -> Result<BlockValidation, ConsensusError> {
    if block.transactions.is_empty() {
        return Err(ConsensusError::InvalidBlock("block has no transactions"));
    }

    if block.transactions.len() > MAX_BLOCK_BASE_SIZE {
        return Err(ConsensusError::InvalidBlock(
            "block has too many transactions",
        ));
    }

    let base_size = block_base_size(block);
    let witness_size = block_witness_size(block);
    let weight = block_weight(block);

    if base_size > MAX_BLOCK_BASE_SIZE {
        return Err(ConsensusError::InvalidBlock(
            "block base size exceeds limit",
        ));
    }

    if weight > MAX_BLOCK_WEIGHT {
        return Err(ConsensusError::InvalidBlock("block weight exceeds limit"));
    }

    if !is_coinbase(&block.transactions[0]) {
        return Err(ConsensusError::InvalidBlock(
            "first transaction is not coinbase",
        ));
    }

    for (index, transaction) in block.transactions.iter().enumerate() {
        validate_transaction_sanity(transaction)?;

        if index != 0 && is_coinbase(transaction) {
            return Err(ConsensusError::InvalidBlock(
                "block contains multiple coinbase transactions",
            ));
        }
    }

    validate_block_covenant_limits(block)?;

    let merkle_root = block_merkle_root(block);

    if merkle_root == [0; 32] {
        return Err(ConsensusError::InvalidBlock("merkle root is zero"));
    }

    if block.header.merkle_root != merkle_root {
        return Err(ConsensusError::InvalidBlock("merkle root mismatch"));
    }

    let witness_root = block_witness_root(block);

    if block.header.witness_root != witness_root {
        return Err(ConsensusError::InvalidBlock("witness root mismatch"));
    }

    Ok(BlockValidation {
        base_size,
        witness_size,
        weight,
        merkle_root,
        witness_root,
    })
}

pub fn validate_transaction_sanity(transaction: &Transaction) -> Result<(), ConsensusError> {
    if transaction.inputs.is_empty() {
        return Err(ConsensusError::InvalidTransaction(
            "transaction has no inputs",
        ));
    }

    if transaction.outputs.is_empty() {
        return Err(ConsensusError::InvalidTransaction(
            "transaction has no outputs",
        ));
    }

    if transaction.base_size() > MAX_TX_SIZE {
        return Err(ConsensusError::InvalidTransaction(
            "transaction base size exceeds limit",
        ));
    }

    if transaction_weight(transaction) > MAX_TX_WEIGHT {
        return Err(ConsensusError::InvalidTransaction(
            "transaction weight exceeds limit",
        ));
    }

    let mut total_output = 0u64;

    for output in &transaction.outputs {
        output.address.validate().map_err(|_| {
            ConsensusError::InvalidTransaction("transaction output address invalid")
        })?;
        total_output =
            total_output
                .checked_add(output.value)
                .ok_or(ConsensusError::InvalidTransaction(
                    "transaction output value overflow",
                ))?;

        if total_output > MAX_MONEY {
            return Err(ConsensusError::InvalidTransaction(
                "transaction output value exceeds max money",
            ));
        }
    }

    if is_coinbase(transaction) {
        validate_coinbase_sanity(transaction)?;
    } else {
        let mut inputs = HashSet::new();

        for input in &transaction.inputs {
            if is_null_outpoint(&input.previous_output) {
                return Err(ConsensusError::InvalidTransaction(
                    "non-coinbase spends null outpoint",
                ));
            }

            if !inputs.insert(input.previous_output.clone()) {
                return Err(ConsensusError::InvalidTransaction(
                    "transaction contains duplicate inputs",
                ));
            }
        }
    }

    if !has_sane_covenants(transaction) {
        return Err(ConsensusError::InvalidTransaction(
            "transaction covenants are structurally invalid",
        ));
    }

    Ok(())
}

/// Return whether a transaction is final for the block height and parent
/// median-time-past supplied by the caller. Handshake encodes time-based
/// locktime by setting the high bit; the remaining 31 bits are the lock value.
/// A non-final lock can still be disabled only when every input uses the final
/// sequence value.
pub fn is_final_transaction(
    transaction: &Transaction,
    block_height: Height,
    median_time_past: u64,
) -> bool {
    if transaction.locktime == 0 {
        return true;
    }

    let lock_value = transaction.locktime & LOCKTIME_MASK;
    let threshold = if transaction.locktime & LOCKTIME_FLAG != 0 {
        median_time_past
    } else {
        u64::from(block_height)
    };

    if u64::from(lock_value) < threshold {
        return true;
    }

    transaction
        .inputs
        .iter()
        .all(|input| input.sequence == u32::MAX)
}

pub fn validate_block_finality(
    block: &Block,
    block_height: Height,
    median_time_past: u64,
) -> Result<(), ConsensusError> {
    if block
        .transactions
        .iter()
        // HSD's contextual block validation starts at transaction index one.
        // A coinbase locktime/sequence commits miner data and is not subject to
        // ordinary transaction finality (mainnet block 1 is a canonical case).
        .skip(1)
        .any(|transaction| !is_final_transaction(transaction, block_height, median_time_past))
    {
        return Err(ConsensusError::InvalidBlock(
            "block contains a non-final transaction",
        ));
    }
    Ok(())
}

fn validate_block_covenant_limits(block: &Block) -> Result<(), ConsensusError> {
    let mut opens = 0u32;
    let mut updates = 0u32;
    let mut renewals = 0u32;
    let mut exclusive_names = HashSet::new();
    for transaction in &block.transactions {
        for output in &transaction.outputs {
            match output.covenant.kind {
                CovenantKind::Open => {
                    opens = opens.saturating_add(1);
                    updates = updates.saturating_add(1);
                }
                CovenantKind::Claim
                | CovenantKind::Update
                | CovenantKind::Transfer
                | CovenantKind::Revoke => updates = updates.saturating_add(1),
                CovenantKind::Register | CovenantKind::Renew | CovenantKind::Finalize => {
                    renewals = renewals.saturating_add(1)
                }
                _ => {}
            }
            if matches!(
                output.covenant.kind,
                CovenantKind::Claim
                    | CovenantKind::Open
                    | CovenantKind::Register
                    | CovenantKind::Update
                    | CovenantKind::Renew
                    | CovenantKind::Transfer
                    | CovenantKind::Finalize
                    | CovenantKind::Revoke
            ) {
                let name_hash: [u8; 32] =
                    output.covenant.items[0]
                        .as_slice()
                        .try_into()
                        .map_err(|_| {
                            ConsensusError::InvalidBlock("name covenant hash has invalid length")
                        })?;
                if !exclusive_names.insert(name_hash) {
                    return Err(ConsensusError::InvalidBlock(
                        "block contains duplicate exclusive name updates",
                    ));
                }
            }
        }
    }
    if opens > MAX_BLOCK_OPENS {
        return Err(ConsensusError::InvalidBlock("block open limit exceeded"));
    }
    if updates > MAX_BLOCK_UPDATES {
        return Err(ConsensusError::InvalidBlock("block update limit exceeded"));
    }
    if renewals > MAX_BLOCK_RENEWALS {
        return Err(ConsensusError::InvalidBlock("block renewal limit exceeded"));
    }
    Ok(())
}

fn has_sane_covenants(transaction: &Transaction) -> bool {
    if is_coinbase(transaction) {
        if transaction.inputs.len() > transaction.outputs.len() {
            return false;
        }
        for (index, output) in transaction.outputs.iter().enumerate() {
            match output.covenant.kind {
                CovenantKind::None => {
                    if !output.covenant.items.is_empty() {
                        return false;
                    }
                }
                CovenantKind::Claim => {
                    let items = &output.covenant.items;
                    if index == 0
                        || index >= transaction.inputs.len()
                        || transaction.inputs[index].witness.items.len() != 1
                        || !item_lengths(items, &[32, 4, usize::MAX, 1, 32, 4])
                        || !valid_name_hash(&items[0], &items[2])
                    {
                        return false;
                    }
                }
                _ => return false,
            }
        }
        return true;
    }

    for (index, output) in transaction.outputs.iter().enumerate() {
        let items = &output.covenant.items;
        let linked = index < transaction.inputs.len();
        let sane = match output.covenant.kind {
            CovenantKind::None => items.is_empty(),
            CovenantKind::Claim => false,
            CovenantKind::Open => {
                item_lengths(items, &[32, 4, usize::MAX])
                    && item_u32(items, 1) == Some(0)
                    && valid_name_hash(&items[0], &items[2])
            }
            CovenantKind::Bid => {
                item_lengths(items, &[32, 4, usize::MAX, 32])
                    && valid_name_hash(&items[0], &items[2])
            }
            CovenantKind::Reveal => linked && item_lengths(items, &[32, 4, 32]),
            CovenantKind::Redeem => linked && item_lengths(items, &[32, 4]),
            CovenantKind::Register => {
                linked
                    && item_lengths(items, &[32, 4, usize::MAX, 32])
                    && items[2].len() <= MAX_RESOURCE_SIZE
            }
            CovenantKind::Update => {
                linked
                    && item_lengths(items, &[32, 4, usize::MAX])
                    && items[2].len() <= MAX_RESOURCE_SIZE
            }
            CovenantKind::Renew => linked && item_lengths(items, &[32, 4, 32]),
            CovenantKind::Transfer => {
                linked
                    && item_lengths(items, &[32, 4, 1, usize::MAX])
                    && items[2][0] <= 31
                    && (2..=40).contains(&items[3].len())
            }
            CovenantKind::Finalize => {
                linked
                    && item_lengths(items, &[32, 4, usize::MAX, 1, 4, 4, 32])
                    && valid_name_hash(&items[0], &items[2])
            }
            CovenantKind::Revoke => linked && item_lengths(items, &[32, 4]),
            CovenantKind::Unknown(_) => {
                items.len() <= MAX_SCRIPT_STACK
                    && output.covenant.encode().len() <= MAX_COVENANT_SIZE
            }
        };
        if !sane {
            return false;
        }
    }
    true
}

fn item_lengths(items: &[Vec<u8>], expected: &[usize]) -> bool {
    items.len() == expected.len()
        && items
            .iter()
            .zip(expected)
            .all(|(item, length)| *length == usize::MAX || item.len() == *length)
}

fn item_u32(items: &[Vec<u8>], index: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        items.get(index)?.as_slice().try_into().ok()?,
    ))
}

fn valid_name_hash(hash: &[u8], name: &[u8]) -> bool {
    let Ok(name) = std::str::from_utf8(name) else {
        return false;
    };
    hash_name(name)
        .map(|expected| expected.as_bytes() == hash)
        .unwrap_or(false)
}

fn validate_coinbase_sanity(transaction: &Transaction) -> Result<(), ConsensusError> {
    if witness_size(&transaction.inputs[0].witness) > MAX_COINBASE_WITNESS_SIZE {
        return Err(ConsensusError::InvalidTransaction(
            "coinbase witness exceeds limit",
        ));
    }

    for input in transaction.inputs.iter().skip(1) {
        if !is_null_outpoint(&input.previous_output) {
            return Err(ConsensusError::InvalidTransaction(
                "coinbase claim input is not null",
            ));
        }

        if input.witness.items.len() != 1 {
            return Err(ConsensusError::InvalidTransaction(
                "coinbase claim input must have one witness item",
            ));
        }

        if input.witness.items[0].len() > MAX_COINBASE_CLAIM_WITNESS_ITEM_SIZE {
            return Err(ConsensusError::InvalidTransaction(
                "coinbase claim witness item exceeds limit",
            ));
        }
    }

    Ok(())
}

pub fn is_coinbase(transaction: &Transaction) -> bool {
    transaction
        .inputs
        .first()
        .map(|input| is_null_outpoint(&input.previous_output))
        .unwrap_or(false)
}

pub fn is_null_outpoint(outpoint: &Outpoint) -> bool {
    outpoint.txid == Txid::ZERO && outpoint.index == u32::MAX
}

pub fn block_merkle_root(block: &Block) -> [u8; 32] {
    merkle_root(block.transactions.iter().map(|transaction| {
        let txid = transaction.txid();
        *txid.as_bytes()
    }))
}

pub fn block_witness_root(block: &Block) -> [u8; 32] {
    merkle_root(block.transactions.iter().map(Transaction::witness_hash))
}

pub fn merkle_root(hashes: impl IntoIterator<Item = [u8; 32]>) -> [u8; 32] {
    let sentinel = blake2b_256(&[]);
    let leaf_marker = [0x00];
    let branch_marker = [0x01];
    let mut nodes = hashes
        .into_iter()
        .map(|hash| blake2b_256_many([leaf_marker.as_slice(), hash.as_slice()]))
        .collect::<Vec<_>>();

    if nodes.is_empty() {
        return sentinel;
    }

    while nodes.len() > 1 {
        let mut next = Vec::with_capacity(nodes.len().div_ceil(2));

        for chunk in nodes.chunks(2) {
            let right = chunk.get(1).unwrap_or(&sentinel);
            next.push(blake2b_256_many([
                branch_marker.as_slice(),
                chunk[0].as_slice(),
                right.as_slice(),
            ]));
        }

        nodes = next;
    }

    nodes[0]
}

pub fn block_base_size(block: &Block) -> usize {
    HEADER_SIZE
        + varint_size(block.transactions.len() as u64)
        + block
            .transactions
            .iter()
            .map(Transaction::base_size)
            .sum::<usize>()
}

pub fn block_witness_size(block: &Block) -> usize {
    block
        .transactions
        .iter()
        .map(Transaction::witness_size)
        .sum()
}

pub fn block_weight(block: &Block) -> usize {
    block_base_size(block)
        .saturating_mul(WITNESS_SCALE_FACTOR)
        .saturating_add(block_witness_size(block))
}

pub fn transaction_weight(transaction: &Transaction) -> usize {
    transaction
        .base_size()
        .saturating_mul(WITNESS_SCALE_FACTOR)
        .saturating_add(transaction.witness_size())
}

fn witness_size(witness: &Witness) -> usize {
    let mut writer = Writer::new();
    witness.write_to(&mut writer);
    writer.finish().len()
}

fn varint_size(value: u64) -> usize {
    match value {
        0x00..=0xfc => 1,
        0xfd..=0xffff => 3,
        0x1_0000..=0xffff_ffff => 5,
        _ => 9,
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown network `{value}`")]
pub struct NetworkParseError {
    value: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ConsensusError {
    #[error("consensus view failed: {0}")]
    View(String),
    #[error("invalid header: {0}")]
    InvalidHeader(&'static str),
    #[error("invalid transaction: {0}")]
    InvalidTransaction(&'static str),
    #[error("invalid block: {0}")]
    InvalidBlock(&'static str),
    #[error("transaction authorization failed: {0}")]
    Authorization(String),
    #[error("contextual covenant validation failed: {0}")]
    ContextualCovenant(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_primitives::{Address, Covenant, CovenantKind, Input, Output, Transaction, Witness};

    fn header(prev_block: BlockHash, nonce: u32, bits: u32) -> Header {
        Header {
            prev_block,
            nonce,
            bits,
            ..Header::default()
        }
    }

    #[test]
    fn canonical_network_ids_are_total_and_stable() {
        for (network, id) in [
            (Network::Mainnet, 0),
            (Network::Testnet, 1),
            (Network::Regtest, 2),
            (Network::Simnet, 3),
        ] {
            assert_eq!(network.canonical_id(), id);
            assert_eq!(Network::from_canonical_id(id), Some(network));
        }
        assert_eq!(Network::from_canonical_id(4), None);
    }

    #[test]
    fn network_parameters_and_genesis_hashes_match_pinned_hsd() {
        let expected = [
            (Network::Mainnet, 0x5b6e_f2d3, 12_038, 0x1c00_ffff),
            (Network::Testnet, 0xb152_0dd2, 13_038, 0x1d00_ffff),
            (Network::Regtest, 0xae38_95cf, 14_038, 0x207f_ffff),
            (Network::Simnet, 0x0e64_8edc, 15_038, 0x207f_ffff),
        ];
        for (network, magic, port, bits) in expected {
            let params = network.params();
            assert_eq!(params.network_id, network.canonical_id());
            assert_eq!(params.packet_magic, magic);
            assert_eq!(params.port, port);
            assert_eq!(params.pow.bits, bits);
            assert_eq!(params.genesis_header().hash(), params.genesis_hash);
        }
    }

    #[test]
    fn supply_constants_and_halving_schedule_match_hsd() {
        assert_eq!(
            MAX_CREATORS + MAX_SPONSORS + MAX_TLD + MAX_DOMAIN + MAX_CA_NAMING + MAX_AIRDROP,
            MAX_INITIAL
        );
        assert_eq!(MAX_INITIAL + MAX_SUBSIDY, MAX_MONEY);
        assert_eq!(2 * BASE_REWARD * 170_000, MAX_SUBSIDY);
        assert_eq!(GENESIS_REWARD, 2_002_210_000);
        assert_eq!(block_subsidy(0, 170_000), 2_000_000_000);
        assert_eq!(block_subsidy(169_999, 170_000), 2_000_000_000);
        assert_eq!(block_subsidy(170_000, 170_000), 1_000_000_000);
        assert_eq!(block_subsidy(8_840_000, 170_000), 0);
        assert_eq!(
            Network::Regtest.params().block_subsidy(2_500),
            1_000_000_000
        );
        assert_eq!(Network::Mainnet.params().block_reward(0), GENESIS_REWARD);
        assert_eq!(Network::Mainnet.params().block_reward(1), BASE_REWARD);
    }

    #[test]
    fn difficulty_special_cases_match_hsd() {
        let regtest = Network::Regtest.params().pow;
        let previous = DifficultyPoint {
            height: 10_000,
            time: 1_000,
            bits: 1,
            chainwork: Uint256::from(100u64),
        };
        assert_eq!(
            expected_next_bits(regtest, 1_001, previous, None, None).unwrap(),
            regtest.bits
        );

        let testnet = Network::Testnet.params().pow;
        assert_eq!(
            expected_next_bits(
                testnet,
                previous.time + u64::from(testnet.target_spacing) * 2 + 1,
                previous,
                None,
                None,
            )
            .unwrap(),
            testnet.bits
        );

        let early = DifficultyPoint {
            height: testnet.target_window + 1,
            bits: testnet.bits,
            ..previous
        };
        assert_eq!(
            expected_next_bits(testnet, early.time + 1, early, None, None).unwrap(),
            testnet.bits
        );
    }

    #[test]
    fn chainwork_retarget_preserves_target_at_the_expected_rate() {
        let pow = Network::Mainnet.params().pow;
        let proof = CompactTarget::from_bits(pow.bits).proof().unwrap();
        let work_delta = proof.checked_mul_u64(u64::from(pow.target_window)).unwrap();
        let first = DifficultyPoint {
            height: 1,
            time: 10_000,
            bits: pow.bits,
            chainwork: Uint256::from(1_000u64),
        };
        let last = DifficultyPoint {
            height: first.height + pow.target_window,
            time: first.time + u64::from(pow.target_timespan),
            bits: pow.bits,
            chainwork: first.chainwork.checked_add(work_delta).unwrap(),
        };

        assert_eq!(retarget_bits(pow, first, last).unwrap(), pow.bits);
        assert_eq!(
            expected_next_bits(pow, last.time + 1, last, Some(first), Some(last)).unwrap(),
            pow.bits
        );
    }

    #[test]
    fn chainwork_retarget_matches_pinned_hsd_half_timespan_vector() {
        let pow = Network::Mainnet.params().pow;
        let first = DifficultyPoint {
            height: 1_000,
            time: 1_000_000,
            bits: pow.bits,
            chainwork: Uint256::from(0x0123_4567_89ab_cdefu64),
        };
        let last = DifficultyPoint {
            height: first.height + pow.target_window,
            time: first.time + u64::from(pow.target_timespan / 2),
            bits: pow.bits,
            chainwork: Uint256::from_be_bytes(hex32(
                "0000000000000000000000000000000000000000000000000123d56819ac5def",
            )),
        };

        assert_eq!(retarget_bits(pow, first, last).unwrap(), 0x1b7f_ff80);
    }

    #[test]
    fn chainwork_retarget_rejects_regression_and_clamps_timespan() {
        let pow = Network::Mainnet.params().pow;
        let first = DifficultyPoint {
            height: 1,
            time: 100,
            bits: pow.bits,
            chainwork: Uint256::from(100u64),
        };
        let regressed = DifficultyPoint {
            height: 2,
            time: 99,
            bits: pow.bits,
            chainwork: Uint256::from(99u64),
        };
        assert!(retarget_bits(pow, first, regressed).is_err());

        let slow = DifficultyPoint {
            height: first.height + pow.target_window,
            time: first.time + u64::from(pow.maximum_actual_timespan) * 2,
            bits: pow.bits,
            chainwork: first
                .chainwork
                .checked_add(Uint256::from(1_000_000u64))
                .unwrap(),
        };
        assert!(retarget_bits(pow, first, slow).is_ok());
    }

    #[test]
    fn selected_network_rejects_another_networks_genesis() {
        let consensus = HeaderConsensus::new(ConsensusParams::for_network(Network::Mainnet));
        let testnet_genesis = Network::Testnet.params().genesis_header();
        assert!(consensus
            .validate_header(
                &testnet_genesis,
                &HeaderValidationContext {
                    height: 0,
                    previous: None,
                    enforce_checkpoints: false,
                    expected_bits: Some(testnet_genesis.bits),
                    median_time_past: None,
                    maximum_time: None,
                    require_pow: false,
                },
            )
            .is_err());
    }

    #[test]
    fn header_consensus_accepts_linked_header_without_pow_requirement() {
        let consensus = HeaderConsensus::new(ConsensusParams::for_network(Network::Regtest));
        let parent = header(BlockHash::ZERO, 1, 0);
        let parent_hash = parent.hash();
        let child = header(parent_hash, 2, 0);

        consensus
            .validate_header(
                &child,
                &HeaderValidationContext {
                    height: 1,
                    previous: Some(HeaderParent {
                        hash: parent_hash,
                        height: 0,
                        bits: parent.bits,
                        chainwork: Uint256::ONE,
                    }),
                    enforce_checkpoints: false,
                    expected_bits: Some(0),
                    median_time_past: None,
                    maximum_time: None,
                    require_pow: false,
                },
            )
            .expect("valid header");
    }

    #[test]
    fn header_consensus_rejects_bad_linkage() {
        let consensus = HeaderConsensus::new(ConsensusParams::for_network(Network::Regtest));
        let error = consensus
            .validate_header(
                &header(BlockHash::new([2; 32]), 2, 0),
                &HeaderValidationContext {
                    height: 1,
                    previous: Some(HeaderParent {
                        hash: BlockHash::new([1; 32]),
                        height: 0,
                        bits: 0,
                        chainwork: Uint256::ONE,
                    }),
                    enforce_checkpoints: false,
                    expected_bits: Some(0),
                    median_time_past: None,
                    maximum_time: None,
                    require_pow: false,
                },
            )
            .expect_err("bad linkage");

        assert!(matches!(
            error,
            ConsensusError::InvalidHeader("previous header hash mismatch")
        ));
    }

    #[test]
    fn header_consensus_enforces_median_and_future_time_bounds() {
        let consensus = HeaderConsensus::new(ConsensusParams::for_network(Network::Regtest));
        let parent = header(BlockHash::ZERO, 1, 0);
        let parent_hash = parent.hash();
        let context = HeaderValidationContext {
            height: 1,
            previous: Some(HeaderParent {
                hash: parent_hash,
                height: 0,
                bits: 0,
                chainwork: Uint256::ONE,
            }),
            enforce_checkpoints: false,
            expected_bits: Some(0),
            median_time_past: Some(100),
            maximum_time: Some(200),
            require_pow: false,
        };
        let mut child = header(parent_hash, 2, 0);
        child.time = 100;
        assert!(consensus.validate_header(&child, &context).is_err());
        child.time = 201;
        assert!(consensus.validate_header(&child, &context).is_err());
        child.time = 101;
        consensus
            .validate_header(&child, &context)
            .expect("bounded timestamp");
    }

    #[test]
    fn header_consensus_enforces_selected_network_checkpoints() {
        let consensus = HeaderConsensus::new(ConsensusParams::for_network(Network::Mainnet));
        let checkpoint = Network::Mainnet.checkpoints()[0];
        let parent = header(BlockHash::ZERO, 1, 0);
        let candidate = header(parent.hash(), 2, 0);
        let context = HeaderValidationContext {
            height: checkpoint.height,
            previous: Some(HeaderParent {
                hash: parent.hash(),
                height: checkpoint.height - 1,
                bits: 0,
                chainwork: Uint256::ONE,
            }),
            enforce_checkpoints: true,
            expected_bits: Some(0),
            median_time_past: None,
            maximum_time: None,
            require_pow: false,
        };

        assert!(matches!(
            consensus.validate_header(&candidate, &context),
            Err(ConsensusError::InvalidHeader("checkpoint mismatch"))
        ));

        let mut disabled = context;
        disabled.enforce_checkpoints = false;
        consensus
            .validate_header(&candidate, &disabled)
            .expect("disabled checkpoint policy");
    }

    fn covenant() -> Covenant {
        Covenant {
            kind: CovenantKind::None,
            items: Vec::new(),
        }
    }

    fn output(value: Amount) -> Output {
        Output {
            value,
            address: Address::new(0, vec![1; 20]).expect("address"),
            covenant: covenant(),
        }
    }

    fn null_outpoint() -> Outpoint {
        Outpoint {
            txid: Txid::ZERO,
            index: u32::MAX,
        }
    }

    fn coinbase(outputs: Vec<Output>) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: null_outpoint(),
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs,
            locktime: 0,
        }
    }

    fn transaction(previous_output: Outpoint, outputs: Vec<Output>) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output,
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs,
            locktime: 0,
        }
    }

    fn block_with_roots(transactions: Vec<Transaction>) -> Block {
        let mut block = Block {
            header: Header::default(),
            transactions,
        };
        block.header.merkle_root = block_merkle_root(&block);
        block.header.witness_root = block_witness_root(&block);
        block
    }

    #[test]
    fn merkle_root_uses_domain_separated_leaf_hashes() {
        let hash = [7; 32];

        assert_eq!(
            merkle_root([hash]),
            blake2b_256_many([[0x00].as_slice(), hash.as_slice()])
        );
    }

    #[test]
    fn block_body_validation_accepts_valid_commitments() {
        let first = coinbase(vec![output(50)]);
        let previous_output = Outpoint {
            txid: Txid::new([3; 32]),
            index: 0,
        };
        let second = transaction(previous_output, vec![output(25)]);
        let block = block_with_roots(vec![first, second]);
        let consensus = HeaderConsensus::new(ConsensusParams::for_network(Network::Regtest));
        let validation = consensus
            .validate_block_body(&block)
            .expect("valid block body");

        assert_eq!(validation.merkle_root, block.header.merkle_root);
        assert_eq!(validation.witness_root, block.header.witness_root);
        assert!(validation.weight >= validation.base_size);
    }

    #[test]
    fn block_body_validation_rejects_bad_merkle_root() {
        let mut block = block_with_roots(vec![coinbase(vec![output(50)])]);
        block.header.merkle_root = [9; 32];
        let consensus = HeaderConsensus::new(ConsensusParams::for_network(Network::Regtest));
        let error = consensus
            .validate_block_body(&block)
            .expect_err("bad merkle root");

        assert!(matches!(
            error,
            ConsensusError::InvalidBlock("merkle root mismatch")
        ));
    }

    #[test]
    fn block_body_validation_rejects_non_coinbase_first_transaction() {
        let previous_output = Outpoint {
            txid: Txid::new([4; 32]),
            index: 0,
        };
        let block = block_with_roots(vec![transaction(previous_output, vec![output(25)])]);
        let consensus = HeaderConsensus::new(ConsensusParams::for_network(Network::Regtest));
        let error = consensus
            .validate_block_body(&block)
            .expect_err("bad coinbase");

        assert!(matches!(
            error,
            ConsensusError::InvalidBlock("first transaction is not coinbase")
        ));
    }

    #[test]
    fn transaction_sanity_rejects_duplicate_inputs() {
        let previous_output = Outpoint {
            txid: Txid::new([5; 32]),
            index: 0,
        };
        let mut tx = transaction(previous_output.clone(), vec![output(25)]);
        tx.inputs.push(Input {
            previous_output,
            sequence: u32::MAX,
            witness: Witness::default(),
        });
        let consensus = HeaderConsensus::new(ConsensusParams::for_network(Network::Regtest));
        let error = consensus
            .validate_transaction_sanity(&tx)
            .expect_err("duplicate input");

        assert!(matches!(
            error,
            ConsensusError::InvalidTransaction("transaction contains duplicate inputs")
        ));
    }

    #[test]
    fn transaction_finality_uses_height_time_flag_and_final_sequences() {
        let mut transaction = transaction(
            Outpoint {
                txid: Txid::new([17; 32]),
                index: 0,
            },
            vec![output(1)],
        );
        transaction.inputs[0].sequence = u32::MAX - 1;

        transaction.locktime = 9;
        assert!(is_final_transaction(&transaction, 10, 0));
        transaction.locktime = 10;
        assert!(!is_final_transaction(&transaction, 10, 0));

        transaction.locktime = LOCKTIME_FLAG | 99;
        assert!(is_final_transaction(&transaction, 0, 100));
        transaction.locktime = LOCKTIME_FLAG | 100;
        assert!(!is_final_transaction(&transaction, 0, 100));

        transaction.inputs[0].sequence = u32::MAX;
        assert!(is_final_transaction(&transaction, 0, 100));
    }

    #[test]
    fn block_finality_rejects_a_non_final_transaction() {
        let mut transaction = transaction(
            Outpoint {
                txid: Txid::new([18; 32]),
                index: 0,
            },
            vec![output(1)],
        );
        transaction.locktime = 5;
        transaction.inputs[0].sequence = u32::MAX - 1;
        let block = block_with_roots(vec![coinbase(vec![output(50)]), transaction]);

        assert!(matches!(
            validate_block_finality(&block, 5, 0).expect_err("non-final block"),
            ConsensusError::InvalidBlock("block contains a non-final transaction")
        ));
    }

    #[test]
    fn block_finality_does_not_apply_to_the_coinbase() {
        let mut coinbase = coinbase(vec![output(50)]);
        coinbase.locktime = 1;
        coinbase.inputs[0].sequence = 368_910_623;
        let block = block_with_roots(vec![coinbase]);

        assert!(!is_final_transaction(&block.transactions[0], 1, 0));
        validate_block_finality(&block, 1, 0).expect("coinbase finality is not checked");
    }

    #[test]
    fn transaction_sanity_enforces_hsd_covenant_shapes_and_name_hashes() {
        let name = b"alpha".to_vec();
        let name_hash = hash_name("alpha").unwrap().as_bytes().to_vec();
        let mut open = output(1);
        open.covenant = Covenant {
            kind: CovenantKind::Open,
            items: vec![name_hash, 0u32.to_le_bytes().to_vec(), name],
        };
        let tx = transaction(
            Outpoint {
                txid: Txid::new([4; 32]),
                index: 0,
            },
            vec![open],
        );
        validate_transaction_sanity(&tx).expect("sane OPEN covenant");

        let mut bad_hash = tx.clone();
        bad_hash.outputs[0].covenant.items[0][0] ^= 1;
        assert!(validate_transaction_sanity(&bad_hash).is_err());

        let mut claim = tx;
        claim.outputs[0].covenant.kind = CovenantKind::Claim;
        assert!(validate_transaction_sanity(&claim).is_err());
    }

    #[test]
    fn block_body_rejects_duplicate_exclusive_name_updates() {
        let name = b"alpha".to_vec();
        let name_hash = hash_name("alpha").unwrap().as_bytes().to_vec();
        let open_output = || Output {
            value: 1,
            address: Address::new(0, vec![2; 20]).unwrap(),
            covenant: Covenant {
                kind: CovenantKind::Open,
                items: vec![name_hash.clone(), 0u32.to_le_bytes().to_vec(), name.clone()],
            },
        };
        let first = transaction(
            Outpoint {
                txid: Txid::new([5; 32]),
                index: 0,
            },
            vec![open_output()],
        );
        let second = transaction(
            Outpoint {
                txid: Txid::new([6; 32]),
                index: 0,
            },
            vec![open_output()],
        );
        let block = block_with_roots(vec![coinbase(vec![output(50)]), first, second]);

        assert!(matches!(
            validate_block_body(&block),
            Err(ConsensusError::InvalidBlock(
                "block contains duplicate exclusive name updates"
            ))
        ));
    }
}
