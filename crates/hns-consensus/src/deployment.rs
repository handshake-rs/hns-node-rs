use hns_primitives::{BlockHash, Height};
use serde::{Deserialize, Serialize};

use crate::{NameFlags, Network, ScriptFlags};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeploymentId {
    Hardening,
    IcannLockup,
    Airstop,
    TestDummy,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Deployment {
    pub id: DeploymentId,
    pub bit: u8,
    pub start_time: u64,
    pub timeout: u64,
    /// `None` selects the network activation threshold, matching HSD's `-1`.
    pub threshold: Option<u32>,
    /// `None` selects the network miner window, matching HSD's `-1`.
    pub window: Option<u32>,
    pub required: bool,
    pub force: bool,
}

impl Deployment {
    pub const fn name(self) -> &'static str {
        match self.id {
            DeploymentId::Hardening => "hardening",
            DeploymentId::IcannLockup => "icannlockup",
            DeploymentId::Airstop => "airstop",
            DeploymentId::TestDummy => "testdummy",
        }
    }

    pub const fn effective_threshold(self, activation_threshold: u32) -> u32 {
        match self.threshold {
            Some(threshold) => threshold,
            None => activation_threshold,
        }
    }

    pub const fn effective_window(self, miner_window: u32) -> u32 {
        match self.window {
            Some(window) => window,
            None => miner_window,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Checkpoint {
    pub height: Height,
    pub hash: BlockHash,
}

#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ThresholdState {
    #[default]
    Defined,
    Started,
    LockedIn,
    Active,
    Failed,
}

impl ThresholdState {
    pub const fn to_u8(self) -> u8 {
        match self {
            Self::Defined => 0,
            Self::Started => 1,
            Self::LockedIn => 2,
            Self::Active => 3,
            Self::Failed => 4,
        }
    }

    pub const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::Defined),
            1 => Some(Self::Started),
            2 => Some(Self::LockedIn),
            3 => Some(Self::Active),
            4 => Some(Self::Failed),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DeploymentHistoryEntry {
    pub version: u32,
    pub median_time_past: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeploymentState {
    pub script_flags: ScriptFlags,
    pub lock_flags: u32,
    pub name_flags: NameFlags,
    pub has_airstop: bool,
    states: [ThresholdState; 4],
}

impl DeploymentState {
    pub fn state(self, id: DeploymentId) -> ThresholdState {
        self.states[deployment_index(id)]
    }

    pub const fn from_states(states: [ThresholdState; 4]) -> Self {
        let mut name_bits = 0;
        if matches!(states[0], ThresholdState::Active) {
            name_bits |= NameFlags::HARDENED.bits();
        }
        if matches!(states[1], ThresholdState::Active) {
            name_bits |= NameFlags::LOCKUP.bits();
        }
        Self {
            script_flags: ScriptFlags::MANDATORY,
            lock_flags: 0,
            name_flags: NameFlags::from_bits(name_bits),
            has_airstop: matches!(states[2], ThresholdState::Active),
            states,
        }
    }

    pub fn with_state(mut self, id: DeploymentId, state: ThresholdState) -> Self {
        self.states[deployment_index(id)] = state;
        Self::from_states(self.states)
    }

    pub fn encode_states(self) -> [u8; 4] {
        self.states.map(ThresholdState::to_u8)
    }

    pub fn decode_states(bytes: [u8; 4]) -> Result<Self, DeploymentError> {
        let mut states = [ThresholdState::Defined; 4];
        for (index, value) in bytes.into_iter().enumerate() {
            states[index] =
                ThresholdState::from_u8(value).ok_or(DeploymentError::InvalidCachedState(value))?;
        }
        Ok(Self::from_states(states))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeploymentPeriod {
    pub median_time_past: u64,
    pub signalling_blocks: u32,
}

const COMMON_DEPLOYMENTS: [Deployment; 4] = [
    Deployment {
        id: DeploymentId::Hardening,
        bit: 0,
        start_time: 1_581_638_400,
        timeout: 1_707_868_800,
        threshold: None,
        window: None,
        required: false,
        force: false,
    },
    Deployment {
        id: DeploymentId::IcannLockup,
        bit: 1,
        start_time: 1_691_625_600,
        timeout: 1_703_980_800,
        threshold: None,
        window: None,
        required: false,
        force: false,
    },
    Deployment {
        id: DeploymentId::Airstop,
        bit: 2,
        start_time: 1_751_328_000,
        timeout: 1_759_881_600,
        threshold: None,
        window: None,
        required: false,
        force: false,
    },
    Deployment {
        id: DeploymentId::TestDummy,
        bit: 28,
        start_time: 1_199_145_601,
        timeout: 1_230_767_999,
        threshold: None,
        window: None,
        required: false,
        force: true,
    },
];

const REGTEST_DEPLOYMENTS: [Deployment; 4] = [
    COMMON_DEPLOYMENTS[0],
    COMMON_DEPLOYMENTS[1],
    COMMON_DEPLOYMENTS[2],
    Deployment {
        id: DeploymentId::TestDummy,
        bit: 28,
        start_time: 0,
        timeout: 4_294_967_295,
        threshold: None,
        window: None,
        required: false,
        force: true,
    },
];

const MAINNET_CHECKPOINTS: [Checkpoint; 15] = [
    checkpoint(
        1_008,
        "0000000000001013c28fa079b545fb805f04c496687799b98e35e83cbbb8953e",
    ),
    checkpoint(
        2_016,
        "0000000000000424ee6c2a5d6e0da5edfc47a4a10328c1792056ee48303c3e40",
    ),
    checkpoint(
        10_000,
        "00000000000001a86811a6f520bf67cefa03207dc84fd315f58153b28694ec51",
    ),
    checkpoint(
        20_000,
        "0000000000000162c7ac70a582256f59c189b5c90d8e9861b3f374ed714c58de",
    ),
    checkpoint(
        30_000,
        "0000000000000004f790862846b23c3a81585aea0fa79a7d851b409e027bcaa7",
    ),
    checkpoint(
        40_000,
        "0000000000000002966206a40b10a575cb46531253b08dae8e1b356cfa277248",
    ),
    checkpoint(
        50_000,
        "00000000000000020c7447e7139feeb90549bfc77a7f18d4ff28f327c04f8d6e",
    ),
    checkpoint(
        56_880,
        "0000000000000001d4ef9ea6908bb4eb970d556bd07cbd7d06a634e1cd5bbf4e",
    ),
    checkpoint(
        61_043,
        "00000000000000015b84385e0307370f8323420eaa27ef6e407f2d3162f1fd05",
    ),
    checkpoint(
        100_000,
        "000000000000000136d7d3efa688072f40d9fdd71bd47bb961694c0f38950246",
    ),
    checkpoint(
        130_000,
        "0000000000000005ee5106df9e48bcd232a1917684ac344b35ddd9b9e4101096",
    ),
    checkpoint(
        160_000,
        "00000000000000021e723ce5aedc021ab4f85d46a6914e40148f01986baa46c9",
    ),
    checkpoint(
        200_000,
        "000000000000000181ebc18d6c34442ffef3eedca90c57ca8ecc29016a1cfe16",
    ),
    checkpoint(
        225_000,
        "00000000000000021f0be013ebad018a9ef97c8501766632f017a778781320d5",
    ),
    checkpoint(
        258_026,
        "0000000000000004963d20732c58e5a91cb7e1b61ec6709d031f1a5ca8c55b95",
    ),
];

const NO_CHECKPOINTS: [Checkpoint; 0] = [];

impl Network {
    pub const fn deployments(self) -> &'static [Deployment] {
        match self {
            Self::Regtest => &REGTEST_DEPLOYMENTS,
            Self::Mainnet | Self::Testnet | Self::Simnet => &COMMON_DEPLOYMENTS,
        }
    }

    pub const fn checkpoints(self) -> &'static [Checkpoint] {
        match self {
            Self::Mainnet => &MAINNET_CHECKPOINTS,
            Self::Testnet | Self::Regtest | Self::Simnet => &NO_CHECKPOINTS,
        }
    }

    pub fn checkpoint(self, height: Height) -> Option<Checkpoint> {
        self.checkpoints()
            .binary_search_by_key(&height, |checkpoint| checkpoint.height)
            .ok()
            .map(|index| self.checkpoints()[index])
    }

    pub const fn last_checkpoint(self) -> Height {
        match self {
            Self::Mainnet => 258_026,
            Self::Testnet | Self::Regtest | Self::Simnet => 0,
        }
    }
}

/// Match HSD's optional checkpoint hash policy. Checkpoints constrain sync and
/// reorganization behavior; they are not a substitute for consensus rules.
pub fn verify_checkpoint(
    network: Network,
    enabled: bool,
    height: Height,
    hash: &BlockHash,
) -> bool {
    !enabled
        || network
            .checkpoint(height)
            .is_none_or(|expected| expected.hash == *hash)
}

/// Match `Chain.isHistoricalHeight`, including HSD's height-zero result on
/// networks whose `lastCheckpoint` is zero.
pub const fn is_hsd_historical_height(
    network: Network,
    checkpoints_enabled: bool,
    height: Height,
) -> bool {
    checkpoints_enabled && height <= network.last_checkpoint()
}

/// Match `Chain.isHistorical(prev)` for a block at `height`. Genesis is not
/// connected through that method and therefore is never a historical block.
pub const fn is_hsd_historical_block(
    network: Network,
    checkpoints_enabled: bool,
    height: Height,
) -> bool {
    height != 0 && is_hsd_historical_height(network, checkpoints_enabled, height)
}

/// Fail-closed wrapper around HSD's historical script bypass. HSD invokes the
/// bypass only after header synchronization has established checkpoint-backed
/// ancestry. HSRD callers must provide the same evidence explicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoricalScriptPolicy {
    network: Network,
    checkpoints_enabled: bool,
    verified_through: Option<Height>,
}

impl HistoricalScriptPolicy {
    pub const fn new(network: Network, checkpoints_enabled: bool) -> Self {
        Self {
            network,
            checkpoints_enabled,
            verified_through: None,
        }
    }

    pub fn with_verified_checkpoint(
        mut self,
        height: Height,
        hash: &BlockHash,
    ) -> Result<Self, DeploymentError> {
        let checkpoint = self
            .network
            .checkpoint(height)
            .ok_or(DeploymentError::UnknownCheckpoint { height })?;
        if checkpoint.hash != *hash {
            return Err(DeploymentError::CheckpointMismatch { height });
        }
        self.verified_through = Some(
            self.verified_through
                .map_or(height, |current| current.max(height)),
        );
        Ok(self)
    }

    pub const fn may_assume_scripts(self, height: Height) -> bool {
        is_hsd_historical_block(self.network, self.checkpoints_enabled, height)
            && match self.verified_through {
                Some(verified) => height <= verified,
                None => false,
            }
    }

    pub const fn requires_script_verification(self, height: Height) -> bool {
        !self.may_assume_scripts(height)
    }
}

pub fn threshold_state(
    activation_threshold: u32,
    miner_window: u32,
    deployment: Deployment,
    history: &[DeploymentHistoryEntry],
) -> Result<ThresholdState, DeploymentError> {
    if history.is_empty() {
        return Err(DeploymentError::EmptyHistory);
    }
    let (window, threshold) =
        deployment_parameters(activation_threshold, miner_window, deployment)?;

    let window = usize::try_from(window).map_err(|_| DeploymentError::WindowTooLarge)?;
    let completed_periods = history.len() / window;
    let mut state = ThresholdState::Defined;
    let signal = 1u32 << deployment.bit;

    for period in 0..completed_periods {
        let end = (period + 1) * window - 1;
        let time = history[end].median_time_past;
        state = match state {
            ThresholdState::Defined if time >= deployment.timeout => ThresholdState::Failed,
            ThresholdState::Defined if time >= deployment.start_time => ThresholdState::Started,
            ThresholdState::Started if time >= deployment.timeout => ThresholdState::Failed,
            ThresholdState::Started => {
                let start = end + 1 - window;
                let count = history[start..=end]
                    .iter()
                    .filter(|entry| entry.version & signal != 0)
                    .count();
                if count >= threshold as usize {
                    ThresholdState::LockedIn
                } else {
                    ThresholdState::Started
                }
            }
            ThresholdState::LockedIn => ThresholdState::Active,
            terminal @ (ThresholdState::Active | ThresholdState::Failed) => terminal,
            ThresholdState::Defined => ThresholdState::Defined,
        };
    }

    Ok(state)
}

/// Advance one cached HSD BIP9 deployment state for the block at
/// `next_height`. HSD changes state only when the candidate begins a new
/// deployment window. The caller supplies the completed parent window at that
/// boundary; no history is needed between boundaries.
pub fn advance_threshold_state(
    activation_threshold: u32,
    miner_window: u32,
    deployment: Deployment,
    next_height: Height,
    previous: ThresholdState,
    period: Option<DeploymentPeriod>,
) -> Result<ThresholdState, DeploymentError> {
    let (window, threshold) =
        deployment_parameters(activation_threshold, miner_window, deployment)?;
    if next_height % window != 0 {
        return Ok(previous);
    }

    let period = period.ok_or(DeploymentError::MissingCompletedPeriod { next_height })?;
    if period.signalling_blocks > window {
        return Err(DeploymentError::SignallingCountExceedsWindow {
            count: period.signalling_blocks,
            window,
        });
    }

    Ok(match previous {
        ThresholdState::Defined if period.median_time_past >= deployment.timeout => {
            ThresholdState::Failed
        }
        ThresholdState::Defined if period.median_time_past >= deployment.start_time => {
            ThresholdState::Started
        }
        ThresholdState::Started if period.median_time_past >= deployment.timeout => {
            ThresholdState::Failed
        }
        ThresholdState::Started if period.signalling_blocks >= threshold => {
            ThresholdState::LockedIn
        }
        ThresholdState::LockedIn => ThresholdState::Active,
        terminal @ (ThresholdState::Active | ThresholdState::Failed) => terminal,
        state => state,
    })
}

fn deployment_parameters(
    activation_threshold: u32,
    miner_window: u32,
    deployment: Deployment,
) -> Result<(u32, u32), DeploymentError> {
    let window = deployment.effective_window(miner_window);
    let threshold = deployment.effective_threshold(activation_threshold);
    if window == 0 {
        return Err(DeploymentError::ZeroWindow);
    }
    if threshold > window {
        return Err(DeploymentError::ThresholdExceedsWindow { threshold, window });
    }
    if deployment.bit >= 32 {
        return Err(DeploymentError::InvalidBit(deployment.bit));
    }
    Ok((window, threshold))
}

pub fn compute_block_version(
    activation_threshold: u32,
    miner_window: u32,
    deployments: &[Deployment],
    history: &[DeploymentHistoryEntry],
) -> Result<u32, DeploymentError> {
    let mut version = 0u32;
    for deployment in deployments {
        if matches!(
            threshold_state(activation_threshold, miner_window, *deployment, history)?,
            ThresholdState::Started | ThresholdState::LockedIn
        ) {
            version |= 1u32 << deployment.bit;
        }
    }
    Ok(version)
}

pub fn deployment_state(
    network: Network,
    history: &[DeploymentHistoryEntry],
) -> Result<DeploymentState, DeploymentError> {
    let params = network.params();
    let mut states = [ThresholdState::Defined; 4];

    for deployment in network.deployments() {
        let state = threshold_state(
            params.activation_threshold,
            params.miner_window,
            *deployment,
            history,
        )?;
        states[deployment_index(deployment.id)] = state;
    }

    // Pinned HSD applies mandatory script flags to every block. No versionbits
    // deployment changes script flags or lock flags.
    Ok(DeploymentState::from_states(states))
}

const fn deployment_index(id: DeploymentId) -> usize {
    match id {
        DeploymentId::Hardening => 0,
        DeploymentId::IcannLockup => 1,
        DeploymentId::Airstop => 2,
        DeploymentId::TestDummy => 3,
    }
}

const fn checkpoint(height: Height, hash: &str) -> Checkpoint {
    Checkpoint {
        height,
        hash: BlockHash::new(hex32(hash)),
    }
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
        _ => panic!("invalid hexadecimal deployment constant"),
    }
}

#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DeploymentError {
    #[error("deployment history is empty")]
    EmptyHistory,
    #[error("deployment window is zero")]
    ZeroWindow,
    #[error("deployment threshold {threshold} exceeds window {window}")]
    ThresholdExceedsWindow { threshold: u32, window: u32 },
    #[error("deployment window does not fit in memory")]
    WindowTooLarge,
    #[error("deployment bit {0} exceeds the 32-bit header version")]
    InvalidBit(u8),
    #[error("cached deployment state byte {0} is invalid")]
    InvalidCachedState(u8),
    #[error("completed deployment period is missing for block height {next_height}")]
    MissingCompletedPeriod { next_height: Height },
    #[error("deployment signalling count {count} exceeds window {window}")]
    SignallingCountExceedsWindow { count: u32, window: u32 },
    #[error("height {height} is not a checkpoint on the selected network")]
    UnknownCheckpoint { height: Height },
    #[error("checkpoint hash mismatch at height {height}")]
    CheckpointMismatch { height: Height },
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Fixture {
        script_flags: FixtureScriptFlags,
        networks: Vec<FixtureNetwork>,
        threshold_vectors: Vec<FixtureThresholdVector>,
        block_version_case: FixtureBlockVersion,
        deployment_effect_cases: Vec<FixtureDeploymentEffect>,
        historical_cases: Vec<FixtureHistoricalCase>,
    }

    #[derive(Deserialize)]
    struct FixtureScriptFlags {
        mandatory: u32,
        standard: u32,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FixtureNetwork {
        name: String,
        activation_threshold: u32,
        miner_window: u32,
        goosig_stop: Height,
        deflation_height: Height,
        claim_prefix: String,
        last_checkpoint: Height,
        checkpoints: Vec<FixtureCheckpoint>,
        deployments: Vec<FixtureDeployment>,
    }

    #[derive(Deserialize)]
    struct FixtureCheckpoint {
        height: Height,
        hash: String,
    }

    #[derive(Clone, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FixtureDeployment {
        name: String,
        bit: u8,
        start_time: u64,
        timeout: u64,
        threshold: i64,
        window: i64,
        required: bool,
        force: bool,
    }

    impl FixtureDeployment {
        fn deployment(&self) -> Deployment {
            Deployment {
                id: deployment_id(&self.name),
                bit: self.bit,
                start_time: self.start_time,
                timeout: self.timeout,
                threshold: (self.threshold >= 0).then_some(self.threshold as u32),
                window: (self.window >= 0).then_some(self.window as u32),
                required: self.required,
                force: self.force,
            }
        }
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FixtureThresholdVector {
        id: String,
        activation_threshold: u32,
        miner_window: u32,
        deployment: FixtureDeployment,
        history: Vec<DeploymentHistoryEntry>,
        expected_state: ThresholdState,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FixtureBlockVersion {
        activation_threshold: u32,
        miner_window: u32,
        deployments: Vec<FixtureDeployment>,
        history: Vec<DeploymentHistoryEntry>,
        expected_version: u32,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FixtureHistoricalCase {
        checkpoints: bool,
        height: Height,
        historical_height: bool,
        historical_block: bool,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FixtureDeploymentEffect {
        active: Vec<String>,
        script_flags: u32,
        lock_flags: u32,
        name_flags: u32,
        has_airstop: bool,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct HistoricalDeploymentFixture {
        network: String,
        activation_threshold: u32,
        miner_window: u32,
        last_checkpoint: Height,
        through_height: Height,
        anchor_hash: String,
        deployments: Vec<FixtureDeployment>,
        historical_boundaries: Vec<FixtureHistoricalBoundary>,
        periods: Vec<FixtureHistoricalPeriod>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FixtureHistoricalBoundary {
        height: Height,
        hash: String,
        historical_height: bool,
        historical_block: bool,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FixtureHistoricalPeriod {
        next_height: Height,
        period_start_height: Height,
        period_end_height: Height,
        period_start_hash: String,
        period_end_hash: String,
        median_time_past: u64,
        signalling: FixtureDeploymentCounts,
        states: FixtureDeploymentStates,
        effects: FixtureHistoricalEffects,
        historical_height: bool,
        historical_block: bool,
    }

    #[derive(Deserialize)]
    struct FixtureDeploymentCounts {
        hardening: u32,
        icannlockup: u32,
        airstop: u32,
        testdummy: u32,
    }

    impl FixtureDeploymentCounts {
        fn get(&self, id: DeploymentId) -> u32 {
            match id {
                DeploymentId::Hardening => self.hardening,
                DeploymentId::IcannLockup => self.icannlockup,
                DeploymentId::Airstop => self.airstop,
                DeploymentId::TestDummy => self.testdummy,
            }
        }
    }

    #[derive(Deserialize)]
    struct FixtureDeploymentStates {
        hardening: ThresholdState,
        icannlockup: ThresholdState,
        airstop: ThresholdState,
        testdummy: ThresholdState,
    }

    impl FixtureDeploymentStates {
        fn get(&self, id: DeploymentId) -> ThresholdState {
            match id {
                DeploymentId::Hardening => self.hardening,
                DeploymentId::IcannLockup => self.icannlockup,
                DeploymentId::Airstop => self.airstop,
                DeploymentId::TestDummy => self.testdummy,
            }
        }
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct FixtureHistoricalEffects {
        script_flags: u32,
        lock_flags: u32,
        name_flags: u32,
        has_airstop: bool,
    }

    fn fixture() -> Fixture {
        serde_json::from_str(include_str!(
            "../../../fixtures/hsd/chains/deployments-v1.json"
        ))
        .expect("deployment fixture")
    }

    fn historical_fixture() -> HistoricalDeploymentFixture {
        serde_json::from_str(include_str!(
            "../../../fixtures/hsd/chains/mainnet-deployment-history-v1.json"
        ))
        .expect("historical deployment fixture")
    }

    fn deployment_id(name: &str) -> DeploymentId {
        match name {
            "hardening" => DeploymentId::Hardening,
            "icannlockup" => DeploymentId::IcannLockup,
            "airstop" => DeploymentId::Airstop,
            "testdummy" => DeploymentId::TestDummy,
            "fixture" | "active" | "locked-in" | "started" | "failed" => DeploymentId::TestDummy,
            other => panic!("unknown fixture deployment {other}"),
        }
    }

    fn decode_hash(value: &str) -> BlockHash {
        let bytes = value.as_bytes();
        assert_eq!(bytes.len(), 64);
        let mut raw = [0u8; 32];
        for (index, output) in raw.iter_mut().enumerate() {
            *output = (hex_nibble(bytes[index * 2]) << 4) | hex_nibble(bytes[index * 2 + 1]);
        }
        BlockHash::new(raw)
    }

    #[test]
    fn network_constants_match_hsd_fixture() {
        let fixture = fixture();
        assert_eq!(
            ScriptFlags::MANDATORY.bits(),
            fixture.script_flags.mandatory
        );
        assert_eq!(ScriptFlags::STANDARD.bits(), fixture.script_flags.standard);

        for expected in fixture.networks {
            let network = Network::from_str(&expected.name).expect("fixture network");
            let params = network.params();
            assert_eq!(params.activation_threshold, expected.activation_threshold);
            assert_eq!(params.miner_window, expected.miner_window);
            assert_eq!(params.goosig_stop, expected.goosig_stop);
            assert_eq!(params.deflation_height, expected.deflation_height);
            assert_eq!(network.claim_prefix(), expected.claim_prefix);
            assert_eq!(network.last_checkpoint(), expected.last_checkpoint);
            let checkpoints = expected
                .checkpoints
                .iter()
                .map(|checkpoint| Checkpoint {
                    height: checkpoint.height,
                    hash: decode_hash(&checkpoint.hash),
                })
                .collect::<Vec<_>>();
            assert_eq!(network.checkpoints(), checkpoints);
            let deployments = expected
                .deployments
                .iter()
                .map(FixtureDeployment::deployment)
                .collect::<Vec<_>>();
            assert_eq!(network.deployments(), deployments);
        }
    }

    #[test]
    fn threshold_states_and_block_version_match_hsd_fixture() {
        let fixture = fixture();
        for vector in fixture.threshold_vectors {
            assert_eq!(
                threshold_state(
                    vector.activation_threshold,
                    vector.miner_window,
                    vector.deployment.deployment(),
                    &vector.history,
                )
                .unwrap_or_else(|error| panic!("{} failed: {error}", vector.id)),
                vector.expected_state,
                "{}",
                vector.id
            );
        }

        let vector = fixture.block_version_case;
        let deployments = vector
            .deployments
            .iter()
            .map(FixtureDeployment::deployment)
            .collect::<Vec<_>>();
        assert_eq!(
            compute_block_version(
                vector.activation_threshold,
                vector.miner_window,
                &deployments,
                &vector.history,
            )
            .expect("block version"),
            vector.expected_version
        );
    }

    #[test]
    fn cached_period_transitions_match_full_hsd_history() {
        let deployment = Deployment {
            id: DeploymentId::TestDummy,
            bit: 3,
            start_time: 20,
            timeout: 100,
            threshold: Some(2),
            window: Some(3),
            required: false,
            force: false,
        };
        let signal = 1u32 << deployment.bit;
        let history = [
            DeploymentHistoryEntry {
                version: 0,
                median_time_past: 0,
            },
            DeploymentHistoryEntry {
                version: 0,
                median_time_past: 10,
            },
            DeploymentHistoryEntry {
                version: 0,
                median_time_past: 20,
            },
            DeploymentHistoryEntry {
                version: signal,
                median_time_past: 30,
            },
            DeploymentHistoryEntry {
                version: 0,
                median_time_past: 40,
            },
            DeploymentHistoryEntry {
                version: signal,
                median_time_past: 50,
            },
            DeploymentHistoryEntry {
                version: 0,
                median_time_past: 60,
            },
            DeploymentHistoryEntry {
                version: 0,
                median_time_past: 70,
            },
            DeploymentHistoryEntry {
                version: 0,
                median_time_past: 80,
            },
        ];

        let mut cached = ThresholdState::Defined;
        for next_height in 1..=history.len() {
            let period = (next_height % 3 == 0).then(|| {
                let completed = &history[next_height - 3..next_height];
                DeploymentPeriod {
                    median_time_past: history[next_height - 1].median_time_past,
                    signalling_blocks: completed
                        .iter()
                        .filter(|entry| entry.version & signal != 0)
                        .count() as u32,
                }
            });
            cached =
                advance_threshold_state(2, 3, deployment, next_height as Height, cached, period)
                    .expect("cached deployment transition");
            assert_eq!(
                cached,
                threshold_state(2, 3, deployment, &history[..next_height])
                    .expect("full deployment history"),
                "height {next_height}"
            );
        }
        assert_eq!(cached, ThresholdState::Active);
    }

    #[test]
    fn deployment_state_cache_codec_is_total_and_rejects_unknown_states() {
        let state = DeploymentState::from_states([
            ThresholdState::Active,
            ThresholdState::LockedIn,
            ThresholdState::Failed,
            ThresholdState::Started,
        ]);
        assert_eq!(
            DeploymentState::decode_states(state.encode_states()),
            Ok(state)
        );
        assert!(matches!(
            DeploymentState::decode_states([0, 1, 2, 5]),
            Err(DeploymentError::InvalidCachedState(5))
        ));
    }

    #[test]
    fn historical_boundaries_match_hsd_and_require_ancestry_evidence() {
        for case in fixture().historical_cases {
            assert_eq!(
                is_hsd_historical_height(Network::Mainnet, case.checkpoints, case.height),
                case.historical_height
            );
            assert_eq!(
                is_hsd_historical_block(Network::Mainnet, case.checkpoints, case.height),
                case.historical_block
            );
        }

        let last = *Network::Mainnet
            .checkpoints()
            .last()
            .expect("mainnet checkpoint");
        let closed = HistoricalScriptPolicy::new(Network::Mainnet, true);
        assert!(closed.requires_script_verification(1));
        let backed = closed
            .with_verified_checkpoint(last.height, &last.hash)
            .expect("verified checkpoint");
        assert!(backed.may_assume_scripts(last.height));
        assert!(backed.requires_script_verification(last.height + 1));
    }

    #[test]
    fn historical_mainnet_periods_match_hsd_deployments_and_script_policy() {
        let fixture = historical_fixture();
        assert_eq!(fixture.network, "main");
        assert_eq!(
            fixture.activation_threshold,
            Network::Mainnet.params().activation_threshold
        );
        assert_eq!(fixture.miner_window, Network::Mainnet.params().miner_window);
        assert_eq!(fixture.last_checkpoint, Network::Mainnet.last_checkpoint());
        assert_eq!(fixture.through_height % fixture.miner_window, 0);
        assert_eq!(
            fixture.periods.len(),
            usize::try_from(fixture.through_height / fixture.miner_window)
                .expect("period count fits in memory")
        );
        assert_eq!(
            fixture
                .deployments
                .iter()
                .map(FixtureDeployment::deployment)
                .collect::<Vec<_>>(),
            Network::Mainnet.deployments()
        );

        let last = *Network::Mainnet
            .checkpoints()
            .last()
            .expect("mainnet checkpoint");
        let policy = HistoricalScriptPolicy::new(Network::Mainnet, true)
            .with_verified_checkpoint(last.height, &last.hash)
            .expect("verified checkpoint policy");

        for boundary in &fixture.historical_boundaries {
            let hash = decode_hash(&boundary.hash);
            assert_eq!(
                is_hsd_historical_height(Network::Mainnet, true, boundary.height),
                boundary.historical_height,
                "historical-height decision at {} ({hash:?})",
                boundary.height,
            );
            assert_eq!(
                is_hsd_historical_block(Network::Mainnet, true, boundary.height),
                boundary.historical_block,
                "historical-block decision at {} ({hash:?})",
                boundary.height,
            );
            assert_eq!(
                policy.may_assume_scripts(boundary.height),
                boundary.historical_block,
                "script policy at {} ({hash:?})",
                boundary.height,
            );
            if let Some(checkpoint) = Network::Mainnet.checkpoint(boundary.height) {
                assert_eq!(hash, checkpoint.hash);
            }
        }
        assert_eq!(
            fixture
                .historical_boundaries
                .last()
                .map(|boundary| boundary.hash.as_str()),
            Some(fixture.anchor_hash.as_str())
        );

        let params = Network::Mainnet.params();
        let mut states = [ThresholdState::Defined; 4];
        for (period_index, period) in fixture.periods.iter().enumerate() {
            let expected_height = u32::try_from(period_index + 1)
                .expect("period index fits u32")
                .checked_mul(fixture.miner_window)
                .expect("period height fits u32");
            assert_eq!(period.next_height, expected_height);
            assert_eq!(
                period.period_start_height,
                period.next_height - fixture.miner_window
            );
            assert_eq!(period.period_end_height, period.next_height - 1);
            let _ = decode_hash(&period.period_start_hash);
            let _ = decode_hash(&period.period_end_hash);

            for deployment in Network::Mainnet.deployments() {
                let index = deployment_index(deployment.id);
                states[index] = advance_threshold_state(
                    params.activation_threshold,
                    params.miner_window,
                    *deployment,
                    period.next_height,
                    states[index],
                    Some(DeploymentPeriod {
                        median_time_past: period.median_time_past,
                        signalling_blocks: period.signalling.get(deployment.id),
                    }),
                )
                .unwrap_or_else(|error| {
                    panic!(
                        "{} transition at height {} failed: {error}",
                        deployment.name(),
                        period.next_height
                    )
                });
                assert_eq!(
                    states[index],
                    period.states.get(deployment.id),
                    "{} state at height {}",
                    deployment.name(),
                    period.next_height
                );
            }

            let state = DeploymentState::from_states(states);
            assert_eq!(state.script_flags.bits(), period.effects.script_flags);
            assert_eq!(state.lock_flags, period.effects.lock_flags);
            assert_eq!(state.name_flags.bits(), period.effects.name_flags);
            assert_eq!(state.has_airstop, period.effects.has_airstop);
            assert_eq!(
                is_hsd_historical_height(Network::Mainnet, true, period.next_height),
                period.historical_height
            );
            assert_eq!(
                is_hsd_historical_block(Network::Mainnet, true, period.next_height),
                period.historical_block
            );
            assert_eq!(
                policy.may_assume_scripts(period.next_height),
                period.historical_block
            );
        }
    }

    #[test]
    fn deployment_effects_keep_script_flags_mandatory() {
        for case in fixture().deployment_effect_cases {
            let mut states = [ThresholdState::Defined; 4];
            for name in &case.active {
                states[deployment_index(deployment_id(name))] = ThresholdState::Active;
            }
            let state = DeploymentState::from_states(states);
            assert_eq!(state.script_flags.bits(), case.script_flags);
            assert_eq!(state.lock_flags, case.lock_flags);
            assert_eq!(state.name_flags.bits(), case.name_flags);
            assert_eq!(state.has_airstop, case.has_airstop);
        }
    }

    #[test]
    fn checkpoint_policy_rejects_only_mismatched_pinned_heights() {
        let checkpoint = Network::Mainnet.checkpoints()[0];
        assert!(verify_checkpoint(
            Network::Mainnet,
            true,
            checkpoint.height,
            &checkpoint.hash
        ));
        assert!(!verify_checkpoint(
            Network::Mainnet,
            true,
            checkpoint.height,
            &BlockHash::ZERO
        ));
        assert!(verify_checkpoint(
            Network::Mainnet,
            false,
            checkpoint.height,
            &BlockHash::ZERO
        ));
        assert!(verify_checkpoint(
            Network::Mainnet,
            true,
            checkpoint.height + 1,
            &BlockHash::ZERO
        ));
    }
}
