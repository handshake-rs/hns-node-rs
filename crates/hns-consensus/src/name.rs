use hns_primitives::{
    sha3_256, BlockHash, CovenantKind, Height, NameHash, NameLifecycleState, NameState, Outpoint,
    Transaction, MAX_NAME_SIZE,
};
use serde::{Deserialize, Serialize};

use crate::ConsensusError;

const RESERVED_DB: &[u8] = include_bytes!("../vendor/names.db");
const LOCKUP_DB: &[u8] = include_bytes!("../vendor/lockup.db");

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameParams {
    pub auction_start: Height,
    pub rollout_interval: u32,
    pub lockup_period: u32,
    pub renewal_window: u32,
    pub renewal_period: u32,
    pub renewal_maturity: u32,
    pub claim_period: u32,
    pub alexa_lockup_period: u32,
    pub claim_frequency: u32,
    pub bidding_period: u32,
    pub reveal_period: u32,
    pub tree_interval: u32,
    pub transfer_lockup: u32,
    pub auction_maturity: u32,
    pub no_rollout: bool,
    pub no_reserved: bool,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameFlags(u32);

impl NameFlags {
    pub const NONE: Self = Self(0);
    pub const HARDENED: Self = Self(1 << 0);
    pub const LOCKUP: Self = Self(1 << 1);

    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NameMutation {
    Unchanged,
    Changed,
}

impl NameMutation {
    pub const fn changed(self) -> bool {
        matches!(self, Self::Changed)
    }
}

/// Chain lookups required by contextual covenant verification. Implementations
/// must answer only for the active chain represented by the immutable state
/// snapshot against which the candidate block is being validated.
pub trait NameContext {
    fn main_chain_height(&self, hash: &BlockHash) -> Result<Option<Height>, ConsensusError>;

    /// Historical checkpoint bypasses are deliberately opt-in. A new
    /// implementation should return false until its checkpoint table is
    /// independently verified against the pinned hsd oracle.
    fn is_historical_height(&self, _height: Height) -> bool {
        false
    }
}

pub fn name_lifecycle(state: &NameState, height: Height, params: NameParams) -> NameLifecycleState {
    if state.revoked != 0 {
        return NameLifecycleState::Revoked;
    }

    if state.claimed != 0 {
        if height < state.height.saturating_add(params.lockup_period) {
            return NameLifecycleState::Locked;
        }
        return NameLifecycleState::Closed;
    }

    let open_period = params.tree_interval.saturating_add(1);
    if height < state.height.saturating_add(open_period) {
        return NameLifecycleState::Opening;
    }
    if height
        < state
            .height
            .saturating_add(open_period)
            .saturating_add(params.bidding_period)
    {
        return NameLifecycleState::Bidding;
    }
    if height
        < state
            .height
            .saturating_add(open_period)
            .saturating_add(params.bidding_period)
            .saturating_add(params.reveal_period)
    {
        return NameLifecycleState::Reveal;
    }
    NameLifecycleState::Closed
}

pub fn is_name_claimable(state: &NameState, height: Height, params: NameParams) -> bool {
    state.claimed != 0 && !params.no_reserved && height < params.claim_period
}

pub fn is_name_expired(state: &NameState, height: Height, params: NameParams) -> bool {
    if state.revoked != 0 {
        return height >= state.revoked.saturating_add(params.auction_maturity);
    }

    if name_lifecycle(state, height, params) != NameLifecycleState::Closed {
        return false;
    }

    if is_name_claimable(state, height, params) {
        return false;
    }

    if height >= state.renewal.saturating_add(params.renewal_window) {
        return true;
    }

    state.owner.is_null()
}

pub fn maybe_expire_name(state: &mut NameState, height: Height, params: NameParams) -> bool {
    if !is_name_expired(state, height, params) {
        return false;
    }

    let data = std::mem::take(&mut state.data);
    state.reset(height);
    state.expired = true;
    state.data = data;
    true
}

pub fn rollout_height(name_hash: &NameHash, params: NameParams) -> Height {
    if params.no_rollout {
        return 0;
    }
    let week = mod_buffer(name_hash.as_bytes(), 52);
    params
        .auction_start
        .saturating_add(week.saturating_mul(params.rollout_interval))
}

pub fn has_rollout(name_hash: &NameHash, height: Height, params: NameParams) -> bool {
    height >= rollout_height(name_hash, params)
}

pub fn is_reserved(name_hash: &NameHash, height: Height, params: NameParams) -> bool {
    if params.no_reserved || height >= params.claim_period {
        return false;
    }
    database_contains(RESERVED_DB, 28, name_hash.as_bytes())
}

pub fn is_locked_up(name_hash: &NameHash, height: Height, params: NameParams) -> bool {
    if params.no_reserved || height < params.claim_period {
        return false;
    }

    let Some(pointer) = database_find(LOCKUP_DB, 4, name_hash.as_bytes()) else {
        return false;
    };
    let pointer = pointer as usize;
    let Some(name_len) = LOCKUP_DB.get(pointer).copied().map(usize::from) else {
        return false;
    };
    let flags_offset = pointer.saturating_add(1).saturating_add(name_len);
    let Some(flags) = LOCKUP_DB.get(flags_offset).copied() else {
        return false;
    };

    let root = flags & 1 != 0;
    root || height < params.alexa_lockup_period
}

pub fn verify_renewal_commitment(
    context: &dyn NameContext,
    hash: &BlockHash,
    height: Height,
    params: NameParams,
) -> Result<bool, ConsensusError> {
    if height < params.renewal_maturity {
        return Ok(true);
    }

    let Some(committed_height) = context.main_chain_height(hash)? else {
        return Ok(false);
    };
    if committed_height > height.saturating_sub(params.renewal_maturity) {
        return Ok(false);
    }
    if committed_height < height.saturating_sub(params.renewal_period) {
        return Ok(false);
    }
    Ok(true)
}

/// Apply one non-claim contextual covenant transition to an in-memory name
/// state. The caller owns loading, transaction-local caching, undo capture, and
/// atomic persistence. Claim outputs are rejected here because their DNSSEC
/// ownership proof and inflation accounting require the dedicated coinbase
/// issuance verifier.
pub fn verify_and_apply_name_covenant(
    transaction: &Transaction,
    output_index: usize,
    height: Height,
    params: NameParams,
    flags: NameFlags,
    state: &mut NameState,
    context: &dyn NameContext,
) -> Result<NameMutation, ConsensusError> {
    let output = transaction.outputs.get(output_index).ok_or_else(|| {
        ConsensusError::ContextualCovenant(format!(
            "missing covenant output at index {output_index}"
        ))
    })?;
    let covenant = &output.covenant;
    if !covenant.kind.is_name() {
        return Ok(NameMutation::Unchanged);
    }

    // HSD checkpoints deliberately skip BID and REDEEM contextual reads because
    // neither transition changes NameState. Keep this bypass narrow and opt-in.
    if context.is_historical_height(height)
        && matches!(covenant.kind, CovenantKind::Bid | CovenantKind::Redeem)
    {
        return Ok(NameMutation::Unchanged);
    }

    let name_hash = NameHash::new(required_hash(covenant.item(0), "name hash")?);
    if name_hash != state.name_hash {
        return Err(ConsensusError::ContextualCovenant(
            "name state key does not match covenant name hash".to_owned(),
        ));
    }

    if covenant.kind == CovenantKind::Claim {
        return Err(ConsensusError::ContextualCovenant(
            "CLAIM requires the DNSSEC ownership-proof verifier".to_owned(),
        ));
    }

    let initially_null = state.is_null();
    if initially_null {
        if covenant.kind != CovenantKind::Open {
            return Err(ConsensusError::ContextualCovenant(
                "non-OPEN covenant references an absent name state".to_owned(),
            ));
        }
        let name = covenant.item(2).ok_or_else(|| {
            ConsensusError::ContextualCovenant("OPEN is missing its name".to_owned())
        })?;
        verify_binary_name(name)?;
        if sha3_256(name) != *name_hash.as_bytes() {
            return Err(ConsensusError::ContextualCovenant(
                "OPEN name does not match its committed name hash".to_owned(),
            ));
        }
        state.initialize(name.to_vec(), height);
    }

    let expired = maybe_expire_name(state, height, params);
    let lifecycle = name_lifecycle(state, height, params);
    let start = required_u32(covenant.item(1), "name start height")?;

    match covenant.kind {
        CovenantKind::Open => {
            require_lifecycle(lifecycle, NameLifecycleState::Opening, "OPEN")?;
            if state.height != height {
                return Err(ConsensusError::ContextualCovenant(
                    "OPEN may initialize a name only once".to_owned(),
                ));
            }
            if !state.expired && is_reserved(&name_hash, height, params) {
                return Err(ConsensusError::ContextualCovenant(
                    "OPEN targets a reserved name".to_owned(),
                ));
            }
            if flags.contains(NameFlags::LOCKUP) && is_locked_up(&name_hash, height, params) {
                return Err(ConsensusError::ContextualCovenant(
                    "OPEN targets an ICANN-locked name".to_owned(),
                ));
            }
            if !has_rollout(&name_hash, height, params) {
                return Err(ConsensusError::ContextualCovenant(
                    "OPEN precedes the name rollout height".to_owned(),
                ));
            }
            Ok(NameMutation::Changed)
        }
        CovenantKind::Bid => {
            require_lifecycle(lifecycle, NameLifecycleState::Bidding, "BID")?;
            require_start(start, state.height, "BID")?;
            Ok(if expired {
                NameMutation::Changed
            } else {
                NameMutation::Unchanged
            })
        }
        CovenantKind::Reveal => {
            require_start(start, state.height, "REVEAL")?;
            require_lifecycle(lifecycle, NameLifecycleState::Reveal, "REVEAL")?;
            let new_owner = Outpoint {
                txid: transaction.txid(),
                index: u32::try_from(output_index).map_err(|_| {
                    ConsensusError::ContextualCovenant("REVEAL output index exceeds u32".to_owned())
                })?,
            };
            if state.owner.is_null() || output.value > state.highest {
                state.value = state.highest;
                state.owner = new_owner;
                state.highest = output.value;
            } else if output.value > state.value {
                state.value = output.value;
            }
            Ok(NameMutation::Changed)
        }
        CovenantKind::Redeem => {
            require_start(start, state.height, "REDEEM")?;
            if lifecycle < NameLifecycleState::Closed {
                return Err(ConsensusError::ContextualCovenant(
                    "REDEEM precedes the closed state".to_owned(),
                ));
            }
            let previous_output = &transaction
                .inputs
                .get(output_index)
                .ok_or_else(|| {
                    ConsensusError::ContextualCovenant(
                        "REDEEM is missing its linked input".to_owned(),
                    )
                })?
                .previous_output;
            if previous_output == &state.owner {
                return Err(ConsensusError::ContextualCovenant(
                    "the winning reveal cannot be redeemed".to_owned(),
                ));
            }
            Ok(if expired {
                NameMutation::Changed
            } else {
                NameMutation::Unchanged
            })
        }
        CovenantKind::Register => {
            require_start(start, state.height, "REGISTER")?;
            require_lifecycle(lifecycle, NameLifecycleState::Closed, "REGISTER")?;
            let previous_output = linked_previous_output(transaction, output_index, "REGISTER")?;
            if previous_output != &state.owner {
                return Err(ConsensusError::ContextualCovenant(
                    "REGISTER does not spend the winning reveal".to_owned(),
                ));
            }
            if output.value != state.value {
                return Err(ConsensusError::ContextualCovenant(format!(
                    "REGISTER value {} does not equal second price {}",
                    output.value, state.value
                )));
            }
            let renewal_hash = BlockHash::new(required_hash(covenant.item(3), "renewal hash")?);
            if !verify_renewal_commitment(context, &renewal_hash, height, params)? {
                return Err(ConsensusError::ContextualCovenant(
                    "REGISTER renewal commitment is not on the permitted active-chain window"
                        .to_owned(),
                ));
            }
            if is_name_claimable(state, height, params)
                && flags.contains(NameFlags::HARDENED)
                && state.weak
            {
                return Err(ConsensusError::ContextualCovenant(
                    "hardened covenant rules reject weak claimed-name registration".to_owned(),
                ));
            }
            state.registered = true;
            state.owner = transaction_outpoint(transaction, output_index)?;
            if let Some(data) = covenant.item(2).filter(|data| !data.is_empty()) {
                state.data = data.to_vec();
            }
            state.renewal = height;
            Ok(NameMutation::Changed)
        }
        CovenantKind::Update => {
            require_start(start, state.height, "UPDATE")?;
            require_lifecycle(lifecycle, NameLifecycleState::Closed, "UPDATE")?;
            state.owner = transaction_outpoint(transaction, output_index)?;
            if let Some(data) = covenant.item(2).filter(|data| !data.is_empty()) {
                state.data = data.to_vec();
            }
            state.transfer = 0;
            Ok(NameMutation::Changed)
        }
        CovenantKind::Renew => {
            require_start(start, state.height, "RENEW")?;
            require_lifecycle(lifecycle, NameLifecycleState::Closed, "RENEW")?;
            if height < state.renewal.saturating_add(params.tree_interval) {
                return Err(ConsensusError::ContextualCovenant(
                    "RENEW is premature".to_owned(),
                ));
            }
            let renewal_hash = BlockHash::new(required_hash(covenant.item(2), "renewal hash")?);
            if !verify_renewal_commitment(context, &renewal_hash, height, params)? {
                return Err(ConsensusError::ContextualCovenant(
                    "RENEW commitment is not on the permitted active-chain window".to_owned(),
                ));
            }
            state.owner = transaction_outpoint(transaction, output_index)?;
            state.transfer = 0;
            state.renewal = height;
            state.renewals = state.renewals.checked_add(1).ok_or_else(|| {
                ConsensusError::ContextualCovenant("name renewal counter overflow".to_owned())
            })?;
            Ok(NameMutation::Changed)
        }
        CovenantKind::Transfer => {
            require_start(start, state.height, "TRANSFER")?;
            require_lifecycle(lifecycle, NameLifecycleState::Closed, "TRANSFER")?;
            if state.transfer != 0 {
                return Err(ConsensusError::ContextualCovenant(
                    "name is already in transfer".to_owned(),
                ));
            }
            state.owner = transaction_outpoint(transaction, output_index)?;
            state.transfer = height;
            Ok(NameMutation::Changed)
        }
        CovenantKind::Finalize => {
            require_start(start, state.height, "FINALIZE")?;
            require_lifecycle(lifecycle, NameLifecycleState::Closed, "FINALIZE")?;
            if state.transfer == 0 {
                return Err(ConsensusError::ContextualCovenant(
                    "FINALIZE has no pending transfer".to_owned(),
                ));
            }
            if height < state.transfer.saturating_add(params.transfer_lockup) {
                return Err(ConsensusError::ContextualCovenant(
                    "FINALIZE precedes transfer maturity".to_owned(),
                ));
            }
            let weak = required_u8(covenant.item(3), "finalize flags")? & 1 != 0;
            let claimed = required_u32(covenant.item(4), "claimed height")?;
            let renewals = required_u32(covenant.item(5), "renewal count")?;
            if weak != state.weak || claimed != state.claimed || renewals != state.renewals {
                return Err(ConsensusError::ContextualCovenant(
                    "FINALIZE state-transfer commitment does not match name state".to_owned(),
                ));
            }
            let renewal_hash = BlockHash::new(required_hash(covenant.item(6), "renewal hash")?);
            if !verify_renewal_commitment(context, &renewal_hash, height, params)? {
                return Err(ConsensusError::ContextualCovenant(
                    "FINALIZE renewal commitment is not on the permitted active-chain window"
                        .to_owned(),
                ));
            }
            state.owner = transaction_outpoint(transaction, output_index)?;
            state.transfer = 0;
            state.renewal = height;
            state.renewals = state.renewals.checked_add(1).ok_or_else(|| {
                ConsensusError::ContextualCovenant("name renewal counter overflow".to_owned())
            })?;
            Ok(NameMutation::Changed)
        }
        CovenantKind::Revoke => {
            require_start(start, state.height, "REVOKE")?;
            require_lifecycle(lifecycle, NameLifecycleState::Closed, "REVOKE")?;
            if state.revoked != 0 {
                return Err(ConsensusError::ContextualCovenant(
                    "name is already revoked".to_owned(),
                ));
            }
            state.revoked = height;
            state.transfer = 0;
            state.data.clear();
            Ok(NameMutation::Changed)
        }
        CovenantKind::None | CovenantKind::Claim | CovenantKind::Unknown(_) => {
            Err(ConsensusError::ContextualCovenant(format!(
                "unexpected contextual name covenant {:?}",
                covenant.kind
            )))
        }
    }
}

fn verify_binary_name(name: &[u8]) -> Result<(), ConsensusError> {
    if name.is_empty() || name.len() > MAX_NAME_SIZE {
        return Err(ConsensusError::ContextualCovenant(
            "OPEN contains an invalid name length".to_owned(),
        ));
    }

    for (index, byte) in name.iter().copied().enumerate() {
        let alpha = byte.is_ascii_lowercase();
        let digit = byte.is_ascii_digit();
        let separator = matches!(byte, b'-' | b'_');
        if !(alpha || digit || separator) {
            return Err(ConsensusError::ContextualCovenant(
                "OPEN contains an invalid name character".to_owned(),
            ));
        }
        if separator && (index == 0 || index + 1 == name.len()) {
            return Err(ConsensusError::ContextualCovenant(
                "OPEN name begins or ends with a separator".to_owned(),
            ));
        }
    }

    const BLACKLIST: [&[u8]; 5] = [b"example", b"invalid", b"local", b"localhost", b"test"];
    if BLACKLIST.contains(&name) {
        return Err(ConsensusError::ContextualCovenant(
            "OPEN targets a consensus-blacklisted name".to_owned(),
        ));
    }

    Ok(())
}

fn require_lifecycle(
    actual: NameLifecycleState,
    expected: NameLifecycleState,
    operation: &'static str,
) -> Result<(), ConsensusError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ConsensusError::ContextualCovenant(format!(
            "{operation} requires {expected:?} name state, got {actual:?}"
        )))
    }
}

fn require_start(
    actual: Height,
    expected: Height,
    operation: &'static str,
) -> Result<(), ConsensusError> {
    if actual == expected {
        Ok(())
    } else {
        Err(ConsensusError::ContextualCovenant(format!(
            "{operation} start height {actual} does not match name height {expected}"
        )))
    }
}

fn linked_previous_output<'a>(
    transaction: &'a Transaction,
    output_index: usize,
    operation: &'static str,
) -> Result<&'a Outpoint, ConsensusError> {
    transaction
        .inputs
        .get(output_index)
        .map(|input| &input.previous_output)
        .ok_or_else(|| {
            ConsensusError::ContextualCovenant(format!("{operation} is missing its linked input"))
        })
}

fn transaction_outpoint(
    transaction: &Transaction,
    output_index: usize,
) -> Result<Outpoint, ConsensusError> {
    Ok(Outpoint {
        txid: transaction.txid(),
        index: u32::try_from(output_index).map_err(|_| {
            ConsensusError::ContextualCovenant("output index exceeds u32".to_owned())
        })?,
    })
}

fn required_hash(item: Option<&[u8]>, label: &'static str) -> Result<[u8; 32], ConsensusError> {
    item.and_then(|item| item.try_into().ok())
        .ok_or_else(|| ConsensusError::ContextualCovenant(format!("invalid or missing {label}")))
}

fn required_u32(item: Option<&[u8]>, label: &'static str) -> Result<u32, ConsensusError> {
    item.and_then(|item| item.try_into().ok())
        .map(u32::from_le_bytes)
        .ok_or_else(|| ConsensusError::ContextualCovenant(format!("invalid or missing {label}")))
}

fn required_u8(item: Option<&[u8]>, label: &'static str) -> Result<u8, ConsensusError> {
    item.and_then(|item| (item.len() == 1).then_some(item[0]))
        .ok_or_else(|| ConsensusError::ContextualCovenant(format!("invalid or missing {label}")))
}

fn mod_buffer(bytes: &[u8], modulus: u32) -> u32 {
    debug_assert!((1..=u8::MAX as u32).contains(&modulus));
    let factor = 256 % modulus;
    bytes.iter().fold(0u32, |accumulator, byte| {
        (factor * accumulator + u32::from(*byte)) % modulus
    })
}

fn database_contains(database: &[u8], prefix_size: usize, hash: &[u8; 32]) -> bool {
    database_find(database, prefix_size, hash).is_some()
}

fn database_find(database: &[u8], prefix_size: usize, hash: &[u8; 32]) -> Option<u32> {
    let size = read_u32(database, 0)? as usize;
    let mut start = 0usize;
    let mut end = size.checked_sub(1)?;

    while start <= end {
        let index = start + (end - start) / 2;
        let position = prefix_size.checked_add(index.checked_mul(36)?)?;
        let candidate = database.get(position..position.checked_add(32)?)?;
        match candidate.cmp(hash.as_slice()) {
            std::cmp::Ordering::Equal => return read_u32(database, position + 32),
            std::cmp::Ordering::Less => start = index.saturating_add(1),
            std::cmp::Ordering::Greater => {
                let Some(previous) = index.checked_sub(1) else {
                    break;
                };
                end = previous;
            }
        }
    }
    None
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    let end = offset.checked_add(4)?;
    let value: [u8; 4] = bytes.get(offset..end)?.try_into().ok()?;
    Some(u32::from_le_bytes(value))
}

#[cfg(test)]
mod tests {
    use hns_primitives::Amount;

    use hns_primitives::{blake2b_256, Address, Covenant, Input, Output, Txid, Witness};
    use serde::Deserialize;

    use super::*;
    use crate::Network;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NamePolicyFixture {
        parameters: NamePolicyParameters,
        datasets: NamePolicyDatasets,
        renewal_commitment_cases: Vec<RenewalCommitmentCase>,
        cases: Vec<NamePolicyCase>,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NamePolicyParameters {
        claim_period: u32,
        alexa_lockup_period: u32,
        renewal_maturity: u32,
        renewal_period: u32,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NamePolicyDatasets {
        names_db_blake2b256: String,
        lockup_db_blake2b256: String,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct NamePolicyCase {
        name_hash: String,
        height: u32,
        reserved: bool,
        locked: bool,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct RenewalCommitmentCase {
        height: u32,
        committed_height: Option<u32>,
        accepted: bool,
    }

    fn hex(bytes: &[u8]) -> String {
        const TABLE: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(TABLE[usize::from(byte >> 4)] as char);
            output.push(TABLE[usize::from(byte & 0x0f)] as char);
        }
        output
    }

    fn decode_hash(value: &str) -> [u8; 32] {
        assert_eq!(value.len(), 64);
        let mut output = [0u8; 32];
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16).expect("hex byte");
        }
        output
    }

    #[derive(Default)]
    struct Context {
        heights: std::collections::HashMap<BlockHash, Height>,
    }

    impl NameContext for Context {
        fn main_chain_height(&self, hash: &BlockHash) -> Result<Option<Height>, ConsensusError> {
            Ok(self.heights.get(hash).copied())
        }
    }

    fn params() -> NameParams {
        NameParams {
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
            no_rollout: true,
            no_reserved: true,
        }
    }

    fn covenant(kind: CovenantKind, hash: NameHash, start: Height, tail: Vec<Vec<u8>>) -> Covenant {
        let mut items = vec![hash.as_bytes().to_vec(), start.to_le_bytes().to_vec()];
        items.extend(tail);
        Covenant { kind, items }
    }

    fn transaction(
        kind: CovenantKind,
        hash: NameHash,
        start: Height,
        tail: Vec<Vec<u8>>,
        value: Amount,
    ) -> Transaction {
        Transaction {
            version: 0,
            inputs: vec![Input {
                previous_output: Outpoint {
                    txid: Txid::new([9; 32]),
                    index: 0,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value,
                address: Address::new(0, vec![7; 20]).expect("address"),
                covenant: covenant(kind, hash, start, tail),
            }],
            locktime: 0,
        }
    }

    #[test]
    fn lifecycle_matches_open_bid_reveal_closed_boundaries() {
        let state = NameState {
            name_hash: NameHash::new([1; 32]),
            name: b"alpha".to_vec(),
            height: 100,
            renewal: 100,
            owner: Outpoint::null(),
            value: 0,
            highest: 0,
            data: Vec::new(),
            transfer: 0,
            revoked: 0,
            claimed: 0,
            renewals: 0,
            registered: false,
            expired: false,
            weak: false,
        };
        assert_eq!(
            name_lifecycle(&state, 105, params()),
            NameLifecycleState::Opening
        );
        assert_eq!(
            name_lifecycle(&state, 106, params()),
            NameLifecycleState::Bidding
        );
        assert_eq!(
            name_lifecycle(&state, 111, params()),
            NameLifecycleState::Reveal
        );
        assert_eq!(
            name_lifecycle(&state, 121, params()),
            NameLifecycleState::Closed
        );
    }

    #[test]
    fn open_initializes_an_absent_name_state() {
        let hash = NameHash::new(hns_primitives::sha3_256(b"alpha"));
        let transaction = transaction(CovenantKind::Open, hash, 0, vec![b"alpha".to_vec()], 0);
        let mut state = NameState::null(hash);
        assert_eq!(
            verify_and_apply_name_covenant(
                &transaction,
                0,
                100,
                params(),
                NameFlags::NONE,
                &mut state,
                &Context::default(),
            )
            .expect("open"),
            NameMutation::Changed
        );
        assert_eq!(state.name, b"alpha");
        assert_eq!(state.height, 100);
    }

    #[test]
    fn renewal_window_uses_active_chain_height() {
        let hash = BlockHash::new([8; 32]);
        let mut context = Context::default();
        context.heights.insert(hash, 1_000);
        assert!(verify_renewal_commitment(&context, &hash, 1_060, params()).unwrap());
        assert!(!verify_renewal_commitment(&context, &hash, 3_600, params()).unwrap());
    }

    #[test]
    fn reserved_and_lockup_policy_matches_the_pinned_hsd_oracle() {
        let fixture: NamePolicyFixture = serde_json::from_str(include_str!(
            "../../../fixtures/hsd/name-states/name-policy-v1.json"
        ))
        .expect("fixture");
        let params = Network::Mainnet.params().names;
        assert_eq!(params.claim_period, fixture.parameters.claim_period);
        assert_eq!(
            params.alexa_lockup_period,
            fixture.parameters.alexa_lockup_period
        );
        assert_eq!(params.renewal_maturity, fixture.parameters.renewal_maturity);
        assert_eq!(params.renewal_period, fixture.parameters.renewal_period);
        assert_eq!(
            hex(&blake2b_256(RESERVED_DB)),
            fixture.datasets.names_db_blake2b256
        );
        assert_eq!(
            hex(&blake2b_256(LOCKUP_DB)),
            fixture.datasets.lockup_db_blake2b256
        );

        for case in fixture.cases {
            let hash = NameHash::new(decode_hash(&case.name_hash));
            assert_eq!(
                is_reserved(&hash, case.height, params),
                case.reserved,
                "reserved policy mismatch at height {} for {}",
                case.height,
                case.name_hash
            );
            assert_eq!(
                is_locked_up(&hash, case.height, params),
                case.locked,
                "lockup policy mismatch at height {} for {}",
                case.height,
                case.name_hash
            );
        }

        let renewal_hash = BlockHash::new([0x88; 32]);
        for case in fixture.renewal_commitment_cases {
            let mut context = Context::default();
            if let Some(height) = case.committed_height {
                context.heights.insert(renewal_hash, height);
            }
            assert_eq!(
                verify_renewal_commitment(&context, &renewal_hash, case.height, params)
                    .expect("renewal commitment"),
                case.accepted,
                "renewal commitment mismatch at height {} with committed height {:?}",
                case.height,
                case.committed_height
            );
        }
    }

    #[test]
    fn vendored_reserved_and_lockup_databases_are_well_formed() {
        assert!(read_u32(RESERVED_DB, 0).is_some_and(|size| size > 0));
        assert!(read_u32(LOCKUP_DB, 0).is_some_and(|size| size > 0));
        let first_reserved: [u8; 32] = RESERVED_DB[28..60].try_into().expect("hash");
        assert!(database_contains(RESERVED_DB, 28, &first_reserved));
        let first_locked: [u8; 32] = LOCKUP_DB[4..36].try_into().expect("hash");
        assert!(database_contains(LOCKUP_DB, 4, &first_locked));
    }
}
