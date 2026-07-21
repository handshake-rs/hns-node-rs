use hns_primitives::{Height, Outpoint, Transaction, Txid};

use crate::{
    ConsensusError, LOCKTIME_FLAG, LOCKTIME_MASK, SEQUENCE_DISABLE_FLAG, SEQUENCE_GRANULARITY,
    SEQUENCE_MASK, SEQUENCE_TYPE_FLAG,
};

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SequenceLock {
    /// `-1` represents no height constraint, matching hsd's internal model.
    pub minimum_height: i64,
    /// `-1` represents no median-time-past constraint.
    pub minimum_time: i64,
}

impl SequenceLock {
    pub const NONE: Self = Self {
        minimum_height: -1,
        minimum_time: -1,
    };

    pub fn is_satisfied_by(self, next_height: Height, parent_median_time: u64) -> bool {
        (self.minimum_height < 0 || self.minimum_height < i64::from(next_height))
            && (self.minimum_time < 0
                || u64::try_from(self.minimum_time)
                    .is_ok_and(|minimum| minimum < parent_median_time))
    }
}

pub trait SequenceLockView {
    /// Return the active-chain height of the coin. `None` reproduces hsd's
    /// mempool/unconfirmed fallback to the next block height.
    fn coin_height(&self, outpoint: &Outpoint) -> Result<Option<Height>, ConsensusError>;

    /// Return median-time-past for the active-chain ancestor at `height`.
    fn median_time_past(&self, height: Height) -> Result<u64, ConsensusError>;
}

/// Consensus predicate used by OP_CHECKLOCKTIMEVERIFY.
pub fn verify_locktime_predicate(
    transaction: &Transaction,
    input_index: usize,
    predicate: u32,
) -> bool {
    let Some(input) = transaction.inputs.get(input_index) else {
        return false;
    };

    if (transaction.locktime & LOCKTIME_FLAG) != (predicate & LOCKTIME_FLAG) {
        return false;
    }

    if (predicate & LOCKTIME_MASK) > (transaction.locktime & LOCKTIME_MASK) {
        return false;
    }

    input.sequence != u32::MAX
}

/// Consensus predicate used by OP_CHECKSEQUENCEVERIFY.
pub fn verify_sequence_predicate(
    transaction: &Transaction,
    input_index: usize,
    predicate: u32,
) -> bool {
    let Some(input) = transaction.inputs.get(input_index) else {
        return false;
    };

    if predicate & SEQUENCE_DISABLE_FLAG != 0 {
        return true;
    }

    if input.sequence & SEQUENCE_DISABLE_FLAG != 0 {
        return false;
    }

    if (input.sequence & SEQUENCE_TYPE_FLAG) != (predicate & SEQUENCE_TYPE_FLAG) {
        return false;
    }

    (predicate & SEQUENCE_MASK) <= (input.sequence & SEQUENCE_MASK)
}

/// Calculate the BIP68-style relative sequence locks exactly as hsd does.
pub fn calculate_sequence_locks(
    transaction: &Transaction,
    next_height: Height,
    view: &dyn SequenceLockView,
) -> Result<SequenceLock, ConsensusError> {
    if is_coinbase(transaction) {
        return Ok(SequenceLock::NONE);
    }

    let mut locks = SequenceLock::NONE;

    for input in &transaction.inputs {
        let sequence = input.sequence;
        if sequence & SEQUENCE_DISABLE_FLAG != 0 {
            continue;
        }

        let coin_height = view
            .coin_height(&input.previous_output)?
            .unwrap_or(next_height);
        let relative = i64::from(sequence & SEQUENCE_MASK);

        if sequence & SEQUENCE_TYPE_FLAG == 0 {
            let minimum = i64::from(coin_height)
                .checked_add(relative)
                .and_then(|value| value.checked_sub(1))
                .ok_or_else(|| {
                    ConsensusError::Authorization(
                        "relative height lock arithmetic overflow".to_owned(),
                    )
                })?;
            locks.minimum_height = locks.minimum_height.max(minimum);
            continue;
        }

        let ancestor_height = coin_height.saturating_sub(1);
        let median_time = view.median_time_past(ancestor_height)?;
        let relative_seconds = relative
            .checked_shl(SEQUENCE_GRANULARITY)
            .and_then(|value| value.checked_sub(1))
            .ok_or_else(|| {
                ConsensusError::Authorization("relative time lock arithmetic overflow".to_owned())
            })?;
        let minimum = i64::try_from(median_time)
            .ok()
            .and_then(|time| time.checked_add(relative_seconds))
            .ok_or_else(|| {
                ConsensusError::Authorization("relative time lock arithmetic overflow".to_owned())
            })?;
        locks.minimum_time = locks.minimum_time.max(minimum);
    }

    Ok(locks)
}

pub fn verify_sequence_locks(
    transaction: &Transaction,
    next_height: Height,
    parent_median_time: u64,
    view: &dyn SequenceLockView,
) -> Result<bool, ConsensusError> {
    Ok(calculate_sequence_locks(transaction, next_height, view)?
        .is_satisfied_by(next_height, parent_median_time))
}

fn is_coinbase(transaction: &Transaction) -> bool {
    transaction.inputs.len() == 1
        && transaction.inputs[0].previous_output.txid == Txid::ZERO
        && transaction.inputs[0].previous_output.index == u32::MAX
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use hns_primitives::{Input, Outpoint, Transaction, Txid, Witness};

    use super::*;

    #[derive(Default)]
    struct View {
        heights: HashMap<Outpoint, Height>,
        times: HashMap<Height, u64>,
    }

    impl SequenceLockView for View {
        fn coin_height(&self, outpoint: &Outpoint) -> Result<Option<Height>, ConsensusError> {
            Ok(self.heights.get(outpoint).copied())
        }

        fn median_time_past(&self, height: Height) -> Result<u64, ConsensusError> {
            self.times
                .get(&height)
                .copied()
                .ok_or_else(|| ConsensusError::View(format!("missing median time at {height}")))
        }
    }

    fn transaction(sequence: u32) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: Outpoint {
                    txid: Txid::new([1; 32]),
                    index: 0,
                },
                sequence,
                witness: Witness::default(),
            }],
            outputs: Vec::new(),
            locktime: 0,
        }
    }

    #[test]
    fn locktime_predicate_matches_type_value_and_nonfinal_sequence() {
        let mut transaction = transaction(7);
        transaction.locktime = 10;
        assert!(verify_locktime_predicate(&transaction, 0, 9));
        assert!(verify_locktime_predicate(&transaction, 0, 10));
        assert!(!verify_locktime_predicate(
            &transaction,
            0,
            LOCKTIME_FLAG | 9
        ));
        assert!(!verify_locktime_predicate(&transaction, 0, 11));
        transaction.inputs[0].sequence = u32::MAX;
        assert!(!verify_locktime_predicate(&transaction, 0, 10));
    }

    #[test]
    fn sequence_predicate_honors_disable_type_and_mask() {
        let transaction = transaction(12);
        assert!(verify_sequence_predicate(&transaction, 0, 10));
        assert!(!verify_sequence_predicate(&transaction, 0, 13));
        assert!(!verify_sequence_predicate(
            &transaction,
            0,
            SEQUENCE_TYPE_FLAG | 1
        ));
        assert!(verify_sequence_predicate(
            &transaction,
            0,
            SEQUENCE_DISABLE_FLAG
        ));
    }

    #[test]
    fn relative_height_lock_matches_hsd_minus_one_rule() {
        let transaction = transaction(3);
        let outpoint = transaction.inputs[0].previous_output.clone();
        let mut view = View::default();
        view.heights.insert(outpoint, 10);

        let lock = calculate_sequence_locks(&transaction, 20, &view).expect("locks");
        assert_eq!(lock.minimum_height, 12);
        assert!(!lock.is_satisfied_by(12, 0));
        assert!(lock.is_satisfied_by(13, 0));
    }

    #[test]
    fn relative_time_lock_uses_the_prior_coin_ancestor_mtp() {
        let transaction = transaction(SEQUENCE_TYPE_FLAG | 2);
        let outpoint = transaction.inputs[0].previous_output.clone();
        let mut view = View::default();
        view.heights.insert(outpoint, 10);
        view.times.insert(9, 1_000);

        let lock = calculate_sequence_locks(&transaction, 20, &view).expect("locks");
        assert_eq!(lock.minimum_time, 2_023);
        assert!(!lock.is_satisfied_by(20, 2_023));
        assert!(lock.is_satisfied_by(20, 2_024));
    }

    #[derive(serde::Deserialize)]
    struct OracleFixture {
        vectors: Vec<OracleVector>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct OracleVector {
        id: String,
        transaction_raw: String,
        coin_heights: Vec<i64>,
        next_height: Height,
        tip_median_time: u64,
        ancestor_median_times: HashMap<String, u64>,
        minimum_height: i64,
        minimum_time: i64,
        valid: bool,
    }

    #[test]
    fn sequence_locks_match_the_pinned_hsd_oracle() {
        let fixture: OracleFixture = serde_json::from_str(include_str!(
            "../../../fixtures/hsd/scripts/sequence-locks-v1.json"
        ))
        .expect("oracle fixture");

        for vector in fixture.vectors {
            let transaction = Transaction::decode(&decode_hex(&vector.transaction_raw))
                .expect("oracle transaction");
            assert_eq!(transaction.inputs.len(), vector.coin_heights.len());

            let mut view = View::default();
            for (input, height) in transaction.inputs.iter().zip(&vector.coin_heights) {
                if let Ok(height) = Height::try_from(*height) {
                    view.heights.insert(input.previous_output.clone(), height);
                }
            }
            for (height, time) in vector.ancestor_median_times {
                view.times.insert(
                    height.parse::<Height>().expect("oracle ancestor height"),
                    time,
                );
            }

            let lock = calculate_sequence_locks(&transaction, vector.next_height, &view)
                .expect("sequence locks");
            assert_eq!(lock.minimum_height, vector.minimum_height, "{}", vector.id);
            assert_eq!(lock.minimum_time, vector.minimum_time, "{}", vector.id);
            assert_eq!(
                lock.is_satisfied_by(vector.next_height, vector.tip_median_time),
                vector.valid,
                "{}",
                vector.id
            );
        }
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0, "oracle hex length");
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let text = std::str::from_utf8(pair).expect("oracle hex utf8");
                u8::from_str_radix(text, 16).expect("oracle hex byte")
            })
            .collect()
    }
}
