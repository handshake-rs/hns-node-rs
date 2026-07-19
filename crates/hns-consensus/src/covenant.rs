use hns_primitives::{
    blake2b_256, Coin, Covenant, CovenantKind, Outpoint, Output, Transaction, Writer,
};
use serde::{Deserialize, Serialize};

use crate::is_coinbase;

/// Observable result of the input/output covenant-linkage pass. This pass is
/// deliberately narrower than Handshake name-state validation: it proves that
/// each spent covenant is allowed to produce the output at the same index and
/// that all local commitments match. Auction phase, ownership, renewal,
/// reserved-name, rollout and Urkel checks remain separate consensus stages.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CovenantLinkSummary {
    pub inputs_checked: usize,
    pub linked_outputs: usize,
    pub name_inputs: usize,
}

/// Reproduce `hsd`'s blind-bid commitment: BLAKE2b-256 over the little-endian
/// bid value followed by the 32-byte nonce.
pub fn blind_bid(value: u64, nonce: &[u8; 32]) -> [u8; 32] {
    let mut writer = Writer::with_capacity(40);
    writer.write_u64(value);
    writer.write_bytes(nonce);
    blake2b_256(&writer.finish())
}

/// Verify the non-coinbase covenant linkage rules implemented by
/// `hsd/lib/covenants/rules.js::verifyCovenants`.
///
/// `input_coins` must be ordered exactly like `transaction.inputs`. The
/// function performs no database access, no name-state mutation and no script
/// verification, making it deterministic and independently testable.
pub fn verify_transaction_covenant_links(
    transaction: &Transaction,
    input_coins: &[Coin],
) -> Result<CovenantLinkSummary, CovenantLinkError> {
    if is_coinbase(transaction) {
        return Err(CovenantLinkError::CoinbaseRequiresIssuanceVerifier);
    }

    if transaction.inputs.len() != input_coins.len() {
        return Err(CovenantLinkError::InputCountMismatch {
            transaction: transaction.inputs.len(),
            coins: input_coins.len(),
        });
    }

    let mut summary = CovenantLinkSummary {
        inputs_checked: input_coins.len(),
        ..CovenantLinkSummary::default()
    };

    for (input_index, (input, coin)) in transaction
        .inputs
        .iter()
        .zip(input_coins)
        .enumerate()
    {
        if input.previous_output != coin.outpoint {
            return Err(CovenantLinkError::CoinOutpointMismatch {
                input_index,
                expected: input.previous_output.clone(),
                actual: coin.outpoint.clone(),
            });
        }

        let output = transaction.outputs.get(input_index);
        let spent = &coin.covenant;
        let spent_kind = spent.kind;

        if spent_kind.is_name() {
            summary.name_inputs += 1;
        }

        match spent_kind {
            CovenantKind::None | CovenantKind::Open | CovenantKind::Redeem => {
                let Some(output) = output else {
                    continue;
                };

                if !matches!(
                    output.covenant.kind,
                    CovenantKind::None | CovenantKind::Open | CovenantKind::Bid
                ) {
                    return Err(CovenantLinkError::InvalidTransition {
                        input_index,
                        from: spent_kind,
                        to: output.covenant.kind,
                    });
                }
            }
            CovenantKind::Bid => {
                let output = require_linked_output(input_index, spent_kind, output)?;
                require_transition(input_index, spent_kind, output, CovenantKind::Reveal)?;
                require_name_and_start_match(input_index, spent, &output.covenant)?;

                let nonce = required_hash(input_index, &output.covenant, 2, "reveal nonce")?;
                let commitment = required_hash(input_index, spent, 3, "bid commitment")?;
                if blind_bid(output.value, &nonce) != commitment {
                    return Err(CovenantLinkError::BlindCommitmentMismatch { input_index });
                }
                if coin.value < output.value {
                    return Err(CovenantLinkError::BidValueInflation {
                        input_index,
                        locked: coin.value,
                        revealed: output.value,
                    });
                }
                summary.linked_outputs += 1;
            }
            CovenantKind::Claim | CovenantKind::Reveal => {
                let output = require_linked_output(input_index, spent_kind, output)?;
                match output.covenant.kind {
                    CovenantKind::Register => {
                        require_name_and_start_match(input_index, spent, &output.covenant)?;
                        require_address_match(input_index, &coin.address, output)?;
                    }
                    CovenantKind::Redeem => {
                        require_name_and_start_match(input_index, spent, &output.covenant)?;
                        if spent_kind == CovenantKind::Claim {
                            return Err(CovenantLinkError::ClaimCannotRedeem { input_index });
                        }
                    }
                    to => {
                        return Err(CovenantLinkError::InvalidTransition {
                            input_index,
                            from: spent_kind,
                            to,
                        });
                    }
                }
                summary.linked_outputs += 1;
            }
            CovenantKind::Register
            | CovenantKind::Update
            | CovenantKind::Renew
            | CovenantKind::Finalize => {
                let output = require_linked_output(input_index, spent_kind, output)?;
                require_locked_value(input_index, coin, output)?;
                require_address_match(input_index, &coin.address, output)?;

                if !matches!(
                    output.covenant.kind,
                    CovenantKind::Update
                        | CovenantKind::Renew
                        | CovenantKind::Transfer
                        | CovenantKind::Revoke
                ) {
                    return Err(CovenantLinkError::InvalidTransition {
                        input_index,
                        from: spent_kind,
                        to: output.covenant.kind,
                    });
                }
                require_name_and_start_match(input_index, spent, &output.covenant)?;
                summary.linked_outputs += 1;
            }
            CovenantKind::Transfer => {
                let output = require_linked_output(input_index, spent_kind, output)?;
                require_locked_value(input_index, coin, output)?;

                match output.covenant.kind {
                    CovenantKind::Update | CovenantKind::Renew | CovenantKind::Revoke => {
                        require_name_and_start_match(input_index, spent, &output.covenant)?;
                        require_address_match(input_index, &coin.address, output)?;
                    }
                    CovenantKind::Finalize => {
                        require_name_and_start_match(input_index, spent, &output.covenant)?;
                        let version = required_u8(
                            input_index,
                            spent,
                            2,
                            "transfer destination version",
                        )?;
                        let hash = required_item(
                            input_index,
                            spent,
                            3,
                            "transfer destination hash",
                        )?;
                        if output.address.version != version
                            || output.address.hash.as_slice() != hash
                        {
                            return Err(CovenantLinkError::TransferDestinationMismatch {
                                input_index,
                            });
                        }
                    }
                    to => {
                        return Err(CovenantLinkError::InvalidTransition {
                            input_index,
                            from: spent_kind,
                            to,
                        });
                    }
                }
                summary.linked_outputs += 1;
            }
            CovenantKind::Revoke => {
                return Err(CovenantLinkError::RevokedCoinSpent { input_index });
            }
            CovenantKind::Unknown(_) => {
                if let Some(output) = output {
                    if output.covenant.kind.is_name() {
                        return Err(CovenantLinkError::UnknownCovenantCreatesName {
                            input_index,
                            to: output.covenant.kind,
                        });
                    }
                }
            }
        }
    }

    Ok(summary)
}

fn require_linked_output<'a>(
    input_index: usize,
    from: CovenantKind,
    output: Option<&'a Output>,
) -> Result<&'a Output, CovenantLinkError> {
    output.ok_or(CovenantLinkError::MissingLinkedOutput { input_index, from })
}

fn require_transition(
    input_index: usize,
    from: CovenantKind,
    output: &Output,
    expected: CovenantKind,
) -> Result<(), CovenantLinkError> {
    if output.covenant.kind != expected {
        return Err(CovenantLinkError::InvalidTransition {
            input_index,
            from,
            to: output.covenant.kind,
        });
    }
    Ok(())
}

fn require_name_and_start_match(
    input_index: usize,
    spent: &Covenant,
    created: &Covenant,
) -> Result<(), CovenantLinkError> {
    let spent_name = required_hash(input_index, spent, 0, "spent name hash")?;
    let created_name = required_hash(input_index, created, 0, "created name hash")?;
    if spent_name != created_name {
        return Err(CovenantLinkError::NameHashMismatch { input_index });
    }

    let spent_start = required_u32(input_index, spent, 1, "spent start height")?;
    let created_start = required_u32(input_index, created, 1, "created start height")?;
    if spent_start != created_start {
        return Err(CovenantLinkError::StartHeightMismatch {
            input_index,
            spent: spent_start,
            created: created_start,
        });
    }
    Ok(())
}

fn require_locked_value(
    input_index: usize,
    coin: &Coin,
    output: &Output,
) -> Result<(), CovenantLinkError> {
    if output.value != coin.value {
        return Err(CovenantLinkError::LockedValueMismatch {
            input_index,
            spent: coin.value,
            created: output.value,
        });
    }
    Ok(())
}

fn require_address_match(
    input_index: usize,
    expected: &hns_primitives::Address,
    output: &Output,
) -> Result<(), CovenantLinkError> {
    if &output.address != expected {
        return Err(CovenantLinkError::AddressMismatch { input_index });
    }
    Ok(())
}

fn required_item<'a>(
    input_index: usize,
    covenant: &'a Covenant,
    item_index: usize,
    field: &'static str,
) -> Result<&'a [u8], CovenantLinkError> {
    covenant
        .item(item_index)
        .ok_or(CovenantLinkError::MalformedInputCovenant {
            input_index,
            field,
        })
}

fn required_u8(
    input_index: usize,
    covenant: &Covenant,
    item_index: usize,
    field: &'static str,
) -> Result<u8, CovenantLinkError> {
    covenant
        .item_u8(item_index)
        .ok_or(CovenantLinkError::MalformedInputCovenant {
            input_index,
            field,
        })
}

fn required_u32(
    input_index: usize,
    covenant: &Covenant,
    item_index: usize,
    field: &'static str,
) -> Result<u32, CovenantLinkError> {
    covenant
        .item_u32(item_index)
        .ok_or(CovenantLinkError::MalformedInputCovenant {
            input_index,
            field,
        })
}

fn required_hash(
    input_index: usize,
    covenant: &Covenant,
    item_index: usize,
    field: &'static str,
) -> Result<[u8; 32], CovenantLinkError> {
    covenant
        .item_hash(item_index)
        .ok_or(CovenantLinkError::MalformedInputCovenant {
            input_index,
            field,
        })
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum CovenantLinkError {
    #[error("coinbase covenant issuance requires the dedicated claim/airdrop verifier")]
    CoinbaseRequiresIssuanceVerifier,
    #[error("transaction has {transaction} inputs but {coins} resolved input coins")]
    InputCountMismatch { transaction: usize, coins: usize },
    #[error(
        "input {input_index} spends {expected:?}, but its resolved coin is keyed by {actual:?}"
    )]
    CoinOutpointMismatch {
        input_index: usize,
        expected: Outpoint,
        actual: Outpoint,
    },
    #[error("input {input_index} covenant {from:?} requires a linked output")]
    MissingLinkedOutput {
        input_index: usize,
        from: CovenantKind,
    },
    #[error("input {input_index} covenant transition {from:?} -> {to:?} is invalid")]
    InvalidTransition {
        input_index: usize,
        from: CovenantKind,
        to: CovenantKind,
    },
    #[error("input {input_index} covenant is missing or mis-encodes {field}")]
    MalformedInputCovenant {
        input_index: usize,
        field: &'static str,
    },
    #[error("input {input_index} name hash does not match its linked output")]
    NameHashMismatch { input_index: usize },
    #[error(
        "input {input_index} start height {spent} does not match linked output height {created}"
    )]
    StartHeightMismatch {
        input_index: usize,
        spent: u32,
        created: u32,
    },
    #[error("input {input_index} reveal value and nonce do not match the bid commitment")]
    BlindCommitmentMismatch { input_index: usize },
    #[error(
        "input {input_index} reveal value {revealed} exceeds locked bid value {locked}"
    )]
    BidValueInflation {
        input_index: usize,
        locked: u64,
        revealed: u64,
    },
    #[error("input {input_index} claim covenant cannot transition to REDEEM")]
    ClaimCannotRedeem { input_index: usize },
    #[error("input {input_index} linked output address does not match the locked address")]
    AddressMismatch { input_index: usize },
    #[error(
        "input {input_index} locked value {spent} does not match linked output value {created}"
    )]
    LockedValueMismatch {
        input_index: usize,
        spent: u64,
        created: u64,
    },
    #[error("input {input_index} FINALIZE address does not match the TRANSFER commitment")]
    TransferDestinationMismatch { input_index: usize },
    #[error("input {input_index} attempts to spend a permanently revoked name coin")]
    RevokedCoinSpent { input_index: usize },
    #[error("input {input_index} unknown covenant cannot create name covenant {to:?}")]
    UnknownCovenantCreatesName {
        input_index: usize,
        to: CovenantKind,
    },
}

#[cfg(test)]
mod tests {
    use hns_primitives::{
        Address, Covenant, Input, Outpoint, Output, Transaction, Txid, Witness,
    };

    use super::*;

    fn address(byte: u8) -> Address {
        Address::new(0, vec![byte; 20]).expect("address")
    }

    fn outpoint(byte: u8, index: u32) -> Outpoint {
        Outpoint {
            txid: Txid::new([byte; 32]),
            index,
        }
    }

    fn covenant(kind: CovenantKind, items: Vec<Vec<u8>>) -> Covenant {
        Covenant { kind, items }
    }

    fn coin(outpoint: Outpoint, value: u64, address: Address, covenant: Covenant) -> Coin {
        Coin {
            outpoint,
            value,
            height: 1,
            coinbase: false,
            address,
            covenant,
        }
    }

    fn transaction(previous_output: Outpoint, output: Output) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output,
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![output],
            locktime: 0,
        }
    }

    #[test]
    fn bid_to_reveal_checks_the_blind_commitment() {
        let previous_output = outpoint(1, 0);
        let name_hash = [2u8; 32];
        let nonce = [3u8; 32];
        let value = 100;
        let spent = covenant(
            CovenantKind::Bid,
            vec![
                name_hash.to_vec(),
                9u32.to_le_bytes().to_vec(),
                b"example".to_vec(),
                blind_bid(value, &nonce).to_vec(),
            ],
        );
        let created = covenant(
            CovenantKind::Reveal,
            vec![
                name_hash.to_vec(),
                9u32.to_le_bytes().to_vec(),
                nonce.to_vec(),
            ],
        );
        let owner = address(4);
        let coin = coin(previous_output.clone(), value, owner.clone(), spent);
        let transaction = transaction(
            previous_output,
            Output {
                value,
                address: owner,
                covenant: created,
            },
        );

        let summary = verify_transaction_covenant_links(&transaction, &[coin])
            .expect("valid bid reveal");
        assert_eq!(summary.linked_outputs, 1);
        assert_eq!(summary.name_inputs, 1);
    }

    #[test]
    fn revoke_is_permanently_unspendable() {
        let previous_output = outpoint(5, 0);
        let coin = coin(
            previous_output.clone(),
            1,
            address(6),
            covenant(
                CovenantKind::Revoke,
                vec![[7u8; 32].to_vec(), 3u32.to_le_bytes().to_vec()],
            ),
        );
        let transaction = transaction(
            previous_output,
            Output {
                value: 1,
                address: address(6),
                covenant: covenant(CovenantKind::None, Vec::new()),
            },
        );

        assert_eq!(
            verify_transaction_covenant_links(&transaction, &[coin]),
            Err(CovenantLinkError::RevokedCoinSpent { input_index: 0 })
        );
    }
    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct OracleFixture {
        cases: Vec<OracleCase>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct OracleCase {
        id: String,
        accepted: bool,
        transaction_raw: String,
        input_coins: Vec<OracleCoin>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct OracleCoin {
        outpoint_txid: String,
        outpoint_index: u32,
        value: u64,
        height: u32,
        coinbase: bool,
        address_version: u8,
        address_hash: String,
        covenant_type: u8,
        covenant_items: Vec<String>,
    }

    #[test]
    fn covenant_linkage_matches_the_pinned_hsd_oracle() {
        let fixture: OracleFixture = serde_json::from_str(include_str!(
            "../../../fixtures/hsd/covenants/linkage-v1.json"
        ))
        .expect("covenant linkage fixture");

        for case in fixture.cases {
            let transaction = Transaction::decode(&decode_hex(&case.transaction_raw))
                .unwrap_or_else(|error| panic!("{} transaction: {error}", case.id));
            let input_coins = case
                .input_coins
                .into_iter()
                .map(|coin| {
                    let txid: [u8; 32] = decode_hex(&coin.outpoint_txid)
                        .try_into()
                        .expect("32-byte fixture txid");
                    Coin {
                        outpoint: Outpoint {
                            txid: Txid::new(txid),
                            index: coin.outpoint_index,
                        },
                        value: coin.value,
                        height: coin.height,
                        coinbase: coin.coinbase,
                        address: Address::new(
                            coin.address_version,
                            decode_hex(&coin.address_hash),
                        )
                        .expect("fixture address"),
                        covenant: Covenant {
                            kind: CovenantKind::from_u8(coin.covenant_type),
                            items: coin
                                .covenant_items
                                .iter()
                                .map(|item| decode_hex(item))
                                .collect(),
                        },
                    }
                })
                .collect::<Vec<_>>();
            let accepted = verify_transaction_covenant_links(&transaction, &input_coins).is_ok();
            assert_eq!(accepted, case.accepted, "oracle case {}", case.id);
        }
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0, "hex length");
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| {
                let high = decode_nibble(pair[0]).expect("hex high nibble");
                let low = decode_nibble(pair[1]).expect("hex low nibble");
                (high << 4) | low
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

}
