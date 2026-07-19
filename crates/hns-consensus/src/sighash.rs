use hns_primitives::{blake2b_256, Outpoint, Transaction, Txid, Writer};

use crate::ConsensusError;

pub const SIGHASH_ALL: u32 = 1;
pub const SIGHASH_NONE: u32 = 2;
pub const SIGHASH_SINGLE: u32 = 3;
pub const SIGHASH_SINGLE_REVERSE: u32 = 4;
pub const SIGHASH_NOINPUT: u32 = 0x40;
pub const SIGHASH_ANYONE_CAN_PAY: u32 = 0x80;
pub const SIGHASH_BASE_MASK: u32 = 0x1f;

/// Return whether a one-byte Handshake signature hash type is accepted by
/// `hsd`'s signature encoding rules. The low five bits select one of the four
/// defined output modes; NOINPUT and ANYONECANPAY are the only modifier bits.
pub const fn is_valid_signature_hash_type(hash_type: u8) -> bool {
    let normalized = (hash_type as u32) & !(SIGHASH_NOINPUT | SIGHASH_ANYONE_CAN_PAY);
    normalized >= SIGHASH_ALL && normalized <= SIGHASH_SINGLE_REVERSE
}

/// Reproduce `hsd`'s BIP143-style Handshake signature hash exactly, including
/// the historical NOINPUT behavior that nulls only the current input while
/// still committing to the aggregate prevout and sequence hashes.
pub fn signature_hash(
    transaction: &Transaction,
    input_index: usize,
    previous_script: &[u8],
    previous_value: u64,
    hash_type: u32,
) -> Result<[u8; 32], ConsensusError> {
    let input = transaction.inputs.get(input_index).ok_or_else(|| {
        ConsensusError::Authorization(format!(
            "signature input index {input_index} is outside {} inputs",
            transaction.inputs.len()
        ))
    })?;

    let base = hash_type & SIGHASH_BASE_MASK;
    let anyone_can_pay = hash_type & SIGHASH_ANYONE_CAN_PAY != 0;
    let no_input = hash_type & SIGHASH_NOINPUT != 0;
    let zero_hash = [0u8; 32];

    let hash_prevouts = if anyone_can_pay {
        zero_hash
    } else {
        let mut writer = Writer::with_capacity(transaction.inputs.len().saturating_mul(36));
        for transaction_input in &transaction.inputs {
            transaction_input.previous_output.write_to(&mut writer);
        }
        blake2b_256(&writer.finish())
    };

    let hash_sequences = if anyone_can_pay
        || matches!(
            base,
            SIGHASH_NONE | SIGHASH_SINGLE | SIGHASH_SINGLE_REVERSE
        )
    {
        zero_hash
    } else {
        let mut writer = Writer::with_capacity(transaction.inputs.len().saturating_mul(4));
        for transaction_input in &transaction.inputs {
            writer.write_u32(transaction_input.sequence);
        }
        blake2b_256(&writer.finish())
    };

    let hash_outputs = match base {
        SIGHASH_NONE => zero_hash,
        SIGHASH_SINGLE => transaction
            .outputs
            .get(input_index)
            .map(|output| {
                let mut writer = Writer::new();
                output.write_to(&mut writer);
                blake2b_256(&writer.finish())
            })
            .unwrap_or(zero_hash),
        SIGHASH_SINGLE_REVERSE => {
            if input_index < transaction.outputs.len() {
                let output_index = transaction.outputs.len() - 1 - input_index;
                let mut writer = Writer::new();
                transaction.outputs[output_index].write_to(&mut writer);
                blake2b_256(&writer.finish())
            } else {
                zero_hash
            }
        }
        _ => {
            let mut writer = Writer::new();
            for output in &transaction.outputs {
                output.write_to(&mut writer);
            }
            blake2b_256(&writer.finish())
        }
    };

    let (current_outpoint, current_sequence) = if no_input {
        (
            Outpoint {
                txid: Txid::ZERO,
                index: u32::MAX,
            },
            u32::MAX,
        )
    } else {
        (input.previous_output.clone(), input.sequence)
    };

    let mut writer = Writer::with_capacity(156usize.saturating_add(previous_script.len()));
    writer.write_u32(transaction.version);
    writer.write_bytes(&hash_prevouts);
    writer.write_bytes(&hash_sequences);
    current_outpoint.write_to(&mut writer);
    writer.write_varbytes(previous_script);
    writer.write_u64(previous_value);
    writer.write_u32(current_sequence);
    writer.write_bytes(&hash_outputs);
    writer.write_u32(transaction.locktime);
    writer.write_u32(hash_type);

    Ok(blake2b_256(&writer.finish()))
}

#[cfg(test)]
mod tests {
    use hns_primitives::{
        Address, Covenant, CovenantKind, Input, Outpoint, Output, Transaction, Txid, Witness,
    };

    use super::*;

    fn transaction() -> Transaction {
        Transaction {
            version: 2,
            inputs: vec![
                Input {
                    previous_output: Outpoint {
                        txid: Txid::new([0x11; 32]),
                        index: 3,
                    },
                    sequence: 0x1020_3040,
                    witness: Witness::default(),
                },
                Input {
                    previous_output: Outpoint {
                        txid: Txid::new([0x22; 32]),
                        index: 7,
                    },
                    sequence: 0x5060_7080,
                    witness: Witness::default(),
                },
            ],
            outputs: vec![
                Output {
                    value: 10,
                    address: Address::new(0, vec![0x33; 20]).expect("address"),
                    covenant: Covenant {
                        kind: CovenantKind::None,
                        items: Vec::new(),
                    },
                },
                Output {
                    value: 20,
                    address: Address::new(0, vec![0x44; 32]).expect("address"),
                    covenant: Covenant {
                        kind: CovenantKind::None,
                        items: Vec::new(),
                    },
                },
            ],
            locktime: 0x8000_002a,
        }
    }

    #[test]
    fn signature_hash_type_encoding_matches_hsd() {
        for base in 1u8..=4 {
            assert!(is_valid_signature_hash_type(base));
            assert!(is_valid_signature_hash_type(base | SIGHASH_NOINPUT as u8));
            assert!(is_valid_signature_hash_type(
                base | SIGHASH_ANYONE_CAN_PAY as u8
            ));
            assert!(is_valid_signature_hash_type(
                base | SIGHASH_NOINPUT as u8 | SIGHASH_ANYONE_CAN_PAY as u8
            ));
        }
        assert!(!is_valid_signature_hash_type(0));
        assert!(!is_valid_signature_hash_type(5));
        assert!(!is_valid_signature_hash_type(0x20 | SIGHASH_ALL as u8));
    }

    #[test]
    fn signature_hash_changes_across_output_modes_and_modifiers() {
        let transaction = transaction();
        let script = [0x51, 0x75, 0x51];
        let hashes = [
            SIGHASH_ALL,
            SIGHASH_NONE,
            SIGHASH_SINGLE,
            SIGHASH_SINGLE_REVERSE,
            SIGHASH_ALL | SIGHASH_NOINPUT,
            SIGHASH_ALL | SIGHASH_ANYONE_CAN_PAY,
        ]
        .map(|hash_type| {
            signature_hash(&transaction, 0, &script, 50, hash_type).expect("sighash")
        });

        for left in 0..hashes.len() {
            for right in left + 1..hashes.len() {
                assert_ne!(hashes[left], hashes[right]);
            }
        }
    }

    #[test]
    fn signature_hash_rejects_an_out_of_range_input() {
        let error = signature_hash(&transaction(), 2, &[], 0, SIGHASH_ALL)
            .expect_err("invalid input index");
        assert!(error.to_string().contains("outside 2 inputs"));
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct OracleFixture {
        transaction_raw: String,
        previous_script_raw: String,
        previous_value: u64,
        vectors: Vec<OracleVector>,
        signature_types: Vec<OracleSignatureType>,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct OracleVector {
        input_index: usize,
        r#type: u32,
        hash: String,
    }

    #[derive(serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct OracleSignatureType {
        r#type: u8,
        valid: bool,
    }

    #[test]
    fn signature_hash_matches_the_pinned_hsd_oracle() {
        let fixture: OracleFixture = serde_json::from_str(include_str!(
            "../../../fixtures/hsd/scripts/sighash-v1.json"
        ))
        .expect("oracle fixture");
        let transaction = Transaction::decode(&decode_hex(&fixture.transaction_raw))
            .expect("oracle transaction");
        let previous_script = decode_hex(&fixture.previous_script_raw);

        for vector in fixture.vectors {
            let actual = signature_hash(
                &transaction,
                vector.input_index,
                &previous_script,
                fixture.previous_value,
                vector.r#type,
            )
            .expect("signature hash");
            assert_eq!(
                hns_primitives::hex_encode(&actual),
                vector.hash,
                "input {} type 0x{:02x}",
                vector.input_index,
                vector.r#type
            );
        }

        for vector in fixture.signature_types {
            assert_eq!(
                is_valid_signature_hash_type(vector.r#type),
                vector.valid,
                "signature type 0x{:02x}",
                vector.r#type
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
