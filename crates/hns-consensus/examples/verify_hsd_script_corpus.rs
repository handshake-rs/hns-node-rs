use std::{env, error::Error, fs, path::Path};

use hns_consensus::{
    count_script_sigops, verify_witness_program, NativeSignatureVerifier, ScriptFlags,
};
use hns_primitives::{sha3_256, Address, Coin, Covenant, CovenantKind, Transaction};
use serde::Deserialize;

const HSD_REPOSITORY: &str = "handshake-org/hsd";
const HSD_REVISION: &str = "698e252ebc7b5c1dd0a9587e342fdd153d020ae4";
const HSD_VERSION: &str = "8.99.0";
const HSD_SCRIPT_SOURCE: &str =
    "test/data/script-tests.json via lib/script/script.js#verify/execute";
const HSD_SCRIPT_CASES: usize = 876;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScriptExecutionFixture {
    schema: u32,
    oracle: ScriptExecutionOracle,
    vectors: Vec<ScriptExecutionVector>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScriptExecutionOracle {
    repository: String,
    revision: String,
    hsd_version: String,
    source: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScriptExecutionVector {
    id: String,
    #[serde(default)]
    comments: Option<String>,
    script_raw: String,
    witness: Vec<String>,
    transaction_raw: String,
    previous_value: u64,
    address_version: u8,
    address_hash: String,
    sigops: u32,
    flags: Vec<String>,
    result: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    let path = env::args_os()
        .nth(1)
        .ok_or("usage: verify_hsd_script_corpus PATH")?;
    let fixture = load_fixture(Path::new(&path))?;
    let signatures = NativeSignatureVerifier::new()?;
    let mut mismatches = Vec::new();

    for (index, vector) in fixture.vectors.iter().enumerate() {
        let expected_id = format!("hsd-script-{index:04}");
        if vector.id != expected_id {
            return Err(format!(
                "script corpus case {index} has id {}; expected {expected_id}",
                vector.id
            )
            .into());
        }
        let script = decode_hex(&vector.script_raw)?;
        let transaction = Transaction::decode(&decode_hex(&vector.transaction_raw)?)?;
        let [input] = transaction.inputs.as_slice() else {
            return Err(format!(
                "{} transaction has {} inputs; expected exactly one",
                vector.id,
                transaction.inputs.len()
            )
            .into());
        };
        let expected_witness = vector
            .witness
            .iter()
            .map(|item| decode_hex(item))
            .chain(std::iter::once(Ok(script.clone())))
            .collect::<Result<Vec<_>, _>>()?;
        if input.witness.items != expected_witness {
            return Err(format!(
                "{} transaction witness does not match the corpus",
                vector.id
            )
            .into());
        }
        let address_hash = decode_hex(&vector.address_hash)?;
        if vector.address_version != 0 || address_hash.as_slice() != sha3_256(&script) {
            return Err(format!(
                "{} address does not commit to its HSD witness script",
                vector.id
            )
            .into());
        }
        let sigops = count_script_sigops(&script);
        if sigops != vector.sigops {
            return Err(format!(
                "{}: expected {} sigops, observed {sigops}",
                vector.id, vector.sigops
            )
            .into());
        }
        let coin = Coin {
            outpoint: input.previous_output.clone(),
            value: vector.previous_value,
            height: 1,
            coinbase: false,
            address: Address::new(vector.address_version, address_hash)?,
            covenant: Covenant {
                kind: CovenantKind::None,
                items: Vec::new(),
            },
        };
        let result = match verify_witness_program(
            &transaction,
            0,
            &coin,
            fixture_flags(&vector.flags)?,
            &signatures,
        ) {
            Ok(()) => "OK",
            Err(error) => error.hsd_code(),
        };
        if result != vector.result {
            mismatches.push(format!(
                "{}: expected {}, observed {}{}",
                vector.id,
                vector.result,
                result,
                vector
                    .comments
                    .as_deref()
                    .map(|comments| format!(" ({comments})"))
                    .unwrap_or_default()
            ));
        }
    }

    if !mismatches.is_empty() {
        return Err(format!(
            "{} of {} HSD script cases mismatched:\n{}",
            mismatches.len(),
            fixture.vectors.len(),
            mismatches.join("\n")
        )
        .into());
    }
    println!(
        "verified {} HSD script execution and sigop cases",
        fixture.vectors.len()
    );
    Ok(())
}

fn load_fixture(path: &Path) -> Result<ScriptExecutionFixture, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let fixture: ScriptExecutionFixture = serde_json::from_slice(&bytes)?;
    validate_fixture(&fixture)?;
    Ok(fixture)
}

fn validate_fixture(fixture: &ScriptExecutionFixture) -> Result<(), Box<dyn Error>> {
    if fixture.schema != 1 {
        return Err(format!("unsupported HSD script corpus schema {}", fixture.schema).into());
    }
    if fixture.oracle.repository != HSD_REPOSITORY
        || fixture.oracle.revision != HSD_REVISION
        || fixture.oracle.hsd_version != HSD_VERSION
        || fixture.oracle.source != HSD_SCRIPT_SOURCE
    {
        return Err("HSD script corpus oracle metadata does not match the pinned source".into());
    }
    if fixture.vectors.len() != HSD_SCRIPT_CASES {
        return Err(format!(
            "HSD script corpus has {} cases; expected {HSD_SCRIPT_CASES}",
            fixture.vectors.len()
        )
        .into());
    }
    Ok(())
}

fn fixture_flags(names: &[String]) -> Result<ScriptFlags, Box<dyn Error>> {
    let mut flags = ScriptFlags::NONE;
    for name in names {
        let flag = match name.as_str() {
            "MINIMALDATA" => ScriptFlags::VERIFY_MINIMAL_DATA,
            "DISCOURAGE_UPGRADABLE_NOPS" => ScriptFlags::VERIFY_DISCOURAGE_UPGRADABLE_NOPS,
            "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => {
                ScriptFlags::VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM
            }
            "MINIMALIF" => ScriptFlags::VERIFY_MINIMAL_IF,
            "NULLFAIL" => ScriptFlags::VERIFY_NULLFAIL,
            other => return Err(format!("unknown script flag {other}").into()),
        };
        flags = flags.union(flag);
    }
    Ok(flags)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if value.len() % 2 != 0 {
        return Err("hex value has odd length".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|offset| {
            u8::from_str_radix(&value[offset..offset + 2], 16)
                .map_err(|error| -> Box<dyn Error> { Box::new(error) })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_fixture(revision: &str) -> ScriptExecutionFixture {
        ScriptExecutionFixture {
            schema: 1,
            oracle: ScriptExecutionOracle {
                repository: HSD_REPOSITORY.to_owned(),
                revision: revision.to_owned(),
                hsd_version: HSD_VERSION.to_owned(),
                source: HSD_SCRIPT_SOURCE.to_owned(),
            },
            vectors: Vec::new(),
        }
    }

    #[test]
    fn full_corpus_rejects_unpinned_oracle_metadata() {
        let error = validate_fixture(&empty_fixture("wrong-revision"))
            .expect_err("wrong revision must fail closed");
        assert!(error.to_string().contains("oracle metadata"));
    }

    #[test]
    fn full_corpus_requires_the_exact_pinned_case_count() {
        let error = validate_fixture(&empty_fixture(HSD_REVISION))
            .expect_err("truncated corpus must fail closed");
        assert!(error.to_string().contains("expected 876"));
    }
}
