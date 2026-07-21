use std::{env, error::Error, fs, path::Path};

use hns_consensus::{verify_witness_program, NativeSignatureVerifier, ScriptFlags};
use hns_primitives::{Address, Coin, Covenant, CovenantKind, Transaction};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ScriptExecutionFixture {
    schema: u32,
    vectors: Vec<ScriptExecutionVector>,
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

    for vector in &fixture.vectors {
        let transaction = Transaction::decode(&decode_hex(&vector.transaction_raw)?)?;
        let input = transaction
            .inputs
            .first()
            .ok_or("script corpus transaction has no input")?;
        let expected_witness = vector
            .witness
            .iter()
            .map(|item| decode_hex(item))
            .chain(std::iter::once(decode_hex(&vector.script_raw)))
            .collect::<Result<Vec<_>, _>>()?;
        if input.witness.items != expected_witness {
            return Err(format!(
                "{} transaction witness does not match the corpus",
                vector.id
            )
            .into());
        }
        let coin = Coin {
            outpoint: input.previous_output.clone(),
            value: vector.previous_value,
            height: 1,
            coinbase: false,
            address: Address::new(vector.address_version, decode_hex(&vector.address_hash)?)?,
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
        "verified {} HSD script execution cases",
        fixture.vectors.len()
    );
    Ok(())
}

fn load_fixture(path: &Path) -> Result<ScriptExecutionFixture, Box<dyn Error>> {
    let bytes = fs::read(path)?;
    let fixture: ScriptExecutionFixture = serde_json::from_slice(&bytes)?;
    if fixture.schema != 1 || fixture.vectors.is_empty() {
        return Err("unsupported or empty HSD script corpus".into());
    }
    Ok(fixture)
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
