use hns_primitives::{
    hash_name, verify_name, Block, CompactTarget, Covenant, Header, Resource, ResourceRecordKind,
    Transaction,
};
use hns_testkit::{FixtureCategory, HsdFixtureLoader};
use serde_json::Value;

#[test]
fn header_hashes_match_hsd_fixture() {
    let fixture = load_json(FixtureCategory::Headers, "codec-v1.json");
    let raw = hex_bytes(fixture["raw"].as_str().expect("raw hex"));
    let header = Header::decode(&raw).expect("header parses");

    assert_eq!(header.encode(), raw);
    assert_eq!(hex(header.hash().as_bytes()), fixture["hash"]);
    assert_eq!(hex(&header.share_hash()), fixture["shareHash"]);
    assert_eq!(hex(&header.pow_hash()), fixture["powHash"]);
    assert_eq!(hex(&header.sub_hash()), fixture["subHash"]);
    assert_eq!(hex(&header.mask_hash()), fixture["maskHash"]);
    assert_eq!(hex(&header.commit_hash()), fixture["commitHash"]);
    assert_eq!(hex(&header.preheader()), fixture["preheader"]);
    assert_eq!(header.verify_pow(), fixture["verifyPow"]);
}

#[test]
fn transaction_hashes_match_hsd_fixture() {
    let fixture = load_json(FixtureCategory::Transactions, "codec-v1.json");
    let raw = hex_bytes(fixture["raw"].as_str().expect("raw hex"));
    let transaction = Transaction::decode(&raw).expect("transaction parses");

    assert_eq!(transaction.encode(), raw);
    assert_eq!(hex(transaction.txid().as_bytes()), fixture["hash"]);
    assert_eq!(hex(&transaction.witness_hash()), fixture["witnessHash"]);
    assert_eq!(transaction.base_size(), fixture["baseSize"]);
    assert_eq!(transaction.encode().len(), fixture["size"]);
}

#[test]
fn block_round_trip_matches_hsd_fixture() {
    let fixture = load_json(FixtureCategory::Blocks, "codec-v1.json");
    let raw = hex_bytes(fixture["raw"].as_str().expect("raw hex"));
    let block = Block::decode(&raw).expect("block parses");

    assert_eq!(block.encode(), raw);
    assert_eq!(hex(block.hash().as_bytes()), fixture["headerHash"]);
    assert_eq!(block.transactions.len() as u64, fixture["txCount"]);
}

#[test]
fn covenant_round_trip_matches_hsd_fixture() {
    let fixture = load_json(FixtureCategory::Covenants, "codec-v1.json");
    let raw = hex_bytes(fixture["raw"].as_str().expect("raw hex"));
    let covenant = Covenant::decode(&raw).expect("covenant parses");

    assert_eq!(covenant.encode(), raw);
    assert_eq!(u64::from(covenant.kind.as_u8()), fixture["type"]);
    assert_eq!(hex(&covenant.items[0]), fixture["items"][0]);
    assert_eq!(hex(&covenant.items[1]), fixture["items"][1]);
}

#[test]
fn resource_scanner_matches_hsd_fixture() {
    let fixture = load_json(FixtureCategory::Resources, "codec-v1.json");
    let raw = hex_bytes(fixture["raw"].as_str().expect("raw hex"));
    let resource = Resource::decode(&raw).expect("resource parses");

    assert_eq!(resource.encode(), raw);
    assert_eq!(resource.records[0].kind, ResourceRecordKind::Synth4);
    assert_eq!(resource.records[1].kind, ResourceRecordKind::Txt);
}

#[test]
fn name_hashes_match_hsd_fixture() {
    let fixture = load_json(FixtureCategory::NameStates, "name-hash-v1.json");
    let valid = fixture["valid"].as_object().expect("valid names");

    for (name, expected) in valid {
        assert!(verify_name(name));
        assert_eq!(
            hex(hash_name(name).expect("name hash").as_bytes()),
            expected.as_str().expect("hash")
        );
    }

    for name in fixture["invalid"].as_array().expect("invalid names") {
        assert!(!verify_name(name.as_str().expect("name")));
    }
}

#[test]
fn compact_targets_match_hsd_fixture() {
    let fixture = load_json(FixtureCategory::Chains, "compact-targets-v1.json");

    for item in fixture.as_array().expect("compact target list") {
        let bits = item["bits"].as_u64().expect("bits") as u32;
        let target = CompactTarget::from_bits(bits);

        assert_eq!(hex(target.bytes()), item["target"]);
        assert_eq!(target.is_valid(), item["valid"]);
    }
}

fn load_json(category: FixtureCategory, name: &str) -> Value {
    let loader = HsdFixtureLoader::workspace_default();
    let bytes = loader.load_bytes(category, name).expect("fixture bytes");
    serde_json::from_slice(&bytes).expect("fixture json")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_bytes(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0, "hex string length");

    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).expect("hex byte"))
        .collect()
}
