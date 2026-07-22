use std::{error::Error, time::Instant};

use hns_consensus::Network;
use hns_mining::{TemplateCacheKey, TemplatePolicy};
use hns_node::{
    MiningEngineConfig, MiningTemplateRequest, NodeBlockImport, NodeConfig, NodeService,
};
use hns_primitives::{blake2b_256_many, Address, Block, NONCE_SIZE};
use serde_json::Value;

const WARMUP_BLOCKS: usize = 10;
const MEASURED_BLOCKS: usize = 100;
const TIP_TO_JOB_P99_TARGET_MICROS: u128 = 25_000;
const CANDIDATE_VALIDATION_P99_TARGET_MICROS: u128 = 5_000;
const LOCAL_CONNECT_P99_TARGET_MICROS: u128 = 50_000;

fn main() {
    if let Err(error) = run() {
        eprintln!("hsrd-performance-gate: {error:#}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), Box<dyn Error>> {
    let mut node = NodeService::try_new(NodeConfig {
        network: Network::Regtest,
        mining_engine: MiningEngineConfig {
            enabled: true,
            ..MiningEngineConfig::default()
        },
        ..NodeConfig::default()
    })?;
    node.connect_block(NodeBlockImport::from_peer(canonical_regtest_genesis()?, 0))?;

    let mut template_micros = Vec::with_capacity(MEASURED_BLOCKS);
    let mut prepare_micros = Vec::with_capacity(MEASURED_BLOCKS);
    let mut tip_to_job_micros = Vec::with_capacity(MEASURED_BLOCKS);
    let mut candidate_micros = Vec::with_capacity(MEASURED_BLOCKS);
    let mut connect_micros = Vec::with_capacity(MEASURED_BLOCKS);

    for iteration in 0..WARMUP_BLOCKS + MEASURED_BLOCKS {
        let snapshot = node
            .observed_mining_snapshot()?
            .ok_or("durable mining snapshot is unavailable")?;
        let mask = [0x42; 32];
        let mask_hash =
            blake2b_256_many([snapshot.tip.hash.as_bytes().as_slice(), mask.as_slice()]);
        let request = MiningTemplateRequest {
            variant: 0,
            payout_address: Address::new(0, vec![0x51; 20])?,
            coinbase_flags: b"hsrd-performance-gate".to_vec(),
            version: 0,
            bits: Network::Regtest.params().pow.bits,
            minimum_time: snapshot.parent_median_time.saturating_add(1),
            reserved_root: [0; 32],
            mask_hash,
            policy: TemplatePolicy::default(),
        };

        let tip_started = Instant::now();
        let template_started = Instant::now();
        let template = node.mining_engine_build_template(request)?;
        let template_elapsed = template_started.elapsed();
        let key = TemplateCacheKey {
            snapshot_generation: template.snapshot_generation(),
            mempool_generation: template.mempool_generation(),
            variant: 0,
        };
        let prepare_started = Instant::now();
        let job = node.mining_engine_prepare_cached_job(&key)?;
        let prepare_elapsed = prepare_started.elapsed();
        let tip_to_job_elapsed = tip_started.elapsed();

        let mut nonce = 0u32;
        let extra_nonce = [0; NONCE_SIZE];
        loop {
            let candidate = job.reconstruct(nonce, job.header().minimum_time, extra_nonce, mask)?;
            if candidate.header.verify_pow() {
                break;
            }
            nonce = nonce
                .checked_add(1)
                .ok_or("regtest nonce space exhausted")?;
        }

        let candidate_started = Instant::now();
        let candidate = job.admit_solution(
            &snapshot,
            nonce,
            job.header().minimum_time,
            extra_nonce,
            mask,
        )?;
        let candidate_elapsed = candidate_started.elapsed();

        let connect_started = Instant::now();
        node.connect_block(NodeBlockImport::from_mining_candidate(candidate)?)?;
        let connect_elapsed = connect_started.elapsed();

        if iteration >= WARMUP_BLOCKS {
            template_micros.push(template_elapsed.as_micros());
            prepare_micros.push(prepare_elapsed.as_micros());
            tip_to_job_micros.push(tip_to_job_elapsed.as_micros());
            candidate_micros.push(candidate_elapsed.as_micros());
            connect_micros.push(connect_elapsed.as_micros());
        }
    }

    print_distribution("template_build", &template_micros);
    print_distribution("job_prepare", &prepare_micros);
    print_distribution("tip_to_job", &tip_to_job_micros);
    print_distribution("candidate_validation", &candidate_micros);
    print_distribution("local_connect", &connect_micros);
    println!("measured_blocks={MEASURED_BLOCKS}");
    println!("failure_count=0");
    println!("unavailable_evidence=0");
    println!("tip_to_job_p99_target_micros={TIP_TO_JOB_P99_TARGET_MICROS}");
    println!("candidate_validation_p99_target_micros={CANDIDATE_VALIDATION_P99_TARGET_MICROS}");
    println!("local_connect_p99_target_micros={LOCAL_CONNECT_P99_TARGET_MICROS}");

    if percentile(&tip_to_job_micros, 99) >= TIP_TO_JOB_P99_TARGET_MICROS
        || percentile(&candidate_micros, 99) >= CANDIDATE_VALIDATION_P99_TARGET_MICROS
        || percentile(&connect_micros, 99) >= LOCAL_CONNECT_P99_TARGET_MICROS
    {
        return Err("one or more native mining-path latency targets were missed".into());
    }
    Ok(())
}

fn canonical_regtest_genesis() -> Result<Block, Box<dyn Error>> {
    let fixture: Value = serde_json::from_str(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../fixtures/hsd/blocks/genesis-v1.json"
    )))?;
    let case = fixture["networks"]
        .as_array()
        .ok_or("genesis fixture has no network cases")?
        .iter()
        .find(|case| case["network"] == "regtest")
        .ok_or("genesis fixture has no regtest case")?;
    let raw = decode_hex(
        case["raw"]
            .as_str()
            .ok_or("regtest genesis fixture has no raw block")?,
    )?;
    Ok(Block::decode(&raw)?)
}

fn decode_hex(value: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    if !value.len().is_multiple_of(2) {
        return Err("hex string has odd length".into());
    }
    (0..value.len())
        .step_by(2)
        .map(|offset| Ok(u8::from_str_radix(&value[offset..offset + 2], 16)?))
        .collect()
}

fn print_distribution(name: &str, samples: &[u128]) {
    println!("{name}_count={}", samples.len());
    println!("{name}_p50_micros={}", percentile(samples, 50));
    println!("{name}_p95_micros={}", percentile(samples, 95));
    println!("{name}_p99_micros={}", percentile(samples, 99));
    println!(
        "{name}_max_micros={}",
        samples.iter().copied().max().unwrap_or(0)
    );
}

fn percentile(samples: &[u128], percentile: usize) -> u128 {
    if samples.is_empty() {
        return 0;
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let rank = percentile.saturating_mul(sorted.len()).saturating_add(99) / 100;
    sorted[rank.saturating_sub(1).min(sorted.len() - 1)]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentile_uses_nearest_rank() {
        let values = (1..=100).collect::<Vec<u128>>();
        assert_eq!(percentile(&values, 50), 50);
        assert_eq!(percentile(&values, 95), 95);
        assert_eq!(percentile(&values, 99), 99);
        assert_eq!(percentile(&[], 99), 0);
    }

    #[test]
    fn canonical_fixture_decodes_to_regtest_genesis() {
        let block = canonical_regtest_genesis().expect("regtest genesis");
        assert_eq!(block.header, Network::Regtest.params().genesis_header());
        assert_eq!(block.hash(), Network::Regtest.params().genesis_hash);
    }
}
