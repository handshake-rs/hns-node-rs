use std::{cmp::Ordering, collections::HashSet, sync::Arc};

use hns_consensus::{
    block_merkle_root, block_subsidy, block_witness_root, validate_block_body, Network,
    MAX_BLOCK_OPENS, MAX_BLOCK_RENEWALS, MAX_BLOCK_SIGOPS, MAX_BLOCK_UPDATES,
};
use hns_mempool::{minimum_policy_fee, MempoolPackage, MempoolSnapshot};
use hns_primitives::{
    blake2b_256_many, Address, Block, Covenant, CovenantKind, Header, Input, Outpoint, Output,
    Transaction, Witness, MAX_BLOCK_WEIGHT,
};

use crate::{
    MiningError, MiningHeaderTemplate, MiningSnapshot, PreparedMiningJob, MAX_PREPARED_JOBS,
};

pub const DEFAULT_RESERVED_TEMPLATE_WEIGHT: usize = 4_000;
pub const DEFAULT_RESERVED_TEMPLATE_SIGOPS: u32 = 400;
pub const MAX_TEMPLATE_VARIANTS: usize = MAX_PREPARED_JOBS;
pub type TemplateId = [u8; 32];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemplatePolicy {
    pub maximum_weight: usize,
    pub maximum_sigops: u32,
    pub maximum_opens: u32,
    pub maximum_updates: u32,
    pub maximum_renewals: u32,
    pub maximum_transactions: usize,
    pub reserved_weight: usize,
    pub reserved_sigops: u32,
    /// Minimum package fee in atomic units per 1,000 HSD policy virtual bytes.
    pub minimum_package_fee_rate: u64,
}

impl Default for TemplatePolicy {
    fn default() -> Self {
        Self {
            maximum_weight: MAX_BLOCK_WEIGHT,
            maximum_sigops: MAX_BLOCK_SIGOPS,
            maximum_opens: MAX_BLOCK_OPENS,
            maximum_updates: MAX_BLOCK_UPDATES,
            maximum_renewals: MAX_BLOCK_RENEWALS,
            maximum_transactions: 50_000,
            reserved_weight: DEFAULT_RESERVED_TEMPLATE_WEIGHT,
            reserved_sigops: DEFAULT_RESERVED_TEMPLATE_SIGOPS,
            minimum_package_fee_rate: 0,
        }
    }
}

impl TemplatePolicy {
    pub fn validate(&self) -> Result<(), MiningError> {
        if self.maximum_weight == 0
            || self.maximum_sigops == 0
            || self.maximum_transactions == 0
            || self.reserved_weight > self.maximum_weight
            || self.reserved_sigops > self.maximum_sigops
            || self.maximum_weight > MAX_BLOCK_WEIGHT
            || self.maximum_sigops > MAX_BLOCK_SIGOPS
            || self.maximum_opens > MAX_BLOCK_OPENS
            || self.maximum_updates > MAX_BLOCK_UPDATES
            || self.maximum_renewals > MAX_BLOCK_RENEWALS
        {
            return Err(MiningError::InvalidTemplatePolicy);
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
pub struct TemplateBuildRequest<'a> {
    pub snapshot: &'a MiningSnapshot,
    pub mempool: &'a MempoolSnapshot,
    pub payout_address: Address,
    pub coinbase_flags: Vec<u8>,
    pub version: u32,
    pub bits: u32,
    pub minimum_time: u64,
    pub reserved_root: [u8; 32],
    pub mask_hash: [u8; 32],
    pub policy: TemplatePolicy,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct TemplateMetrics {
    pub transaction_count: usize,
    pub selected_packages: usize,
    pub fees: u64,
    pub weight: usize,
    pub sigops: u32,
    pub opens: u32,
    pub updates: u32,
    pub renewals: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MiningTemplate {
    template_id: TemplateId,
    snapshot_generation: u64,
    mempool_generation: u64,
    header: MiningHeaderTemplate,
    transactions: Arc<[Transaction]>,
    metrics: TemplateMetrics,
}

impl MiningTemplate {
    pub const fn template_id(&self) -> TemplateId {
        self.template_id
    }

    pub const fn snapshot_generation(&self) -> u64 {
        self.snapshot_generation
    }

    pub const fn mempool_generation(&self) -> u64 {
        self.mempool_generation
    }

    pub const fn header(&self) -> &MiningHeaderTemplate {
        &self.header
    }

    pub fn transactions(&self) -> &[Transaction] {
        &self.transactions
    }

    pub const fn metrics(&self) -> &TemplateMetrics {
        &self.metrics
    }

    pub fn prepare_job(&self, snapshot: &MiningSnapshot) -> Result<PreparedMiningJob, MiningError> {
        if snapshot.generation != self.snapshot_generation
            || snapshot.tip.hash != self.header.parent_hash
            || snapshot.next_tree_root != self.header.tree_root
        {
            return Err(MiningError::StaleTemplate);
        }
        PreparedMiningJob::new(
            snapshot,
            self.header.clone(),
            Arc::clone(&self.transactions),
        )
    }
}

#[derive(Clone, Debug, Default)]
pub struct TemplateAssembler;

impl TemplateAssembler {
    pub fn assemble(
        &self,
        request: TemplateBuildRequest<'_>,
    ) -> Result<MiningTemplate, MiningError> {
        request.policy.validate()?;
        let next_height = request
            .snapshot
            .tip
            .height
            .checked_add(1)
            .ok_or(MiningError::InvalidTemplateContext)?;
        let network = Network::from_canonical_id(request.snapshot.network_id)
            .ok_or(MiningError::InvalidTemplateContext)?;
        if request.minimum_time <= request.snapshot.tip.time
            || request.mask_hash == [0; 32]
            || request.payout_address.validate().is_err()
        {
            return Err(MiningError::InvalidTemplateContext);
        }

        let mut selected = HashSet::new();
        let mut selected_transactions = Vec::new();
        let mut selected_names = HashSet::new();
        let mut metrics = TemplateMetrics {
            weight: request.policy.reserved_weight,
            sigops: request.policy.reserved_sigops,
            ..TemplateMetrics::default()
        };

        loop {
            let mut best: Option<MempoolPackage> = None;
            for txid in request.mempool.txids() {
                if selected.contains(&txid) {
                    continue;
                }
                let package = request
                    .mempool
                    .package_for(txid, &selected)
                    .map_err(|error| MiningError::Mempool(error.to_string()))?;
                if package.is_empty()
                    || !package_meets_fee_rate(&package, request.policy.minimum_package_fee_rate)
                    || !package_fits(
                        &package,
                        &metrics,
                        selected_transactions.len(),
                        &selected_names,
                        &request.policy,
                    )
                {
                    continue;
                }
                if best
                    .as_ref()
                    .is_none_or(|current| compare_packages(&package, current) == Ordering::Greater)
                {
                    best = Some(package);
                }
            }

            let Some(package) = best else {
                break;
            };
            for txid in &package.txids {
                if selected.insert(*txid) {
                    let transaction = request
                        .mempool
                        .transaction(txid)
                        .ok_or(MiningError::MempoolTransactionMissing(*txid))?
                        .clone();
                    selected_transactions.push(transaction);
                }
            }
            selected_names.extend(package.exclusive_names.iter().copied());
            metrics.selected_packages = metrics.selected_packages.saturating_add(1);
            metrics.fees = metrics
                .fees
                .checked_add(package.fee)
                .ok_or(MiningError::TemplateArithmetic)?;
            metrics.weight = metrics
                .weight
                .checked_add(package.weight)
                .ok_or(MiningError::TemplateArithmetic)?;
            metrics.sigops = metrics.sigops.saturating_add(package.sigops);
            metrics.opens = metrics.opens.saturating_add(package.opens);
            metrics.updates = metrics.updates.saturating_add(package.updates);
            metrics.renewals = metrics.renewals.saturating_add(package.renewals);
        }

        let reward = block_subsidy(next_height, network.params().halving_interval)
            .checked_add(metrics.fees)
            .ok_or(MiningError::TemplateArithmetic)?;
        let coinbase = create_coinbase(
            next_height,
            request.snapshot.generation,
            reward,
            request.payout_address,
            request.coinbase_flags,
        )?;
        let mut transactions = Vec::with_capacity(selected_transactions.len().saturating_add(1));
        transactions.push(coinbase);
        transactions.extend(selected_transactions);
        let mut block = Block {
            header: Header {
                time: request.minimum_time,
                prev_block: request.snapshot.tip.hash,
                tree_root: request.snapshot.next_tree_root,
                reserved_root: request.reserved_root,
                version: request.version,
                bits: request.bits,
                ..Header::default()
            },
            transactions,
        };
        block.header.merkle_root = block_merkle_root(&block);
        block.header.witness_root = block_witness_root(&block);
        let body = validate_block_body(&block).map_err(|_| MiningError::InvalidTemplateBody)?;
        if body.weight > request.policy.maximum_weight {
            return Err(MiningError::InvalidTemplateBody);
        }
        metrics.transaction_count = block.transactions.len();
        metrics.weight = body.weight;
        let header = MiningHeaderTemplate {
            parent_hash: block.header.prev_block,
            tree_root: block.header.tree_root,
            reserved_root: block.header.reserved_root,
            witness_root: block.header.witness_root,
            merkle_root: block.header.merkle_root,
            version: block.header.version,
            bits: block.header.bits,
            minimum_time: block.header.time,
            mask_hash: request.mask_hash,
        };
        let transactions = Arc::<[Transaction]>::from(block.transactions);
        let template_id = template_id(
            request.snapshot.network_id,
            request.snapshot.generation,
            request.mempool.generation(),
            &header,
            &transactions,
        );
        Ok(MiningTemplate {
            template_id,
            snapshot_generation: request.snapshot.generation,
            mempool_generation: request.mempool.generation(),
            header,
            transactions,
            metrics,
        })
    }
}

fn create_coinbase(
    height: u32,
    generation: u64,
    reward: u64,
    payout_address: Address,
    coinbase_flags: Vec<u8>,
) -> Result<Transaction, MiningError> {
    if coinbase_flags.len() > hns_consensus::MAX_COINBASE_WITNESS_SIZE {
        return Err(MiningError::InvalidTemplateContext);
    }
    let sequence = u32::try_from(generation & u64::from(u32::MAX))
        .map_err(|_| MiningError::TemplateArithmetic)?;
    Ok(Transaction {
        version: 0,
        inputs: vec![Input {
            previous_output: Outpoint::null(),
            sequence,
            witness: Witness {
                items: vec![coinbase_flags, vec![0; 8], vec![0; 8]],
            },
        }],
        outputs: vec![Output {
            value: reward,
            address: payout_address,
            covenant: Covenant {
                kind: CovenantKind::None,
                items: Vec::new(),
            },
        }],
        locktime: height,
    })
}

fn package_meets_fee_rate(package: &MempoolPackage, minimum_rate: u64) -> bool {
    package.fee >= minimum_policy_fee(package.policy_size, minimum_rate)
}

fn package_fits(
    package: &MempoolPackage,
    current: &TemplateMetrics,
    selected_count: usize,
    selected_names: &HashSet<[u8; 32]>,
    policy: &TemplatePolicy,
) -> bool {
    selected_count
        .checked_add(package.txids.len())
        .is_some_and(|count| count.saturating_add(1) <= policy.maximum_transactions)
        && current
            .weight
            .checked_add(package.weight)
            .is_some_and(|weight| weight <= policy.maximum_weight)
        && current.sigops.saturating_add(package.sigops) <= policy.maximum_sigops
        && current.opens.saturating_add(package.opens) <= policy.maximum_opens
        && current.updates.saturating_add(package.updates) <= policy.maximum_updates
        && current.renewals.saturating_add(package.renewals) <= policy.maximum_renewals
        && package
            .exclusive_names
            .iter()
            .all(|name| !selected_names.contains(name))
}

fn compare_packages(left: &MempoolPackage, right: &MempoolPackage) -> Ordering {
    let left_rate = u128::from(left.fee).saturating_mul(right.policy_size.max(1) as u128);
    let right_rate = u128::from(right.fee).saturating_mul(left.policy_size.max(1) as u128);
    left_rate
        .cmp(&right_rate)
        .then_with(|| right.oldest_sequence.cmp(&left.oldest_sequence))
        .then_with(|| right.txids.cmp(&left.txids))
}

fn template_id(
    network_id: u8,
    generation: u64,
    mempool_generation: u64,
    header: &MiningHeaderTemplate,
    transactions: &[Transaction],
) -> TemplateId {
    let mut body = Vec::new();
    let transaction_count = u64::try_from(transactions.len())
        .expect("transaction count fits in the canonical u64 encoding")
        .to_le_bytes();
    body.extend_from_slice(&transaction_count);
    for transaction in transactions {
        let encoded = transaction.encode();
        let encoded_len = u64::try_from(encoded.len())
            .expect("transaction length fits in the canonical u64 encoding")
            .to_le_bytes();
        body.extend_from_slice(&encoded_len);
        body.extend_from_slice(&encoded);
    }
    let network = [network_id];
    let generation = generation.to_le_bytes();
    let mempool_generation = mempool_generation.to_le_bytes();
    let version = header.version.to_le_bytes();
    let bits = header.bits.to_le_bytes();
    let minimum_time = header.minimum_time.to_le_bytes();
    blake2b_256_many([
        b"hsrd/mining-template/v1".as_slice(),
        network.as_slice(),
        generation.as_slice(),
        mempool_generation.as_slice(),
        header.parent_hash.as_bytes().as_slice(),
        header.tree_root.as_slice(),
        header.reserved_root.as_slice(),
        version.as_slice(),
        bits.as_slice(),
        minimum_time.as_slice(),
        header.mask_hash.as_slice(),
        body.as_slice(),
    ])
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct TemplateCacheKey {
    pub snapshot_generation: u64,
    pub mempool_generation: u64,
    pub variant: u32,
}

#[derive(Clone, Debug, Default)]
pub struct FutureTemplateCache {
    templates: std::collections::BTreeMap<TemplateCacheKey, Arc<MiningTemplate>>,
}

impl FutureTemplateCache {
    pub fn insert(
        &mut self,
        key: TemplateCacheKey,
        template: MiningTemplate,
    ) -> Result<Arc<MiningTemplate>, MiningError> {
        if key.snapshot_generation != template.snapshot_generation()
            || key.mempool_generation != template.mempool_generation()
        {
            return Err(MiningError::InvalidTemplateContext);
        }
        if let Some(existing) = self.templates.get(&key) {
            if existing.as_ref() == &template {
                return Ok(Arc::clone(existing));
            }
            return Err(MiningError::TemplateConflict);
        }
        if self.templates.len() >= MAX_TEMPLATE_VARIANTS {
            return Err(MiningError::TemplateCapacity);
        }
        let template = Arc::new(template);
        self.templates.insert(key, Arc::clone(&template));
        Ok(template)
    }

    pub fn activate(
        &mut self,
        key: &TemplateCacheKey,
        snapshot: &MiningSnapshot,
    ) -> Result<Arc<MiningTemplate>, MiningError> {
        let template = self
            .templates
            .get(key)
            .cloned()
            .ok_or(MiningError::UnknownTemplate)?;
        if template.snapshot_generation() != snapshot.generation
            || template.header().parent_hash != snapshot.tip.hash
            || template.header().tree_root != snapshot.next_tree_root
        {
            return Err(MiningError::StaleTemplate);
        }
        self.templates
            .retain(|candidate, _| candidate.snapshot_generation == snapshot.generation);
        Ok(template)
    }

    pub fn get(&self, key: &TemplateCacheKey) -> Option<Arc<MiningTemplate>> {
        self.templates.get(key).cloned()
    }

    pub fn retain_generation(&mut self, snapshot_generation: u64) {
        self.templates
            .retain(|key, _| key.snapshot_generation == snapshot_generation);
    }

    pub fn clear(&mut self) {
        self.templates.clear();
    }

    pub fn len(&self) -> usize {
        self.templates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TemplateVariant {
    pub variant: u32,
    pub payout_address: Address,
    pub coinbase_flags: Vec<u8>,
    pub version: u32,
    pub bits: u32,
    pub minimum_time: u64,
    pub reserved_root: [u8; 32],
    pub mask_hash: [u8; 32],
    pub policy: TemplatePolicy,
}

/// Atomically prepares a bounded set of future template variants for one chain
/// and mempool generation. A failed rebuild leaves the previous cache intact.
#[derive(Clone, Debug)]
pub struct TemplateCoordinator {
    assembler: TemplateAssembler,
    cache: FutureTemplateCache,
    maximum_variants: usize,
}

impl TemplateCoordinator {
    pub fn new(maximum_variants: usize) -> Result<Self, MiningError> {
        if maximum_variants == 0 || maximum_variants > MAX_TEMPLATE_VARIANTS {
            return Err(MiningError::TemplateCapacity);
        }
        Ok(Self {
            assembler: TemplateAssembler,
            cache: FutureTemplateCache::default(),
            maximum_variants,
        })
    }

    pub fn rebuild(
        &mut self,
        snapshot: &MiningSnapshot,
        mempool: &MempoolSnapshot,
        variants: impl IntoIterator<Item = TemplateVariant>,
    ) -> Result<Vec<Arc<MiningTemplate>>, MiningError> {
        let variants = variants.into_iter().collect::<Vec<_>>();
        if variants.is_empty() || variants.len() > self.maximum_variants {
            return Err(MiningError::TemplateCapacity);
        }
        let mut seen = HashSet::new();
        let mut replacement = FutureTemplateCache::default();
        let mut built = Vec::with_capacity(variants.len());
        for variant in variants {
            if !seen.insert(variant.variant) {
                return Err(MiningError::TemplateConflict);
            }
            let template = self.assembler.assemble(TemplateBuildRequest {
                snapshot,
                mempool,
                payout_address: variant.payout_address,
                coinbase_flags: variant.coinbase_flags,
                version: variant.version,
                bits: variant.bits,
                minimum_time: variant.minimum_time,
                reserved_root: variant.reserved_root,
                mask_hash: variant.mask_hash,
                policy: variant.policy,
            })?;
            let key = TemplateCacheKey {
                snapshot_generation: snapshot.generation,
                mempool_generation: mempool.generation(),
                variant: variant.variant,
            };
            built.push(replacement.insert(key, template)?);
        }
        self.cache = replacement;
        Ok(built)
    }

    pub fn activate(
        &mut self,
        key: &TemplateCacheKey,
        snapshot: &MiningSnapshot,
    ) -> Result<Arc<MiningTemplate>, MiningError> {
        self.cache.activate(key, snapshot)
    }

    pub fn get(&self, key: &TemplateCacheKey) -> Option<Arc<MiningTemplate>> {
        self.cache.get(key)
    }

    pub fn clear(&mut self) {
        self.cache.clear();
    }

    pub fn len(&self) -> usize {
        self.cache.len()
    }

    pub fn is_empty(&self) -> bool {
        self.cache.is_empty()
    }
}

impl Default for TemplateCoordinator {
    fn default() -> Self {
        Self::new(MAX_TEMPLATE_VARIANTS).expect("default template capacity is valid")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_consensus::{
        transaction_weight, ConsensusError, Network, SequenceLockView, TransactionInputVerifier,
    };
    use hns_mempool::{
        sigop_adjusted_virtual_size, standard_output_dust_threshold, Admission,
        ContextualTransactionVerifier, MemoryMempool, Mempool, MempoolContext, MempoolView,
        BYTES_PER_SIGOP, HSD_ABSURD_FEE_FACTOR, HSD_MAX_P2WSH_PUSH, HSD_MAX_P2WSH_SIZE,
        HSD_MAX_P2WSH_STACK, HSD_MAX_STANDARD_TX_VERSION, HSD_MAX_STANDARD_TX_WEIGHT,
        HSD_MINIMUM_RELAY_FEE_RATE, MAX_TX_SIGOPS,
    };
    use hns_primitives::{Coin, Height, Txid};
    use std::collections::HashMap;

    #[derive(Default)]
    struct View {
        coins: HashMap<Outpoint, Coin>,
    }

    impl SequenceLockView for View {
        fn coin_height(&self, outpoint: &Outpoint) -> Result<Option<Height>, ConsensusError> {
            Ok(self.coins.get(outpoint).map(|coin| coin.height))
        }

        fn median_time_past(&self, _height: Height) -> Result<u64, ConsensusError> {
            Ok(1)
        }
    }

    impl MempoolView for View {
        fn coin(&self, outpoint: &Outpoint) -> Result<Option<Coin>, ConsensusError> {
            Ok(self.coins.get(outpoint).cloned())
        }
    }

    struct Allow;

    impl TransactionInputVerifier for Allow {
        fn verify_input(
            &self,
            _transaction: &Transaction,
            _input_index: usize,
            _coin: &Coin,
        ) -> Result<(), ConsensusError> {
            Ok(())
        }
    }

    impl ContextualTransactionVerifier for Allow {
        fn verify(
            &self,
            _transaction: &Transaction,
            _input_coins: &[Coin],
            _context: &MempoolContext,
            _accepted_name_transactions: &[&Transaction],
        ) -> Result<(), ConsensusError> {
            Ok(())
        }
    }

    fn address(byte: u8) -> Address {
        Address::new(0, vec![byte; 20]).expect("address")
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        fn nibble(value: u8) -> u8 {
            match value {
                b'0'..=b'9' => value - b'0',
                b'a'..=b'f' => value - b'a' + 10,
                _ => panic!("invalid fixture hex"),
            }
        }
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
            .collect()
    }

    fn transaction(previous: Outpoint, input_value: u64, output_value: u64) -> (Transaction, Coin) {
        let coin = Coin {
            outpoint: previous.clone(),
            value: input_value,
            height: 1,
            coinbase: false,
            address: address(2),
            covenant: Covenant {
                kind: CovenantKind::None,
                items: Vec::new(),
            },
        };
        let transaction = Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: previous,
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value: output_value,
                address: address(3),
                covenant: Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            }],
            locktime: 0,
        };
        (transaction, coin)
    }

    fn snapshot() -> MiningSnapshot {
        MiningSnapshot {
            network_id: Network::Regtest.canonical_id(),
            generation: 7,
            tip: crate::HeaderSummary {
                hash: hns_primitives::BlockHash::new([1; 32]),
                parent_hash: hns_primitives::BlockHash::new([0; 32]),
                height: 10,
                tree_root: [2; 32],
                time: 100,
                bits: 0x207f_ffff,
            },
            next_tree_root: [3; 32],
            chainwork: 10u64.into(),
        }
    }

    #[test]
    fn hsd_oracle_coinbase_and_subsidy_vectors_match() {
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../fixtures/hsd/mining/template-v1.json"
        ))
        .expect("hsrd mining fixture");
        assert_eq!(fixture["schema"], 3);
        let deterministic = &fixture["deterministicCoinbase"];
        let coinbase = create_coinbase(
            u32::try_from(deterministic["height"].as_u64().expect("height"))
                .expect("height fits u32"),
            deterministic["generationAsSequence"]
                .as_u64()
                .expect("generation"),
            deterministic["reward"].as_u64().expect("reward"),
            address(9),
            b"hsrd".to_vec(),
        )
        .expect("coinbase");
        assert_eq!(
            hns_primitives::hex_encode(&coinbase.encode()),
            deterministic["raw"].as_str().expect("raw coinbase")
        );

        for case in fixture["subsidyCases"].as_array().expect("subsidy cases") {
            let height =
                u32::try_from(case["height"].as_u64().expect("height")).expect("height fits u32");
            let interval = u32::try_from(case["interval"].as_u64().expect("interval"))
                .expect("interval fits u32");
            assert_eq!(
                block_subsidy(height, interval),
                case["reward"].as_u64().expect("reward")
            );
        }

        let policy = &fixture["mempoolSigopPolicy"];
        assert_eq!(
            policy["maxTxSigops"].as_u64().expect("maximum sigops"),
            u64::from(MAX_TX_SIGOPS)
        );
        assert_eq!(
            policy["bytesPerSigop"].as_u64().expect("bytes per sigop"),
            BYTES_PER_SIGOP as u64
        );
        let policy_transaction = Transaction::decode(&decode_hex(
            policy["transactionRaw"]
                .as_str()
                .expect("policy transaction"),
        ))
        .expect("policy transaction decode");
        assert_eq!(
            transaction_weight(&policy_transaction) as u64,
            policy["transactionWeight"]
                .as_u64()
                .expect("policy transaction weight")
        );
        for case in policy["cases"].as_array().expect("sigop policy cases") {
            let sigops = u32::try_from(case["sigops"].as_u64().expect("case sigops"))
                .expect("case sigops fit u32");
            assert_eq!(
                sigop_adjusted_virtual_size(&policy_transaction, sigops) as u64,
                case["policySize"].as_u64().expect("policy size")
            );
            assert_eq!(
                sigops <= MAX_TX_SIGOPS,
                case["accepted"].as_bool().expect("policy acceptance")
            );
        }
        for case in policy["minimumFeeCases"]
            .as_array()
            .expect("minimum fee cases")
        {
            let policy_size =
                usize::try_from(case["policySize"].as_u64().expect("fee policy size"))
                    .expect("fee policy size fits usize");
            let rate = case["rate"].as_u64().expect("fee rate");
            assert_eq!(
                minimum_policy_fee(policy_size, rate),
                case["minimumFee"].as_u64().expect("minimum fee")
            );
        }
        let standard = &fixture["mempoolStandardPolicy"];
        assert_eq!(standard["maximumVersion"], HSD_MAX_STANDARD_TX_VERSION);
        assert_eq!(standard["maximumWeight"], HSD_MAX_STANDARD_TX_WEIGHT);
        assert_eq!(standard["maximumWitnessStack"], HSD_MAX_P2WSH_STACK);
        assert_eq!(standard["maximumWitnessPush"], HSD_MAX_P2WSH_PUSH);
        assert_eq!(standard["maximumWitnessScript"], HSD_MAX_P2WSH_SIZE);
        assert_eq!(standard["absurdFeeFactor"], HSD_ABSURD_FEE_FACTOR);
        let dust_output = Output {
            value: 1,
            address: address(2),
            covenant: Covenant {
                kind: CovenantKind::None,
                items: Vec::new(),
            },
        };
        assert_eq!(
            standard_output_dust_threshold(&dust_output, HSD_MINIMUM_RELAY_FEE_RATE),
            standard["dustThreshold"].as_u64().expect("dust threshold")
        );
        for network in standard["requireStandard"]
            .as_array()
            .expect("network standardness")
        {
            let expected = match network["network"].as_str().expect("network") {
                "main" => true,
                "testnet" | "regtest" | "simnet" => false,
                other => panic!("unexpected HSD network {other}"),
            };
            assert_eq!(
                network["required"].as_bool().expect("standardness flag"),
                expected
            );
        }
        let expected_cases = [
            ("baseline", true),
            ("version-one", false),
            ("unknown-address", false),
            ("dust", false),
            ("multiple-nulldata", false),
        ];
        for (case, (name, accepted)) in standard["cases"]
            .as_array()
            .expect("standardness cases")
            .iter()
            .zip(expected_cases)
        {
            assert_eq!(case["name"], name);
            assert_eq!(case["accepted"], accepted);
        }
    }

    #[test]
    fn package_selection_prefers_fee_rate_and_builds_valid_body() {
        let first_prev = Outpoint {
            txid: Txid::new([4; 32]),
            index: 0,
        };
        let second_prev = Outpoint {
            txid: Txid::new([5; 32]),
            index: 0,
        };
        let (first, first_coin) = transaction(first_prev.clone(), 100, 90);
        let (second, second_coin) = transaction(second_prev.clone(), 100, 50);
        let mut view = View::default();
        view.coins.insert(first_prev, first_coin);
        view.coins.insert(second_prev, second_coin);
        let mut pool = MemoryMempool::new();
        for transaction in [first, second] {
            assert!(matches!(
                pool.submit_with_context(
                    transaction,
                    &MempoolContext::testing(11, 100),
                    &view,
                    &Allow,
                    &Allow,
                )
                .expect("admit"),
                Admission::Accepted(_)
            ));
        }
        let snapshot = snapshot();
        let pool_snapshot = pool.snapshot();
        let template = TemplateAssembler
            .assemble(TemplateBuildRequest {
                snapshot: &snapshot,
                mempool: &pool_snapshot,
                payout_address: address(9),
                coinbase_flags: b"hsrd".to_vec(),
                version: 1,
                bits: 0x207f_ffff,
                minimum_time: 101,
                reserved_root: [0; 32],
                mask_hash: [8; 32],
                policy: TemplatePolicy::default(),
            })
            .expect("template");
        assert_eq!(template.transactions().len(), 3);
        assert_eq!(template.header().tree_root, snapshot.next_tree_root);
        assert_eq!(template.metrics().fees, 60);
        assert_eq!(template.transactions()[0].outputs[0].value, 2_000_000_060);
        assert!(template.prepare_job(&snapshot).is_ok());
    }

    #[test]
    fn package_ranking_uses_hsd_sigop_size_but_block_fit_uses_weight() {
        let heavy_prev = Outpoint {
            txid: Txid::new([6; 32]),
            index: 0,
        };
        let normal_prev = Outpoint {
            txid: Txid::new([7; 32]),
            index: 0,
        };
        let (mut heavy, mut heavy_coin) = transaction(heavy_prev.clone(), 1_000, 900);
        heavy_coin.address = Address::new(0, vec![0x44; 32]).expect("script-hash address");
        heavy.inputs[0].witness = Witness {
            items: vec![vec![0xae; 200]],
        };
        let heavy_txid = heavy.txid();
        let (normal, normal_coin) = transaction(normal_prev.clone(), 100, 90);
        let normal_txid = normal.txid();
        let mut view = View::default();
        view.coins.insert(heavy_prev, heavy_coin);
        view.coins.insert(normal_prev, normal_coin);
        let mut pool = MemoryMempool::new();
        for transaction in [heavy.clone(), normal.clone()] {
            assert!(matches!(
                pool.submit_with_context(
                    transaction,
                    &MempoolContext::testing(11, 100),
                    &view,
                    &Allow,
                    &Allow,
                )
                .expect("admit"),
                Admission::Accepted(_)
            ));
        }
        let pool_snapshot = pool.snapshot();
        let heavy_entry = pool_snapshot.entry(&heavy_txid).expect("heavy entry");
        let normal_entry = pool_snapshot.entry(&normal_txid).expect("normal entry");
        assert!(
            100u128 * (transaction_weight(&normal) as u128)
                > 10u128 * (transaction_weight(&heavy) as u128),
            "raw weight would rank the sigop-heavy transaction first"
        );
        assert!(
            100u128 * (normal_entry.policy_size as u128)
                < 10u128 * (heavy_entry.policy_size as u128),
            "HSD policy size must reverse the raw-weight ranking"
        );

        let snapshot = snapshot();
        let template = TemplateAssembler
            .assemble(TemplateBuildRequest {
                snapshot: &snapshot,
                mempool: &pool_snapshot,
                payout_address: address(9),
                coinbase_flags: b"hsrd".to_vec(),
                version: 1,
                bits: 0x207f_ffff,
                minimum_time: 101,
                reserved_root: [0; 32],
                mask_hash: [8; 32],
                policy: TemplatePolicy::default(),
            })
            .expect("template");
        assert_eq!(template.transactions()[1].txid(), normal_txid);
        assert_eq!(template.transactions()[2].txid(), heavy_txid);
        assert_eq!(
            template.metrics().weight,
            hns_consensus::block_weight(&Block {
                header: Header::default(),
                transactions: template.transactions().to_vec(),
            })
        );
    }

    #[test]
    fn template_cache_rejects_stale_generation() {
        let snapshot = snapshot();
        let pool = MemoryMempool::new();
        let pool_snapshot = pool.snapshot();
        let template = TemplateAssembler
            .assemble(TemplateBuildRequest {
                snapshot: &snapshot,
                mempool: &pool_snapshot,
                payout_address: address(9),
                coinbase_flags: Vec::new(),
                version: 1,
                bits: 0x207f_ffff,
                minimum_time: 101,
                reserved_root: [0; 32],
                mask_hash: [8; 32],
                policy: TemplatePolicy::default(),
            })
            .expect("template");
        let key = TemplateCacheKey {
            snapshot_generation: snapshot.generation,
            mempool_generation: pool.info().generation,
            variant: 0,
        };
        let mut cache = FutureTemplateCache::default();
        cache.insert(key.clone(), template).expect("insert");
        assert!(cache.activate(&key, &snapshot).is_ok());
        let mut stale = snapshot.clone();
        stale.generation += 1;
        assert!(matches!(
            cache.activate(&key, &stale),
            Err(MiningError::StaleTemplate)
        ));
    }

    #[test]
    fn coordinator_rebuild_is_atomic_and_generation_bound() {
        let snapshot = snapshot();
        let pool = MemoryMempool::new();
        let pool_snapshot = pool.snapshot();
        let mut coordinator = TemplateCoordinator::new(2).expect("coordinator");
        let variants = [0u32, 1u32].map(|variant| TemplateVariant {
            variant,
            payout_address: address(9),
            coinbase_flags: vec![u8::try_from(variant).expect("test variant fits in u8")],
            version: 1,
            bits: 0x207f_ffff,
            minimum_time: 101,
            reserved_root: [0; 32],
            mask_hash: [u8::try_from(variant.saturating_add(1)).expect("test variant fits in u8");
                32],
            policy: TemplatePolicy::default(),
        });
        let templates = coordinator
            .rebuild(&snapshot, &pool_snapshot, variants)
            .expect("rebuild");
        assert_eq!(templates.len(), 2);
        assert_eq!(coordinator.len(), 2);

        let key = TemplateCacheKey {
            snapshot_generation: snapshot.generation,
            mempool_generation: pool_snapshot.generation(),
            variant: 1,
        };
        assert!(coordinator.activate(&key, &snapshot).is_ok());

        let duplicate = [0u32, 0u32].map(|variant| TemplateVariant {
            variant,
            payout_address: address(9),
            coinbase_flags: Vec::new(),
            version: 1,
            bits: 0x207f_ffff,
            minimum_time: 101,
            reserved_root: [0; 32],
            mask_hash: [9; 32],
            policy: TemplatePolicy::default(),
        });
        assert!(matches!(
            coordinator.rebuild(&snapshot, &pool_snapshot, duplicate),
            Err(MiningError::TemplateConflict)
        ));
        assert_eq!(coordinator.len(), 2);
    }

    #[test]
    fn policy_never_exceeds_consensus_limits() {
        assert!(TemplatePolicy {
            maximum_weight: MAX_BLOCK_WEIGHT + 1,
            ..TemplatePolicy::default()
        }
        .validate()
        .is_err());
        assert!(TemplatePolicy {
            reserved_sigops: MAX_BLOCK_SIGOPS + 1,
            ..TemplatePolicy::default()
        }
        .validate()
        .is_err());
    }
}
