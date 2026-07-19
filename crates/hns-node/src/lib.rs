#![forbid(unsafe_code)]

use std::{
    collections::HashSet,
    future::Future,
    net::SocketAddr,
    path::PathBuf,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use axum::{body::Bytes, extract::State, routing::post, Json, Router};
use hns_chain::{
    delete_canonical_height_from_batch, delete_tx_index_for_block_from_batch,
    write_block_index_to_batch, write_canonical_height_to_batch, write_raw_block_to_batch,
    write_record_to_batch, write_tx_index_for_block_to_batch, BlockIndexRecord, BlockStatus,
    ChainTip, HeaderRecord, RawBlockRecord, RawBlockSource, StoredBlockIndex, StoredHeaderIndex,
};
use hns_consensus::{
    expected_next_bits, validate_block_finality, ConsensusParams, DifficultyPoint, HeaderConsensus,
    HeaderParent, HeaderValidationContext, Network, MAX_FUTURE_BLOCK_TIME, MEDIAN_TIMESPAN,
};
use hns_mempool::{MemoryMempool, Mempool};
use hns_mining::{
    HeaderSummary, MiningEventHub, MiningGeneration, MiningSnapshot, MiningSubscriptions,
    SolvedMiningCandidate,
};
use hns_primitives::{Block, BlockHash, Coin, CompactTarget, Height, NameState, Uint256};
use hns_rpc::{
    BasicRpcService, JsonRpcRequest, JsonRpcResponse, RpcBlockEntry, RpcErrorObject,
    RpcHeaderEntry, RpcService, RpcSnapshot, RpcTransactionEntry,
};
use hns_state::{
    connect_block_to_batch, decode_coin, decode_name_state, disconnect_block_to_batch,
    ConnectBlock, DisconnectBlock, StoredStateEngine,
};
use hns_store::{
    decode_u64, encode_u64, open_store, ColumnFamily, MetaKey, ReadSnapshot, Store, StoreBackend,
    StoreConfig, StoreHandle, WriteBatch,
};
use tokio::net::TcpListener;
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeConfig {
    pub network: Network,
    pub data_dir: Option<PathBuf>,
    pub config_file: Option<PathBuf>,
    pub rpc_bind: SocketAddr,
    pub metrics_bind: Option<SocketAddr>,
    pub log_filter: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            network: Network::Mainnet,
            data_dir: None,
            config_file: None,
            rpc_bind: SocketAddr::from(([127, 0, 0, 1], 12037)),
            metrics_bind: None,
            log_filter: "info".to_owned(),
        }
    }
}

#[derive(Debug)]
pub struct NodeService {
    config: NodeConfig,
    state: NodeState,
    mining_events: MiningEventHub,
}

impl NodeService {
    pub fn new(config: NodeConfig) -> Self {
        let state = NodeState::memory_for_network(config.network);
        Self::with_state(config, state)
    }

    pub fn try_new(config: NodeConfig) -> Result<Self> {
        let state = NodeState::from_config(&config)?;
        Self::try_with_state(config, state)
    }

    pub fn with_state(config: NodeConfig, state: NodeState) -> Self {
        Self::try_with_state(config, state).expect("node mining state initializes")
    }

    pub fn try_with_state(config: NodeConfig, state: NodeState) -> Result<Self> {
        if state.network() != config.network {
            anyhow::bail!(
                "node state network {} does not match configured network {}",
                state.network(),
                config.network
            );
        }
        let durable = state.durable_mining_state()?;
        let mining_events = MiningEventHub::from_durable(durable.generation, durable.snapshot)
            .map_err(|error| anyhow::anyhow!("failed to initialize mining events: {error}"))?;
        Ok(Self {
            config,
            state,
            mining_events,
        })
    }

    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    pub fn state(&self) -> &NodeState {
        &self.state
    }

    pub fn state_mut(&mut self) -> &mut NodeState {
        &mut self.state
    }

    pub fn mining_snapshot(&self) -> Option<Arc<MiningSnapshot>> {
        self.mining_events.snapshot()
    }

    pub fn subscribe_mining_events(&self) -> MiningSubscriptions {
        self.mining_events.subscribe()
    }

    pub fn rpc_service(&self) -> Result<BasicRpcService> {
        Ok(BasicRpcService::new(self.rpc_snapshot()?))
    }

    pub fn connect_block(&mut self, request: NodeBlockImport) -> Result<BlockIndexRecord> {
        let summary = HeaderSummary::from_block(&request.block, request.height);
        self.mining_events.candidate_tip_seen(summary.clone());
        let chainwork = self.state.validate_import(&request)?;
        HeaderConsensus::new(ConsensusParams::for_network(self.config.network))
            .validate_block_body(&request.block)
            .map_err(|error| anyhow::anyhow!("block body validation failed: {error}"))?;
        self.mining_events.block_validated(summary);

        let committed = self.state.commit_validated_block(request, chainwork)?;
        self.publish_durable_mining_state(&committed.mining)?;
        Ok(committed.record)
    }

    pub fn submit_mining_candidate(
        &mut self,
        candidate: SolvedMiningCandidate,
    ) -> Result<BlockIndexRecord> {
        let snapshot = self
            .mining_snapshot()
            .ok_or_else(|| anyhow::anyhow!("cannot submit a mining candidate without a tip"))?;
        if candidate.snapshot_generation() != snapshot.generation
            || candidate.parent_height() != snapshot.tip.height
            || candidate.block().header.prev_block != snapshot.tip.hash
        {
            anyhow::bail!("mining candidate is stale for the committed tip generation");
        }
        self.connect_block(NodeBlockImport::from_mining_candidate(candidate)?)
    }

    pub fn disconnect_block(&mut self, request: NodeBlockDisconnect) -> Result<BlockIndexRecord> {
        let disconnected = self.state.disconnect_block(request)?;
        self.publish_durable_mining_state(&disconnected.mining)?;
        Ok(disconnected.record)
    }

    pub fn apply_reorg(&mut self, request: NodeReorg) -> Result<NodeReorgSummary> {
        for connect in &request.connect {
            let summary = HeaderSummary::from_block(&connect.block, connect.height);
            self.mining_events.candidate_tip_seen(summary.clone());
            HeaderConsensus::new(ConsensusParams::for_network(self.config.network))
                .validate_block_body(&connect.block)
                .map_err(|error| anyhow::anyhow!("reorg block body validation failed: {error}"))?;
            self.mining_events.block_validated(summary);
        }

        if request.disconnect.is_empty() && request.connect.is_empty() {
            return Ok(NodeReorgSummary::default());
        }

        self.mining_events
            .reorg_started(request.disconnect.len(), request.connect.len());
        match self.state.apply_reorg(request) {
            Ok(reorg) => {
                self.publish_durable_mining_state(&reorg.mining)?;
                Ok(reorg.summary)
            }
            Err(error) => {
                if let Ok(durable) = self.state.durable_mining_state() {
                    let _ = self.publish_durable_mining_state(&durable);
                }
                self.mining_events.reorg_aborted();
                Err(error)
            }
        }
    }

    fn publish_durable_mining_state(&self, durable: &DurableMiningState) -> Result<()> {
        if durable.generation <= self.mining_events.committed_generation() {
            return Ok(());
        }
        match &durable.snapshot {
            Some(snapshot) => self
                .mining_events
                .tip_committed(Arc::clone(snapshot))
                .map_err(|error| {
                    anyhow::anyhow!("failed to publish committed mining tip: {error}")
                }),
            None => self
                .mining_events
                .tip_cleared(durable.generation)
                .map_err(|error| anyhow::anyhow!("failed to publish cleared mining tip: {error}")),
        }
    }

    pub async fn run_until_shutdown(&self, shutdown: ShutdownSignal) -> Result<()> {
        let rpc_service = self.rpc_service()?;
        let listener = TcpListener::bind(self.config.rpc_bind)
            .await
            .with_context(|| format!("failed to bind RPC listener on {}", self.config.rpc_bind))?;
        let local_addr = listener
            .local_addr()
            .context("failed to read RPC listener address")?;

        tracing::info!(
            network = %self.config.network,
            rpc_bind = %local_addr,
            mempool_size = rpc_service.snapshot().mempool_info.transaction_count,
            "hsrd rpc server started"
        );
        serve_rpc_listener(listener, rpc_service, shutdown.wait()).await?;
        tracing::info!("hsrd rpc server stopped");
        Ok(())
    }

    fn rpc_snapshot(&self) -> Result<RpcSnapshot> {
        let chain_tip = self.state.best_block_tip()?;
        let entries = self.state.rpc_entries()?;

        Ok(RpcSnapshot {
            network: self.config.network.to_string(),
            chain_tip,
            headers: entries.headers,
            blocks: entries.blocks,
            transactions: entries.transactions,
            coins: entries.coins,
            names: entries.names,
            mempool_info: self.state.mempool.info(),
            mempool_entries: self.state.mempool.entries(),
            peer_count: 0,
        })
    }
}

#[derive(Clone, Debug)]
struct RpcHttpState {
    service: Arc<BasicRpcService>,
}

#[derive(Clone, Debug, Default)]
struct RpcStoreEntries {
    headers: Vec<RpcHeaderEntry>,
    blocks: Vec<RpcBlockEntry>,
    transactions: Vec<RpcTransactionEntry>,
    coins: Vec<Coin>,
    names: Vec<NameState>,
}

pub async fn serve_rpc_listener<F>(
    listener: TcpListener,
    service: BasicRpcService,
    shutdown: F,
) -> Result<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let state = RpcHttpState {
        service: Arc::new(service),
    };
    let app = Router::new()
        .route("/", post(handle_rpc_http))
        .route("/rpc", post(handle_rpc_http))
        .with_state(state);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .context("RPC server failed")
}

async fn handle_rpc_http(State(state): State<RpcHttpState>, body: Bytes) -> Json<JsonRpcResponse> {
    let request = match serde_json::from_slice::<JsonRpcRequest>(&body) {
        Ok(request) => request,
        Err(error) => {
            return Json(json_rpc_error(
                None,
                -32700,
                format!("parse error: {error}"),
            ))
        }
    };
    let id = request.id.clone();

    Json(
        state
            .service
            .handle(request)
            .unwrap_or_else(|error| json_rpc_error(id, -32603, format!("internal error: {error}"))),
    )
}

fn json_rpc_error(id: Option<serde_json::Value>, code: i64, message: String) -> JsonRpcResponse {
    JsonRpcResponse {
        jsonrpc: "2.0".to_owned(),
        result: None,
        error: Some(RpcErrorObject { code, message }),
        id,
    }
}

#[derive(Clone, Debug)]
pub struct NodeBlockImport {
    block: Block,
    height: Height,
    chainwork_override: Option<Uint256>,
    source: RawBlockSource,
}

impl NodeBlockImport {
    pub fn fixture(block: Block, height: Height, chainwork: u64) -> Self {
        Self {
            block,
            height,
            chainwork_override: Some(Uint256::from(chainwork)),
            source: RawBlockSource::Fixture,
        }
    }

    pub fn from_peer(block: Block, height: Height) -> Self {
        Self {
            block,
            height,
            chainwork_override: None,
            source: RawBlockSource::Peer,
        }
    }

    pub fn from_mining_candidate(candidate: SolvedMiningCandidate) -> Result<Self> {
        let height = candidate
            .parent_height()
            .checked_add(1)
            .ok_or_else(|| anyhow::anyhow!("mining candidate height overflow"))?;
        Ok(Self {
            block: candidate.into_block(),
            height,
            chainwork_override: None,
            source: RawBlockSource::Mining,
        })
    }

    pub fn block(&self) -> &Block {
        &self.block
    }

    pub fn height(&self) -> Height {
        self.height
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NodeBlockDisconnect {
    pub block_hash: hns_primitives::BlockHash,
    pub height: Height,
}

#[derive(Clone, Debug)]
pub struct NodeReorg {
    pub disconnect: Vec<NodeBlockDisconnect>,
    pub connect: Vec<NodeBlockImport>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct NodeReorgSummary {
    pub disconnected: Vec<BlockIndexRecord>,
    pub connected: Vec<BlockIndexRecord>,
}

#[derive(Clone, Debug)]
struct DurableMiningState {
    generation: MiningGeneration,
    snapshot: Option<Arc<MiningSnapshot>>,
}

#[derive(Clone, Debug)]
struct NodeBlockMutation {
    record: BlockIndexRecord,
    mining: DurableMiningState,
}

#[derive(Clone, Debug)]
struct NodeReorgMutation {
    summary: NodeReorgSummary,
    mining: DurableMiningState,
}

#[derive(Clone, Debug)]
pub struct NodeState {
    network: Network,
    pub store: StoreHandle,
    pub chain: StoredHeaderIndex<StoreHandle>,
    pub blocks: StoredBlockIndex<StoreHandle>,
    pub state_engine: StoredStateEngine<StoreHandle>,
    pub mempool: MemoryMempool,
}

impl NodeState {
    pub fn memory() -> Self {
        Self::memory_for_network(Network::Mainnet)
    }

    pub fn memory_for_network(network: Network) -> Self {
        Self::from_store_for_network(StoreHandle::memory(), network)
            .expect("memory node state initializes")
    }

    pub fn from_config(config: &NodeConfig) -> Result<Self> {
        let store = match &config.data_dir {
            Some(data_dir) => open_store(&StoreConfig {
                path: data_dir.join("chain"),
                backend: StoreBackend::RocksDb,
            })
            .map_err(|error| anyhow::anyhow!("failed to open node store: {error}"))?,
            None => StoreHandle::memory(),
        };

        Self::from_store_for_network(store, config.network)
    }

    pub fn from_store_for_network(store: StoreHandle, network: Network) -> Result<Self> {
        bind_store_network(&store, network)?;
        let chain = StoredHeaderIndex::new(store.clone())
            .map_err(|error| anyhow::anyhow!("failed to initialize header index: {error}"))?;
        let blocks = StoredBlockIndex::new(store.clone())
            .map_err(|error| anyhow::anyhow!("failed to initialize block index: {error}"))?;
        let state_engine = StoredStateEngine::new(store.clone())
            .map_err(|error| anyhow::anyhow!("failed to initialize state engine: {error}"))?;

        Ok(Self {
            network,
            store,
            chain,
            blocks,
            state_engine,
            mempool: MemoryMempool::new(),
        })
    }

    pub const fn network(&self) -> Network {
        self.network
    }

    fn best_block_tip(&self) -> Result<Option<ChainTip>> {
        let snapshot = self.store.snapshot()?;
        let Some(bytes) = snapshot
            .get(ColumnFamily::Meta, MetaKey::BestBlockHash.as_bytes())
            .context("failed to read best block hash")?
        else {
            return Ok(None);
        };
        let hash = block_hash_from_bytes(&bytes)?;
        let Some(record) = self
            .blocks
            .load_block_record(&hash)
            .map_err(|error| anyhow::anyhow!("failed to load best block record: {error}"))?
        else {
            anyhow::bail!("best block index record is missing for {}", hash.to_hex());
        };

        Ok(Some(ChainTip {
            hash,
            height: record.height,
            chainwork: record.chainwork,
        }))
    }

    fn durable_mining_state(&self) -> Result<DurableMiningState> {
        let snapshot = self.store.snapshot()?;
        let generation = mining_generation_from_snapshot(&snapshot)?;
        let best_hash = snapshot
            .get(ColumnFamily::Meta, MetaKey::BestBlockHash.as_bytes())
            .context("failed to read durable mining tip")?
            .map(|bytes| block_hash_from_bytes(&bytes))
            .transpose()?;

        let mining_snapshot = match best_hash {
            Some(hash) => Some(mining_snapshot_for_hash(
                &snapshot,
                self.network.canonical_id(),
                hash,
                generation,
            )?),
            None => None,
        };
        Ok(DurableMiningState {
            generation,
            snapshot: mining_snapshot,
        })
    }

    fn rpc_entries(&self) -> Result<RpcStoreEntries> {
        let snapshot = self.store.snapshot()?;
        let headers = self.rpc_headers(&snapshot)?;
        let canonical_hashes = headers
            .iter()
            .map(|entry| entry.record.hash)
            .collect::<HashSet<_>>();

        let mut block_records = snapshot
            .scan_prefix(ColumnFamily::BlockIndex, b"")
            .context("failed to scan block index")?
            .into_iter()
            .map(|(_, bytes)| {
                BlockIndexRecord::decode(&bytes)
                    .map_err(|error| anyhow::anyhow!("failed to decode block index: {error}"))
            })
            .collect::<Result<Vec<_>>>()?;
        block_records.sort_by_key(|record| (record.height, record.hash));

        let mut blocks = Vec::new();
        let mut transactions = Vec::new();
        for record in block_records {
            if !record.status.state_connected || !canonical_hashes.contains(&record.hash) {
                continue;
            }

            let Some(block) = self
                .blocks
                .load_block(&record.hash)
                .map_err(|error| anyhow::anyhow!("failed to load RPC block: {error}"))?
            else {
                continue;
            };

            transactions.extend(block.transactions.iter().map(|transaction| {
                RpcTransactionEntry::from_transaction(
                    transaction,
                    Some(record.hash),
                    Some(record.height),
                )
            }));
            blocks.push(RpcBlockEntry::from_block(record, &block));
        }

        let coins = snapshot
            .scan_prefix(ColumnFamily::Utxo, b"")
            .context("failed to scan UTXO set")?
            .into_iter()
            .map(|(_, bytes)| {
                decode_coin(&bytes)
                    .map_err(|error| anyhow::anyhow!("failed to decode coin: {error}"))
            })
            .collect::<Result<Vec<_>>>()?;

        let names = snapshot
            .scan_prefix(ColumnFamily::NameState, b"")
            .context("failed to scan name state")?
            .into_iter()
            .map(|(_, bytes)| {
                decode_name_state(&bytes)
                    .map_err(|error| anyhow::anyhow!("failed to decode name state: {error}"))
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(RpcStoreEntries {
            headers,
            blocks,
            transactions,
            coins,
            names,
        })
    }

    fn rpc_headers(&self, snapshot: &impl ReadSnapshot) -> Result<Vec<RpcHeaderEntry>> {
        let mut entries = snapshot
            .scan_prefix(ColumnFamily::HeightIndex, b"")
            .context("failed to scan canonical height index")?;
        entries.sort_by(|left, right| left.0.cmp(&right.0));

        let mut headers = Vec::with_capacity(entries.len());
        for (height_key, hash_bytes) in entries {
            let height = decode_height_key(&height_key)?;
            let hash = block_hash_from_bytes(&hash_bytes)?;

            if let Some(record) = self
                .chain
                .load_record(&hash)
                .map_err(|error| anyhow::anyhow!("failed to load header record: {error}"))?
            {
                headers.push(RpcHeaderEntry::new(record));
                continue;
            }

            let Some(block) = self.blocks.load_block(&hash).map_err(|error| {
                anyhow::anyhow!("failed to load block header fallback: {error}")
            })?
            else {
                continue;
            };
            let chainwork = self
                .blocks
                .load_block_record(&hash)
                .map_err(|error| anyhow::anyhow!("failed to load block header index: {error}"))?
                .map(|record| record.chainwork)
                .unwrap_or(Uint256::ZERO);
            headers.push(RpcHeaderEntry::new(HeaderRecord {
                hash,
                height,
                chainwork,
                header: block.header,
                status: BlockStatus {
                    header_valid: true,
                    ..BlockStatus::default()
                },
            }));
        }

        Ok(headers)
    }

    fn validate_import(&self, request: &NodeBlockImport) -> Result<Uint256> {
        let snapshot = self.store.snapshot()?;
        let parent = if request.height == 0 {
            None
        } else {
            Some(
                self.chain
                    .load_record(&request.block.header.prev_block)
                    .map_err(|error| anyhow::anyhow!("failed to load header parent: {error}"))?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "missing header parent {}",
                            request.block.header.prev_block.to_hex()
                        )
                    })?,
            )
        };

        let median_time_past = parent
            .as_ref()
            .map(|record| self.median_time_past(record))
            .transpose()?;

        if request.chainwork_override.is_none() {
            let expected_bits = Some(self.expected_bits_for_import(request, parent.as_ref())?);
            let maximum_time = current_unix_time()?.saturating_add(MAX_FUTURE_BLOCK_TIME);
            HeaderConsensus::new(ConsensusParams::for_network(self.network))
                .validate_header(
                    &request.block.header,
                    &HeaderValidationContext {
                        height: request.height,
                        previous: parent.as_ref().map(|record| HeaderParent {
                            hash: record.hash,
                            height: record.height,
                            bits: record.header.bits,
                            chainwork: record.chainwork,
                        }),
                        expected_bits,
                        median_time_past,
                        maximum_time: Some(maximum_time),
                        require_pow: true,
                    },
                )
                .map_err(|error| anyhow::anyhow!("header validation failed: {error}"))?;
        }

        validate_block_finality(
            &request.block,
            request.height,
            median_time_past.unwrap_or(request.block.header.time),
        )
        .map_err(|error| anyhow::anyhow!("transaction finality validation failed: {error}"))?;

        let chainwork = match request.chainwork_override {
            Some(chainwork) => chainwork,
            None => {
                let proof = CompactTarget::from_bits(request.block.header.bits)
                    .proof()
                    .ok_or_else(|| anyhow::anyhow!("header has an invalid proof-of-work target"))?;
                parent
                    .as_ref()
                    .map(|record| record.chainwork)
                    .unwrap_or(Uint256::ZERO)
                    .checked_add(proof)
                    .ok_or_else(|| anyhow::anyhow!("header chainwork overflow"))?
            }
        };

        validate_canonical_extension(&snapshot, request, chainwork)?;
        Ok(chainwork)
    }

    fn expected_bits_for_import(
        &self,
        request: &NodeBlockImport,
        parent: Option<&HeaderRecord>,
    ) -> Result<u32> {
        let pow = self.network.params().pow;
        let Some(parent) = parent else {
            return Ok(pow.bits);
        };
        let previous = difficulty_point(parent);
        let reset = pow.target_reset
            && request.block.header.time
                > parent
                    .header
                    .time
                    .saturating_add(u64::from(pow.target_spacing).saturating_mul(2));
        if pow.no_retargeting || reset || parent.height < pow.target_window.saturating_add(2) {
            return expected_next_bits(pow, request.block.header.time, previous, None, None)
                .map_err(|error| anyhow::anyhow!("difficulty validation failed: {error}"));
        }

        let last = self.suitable_block(parent)?;
        let ancestor_height = parent
            .height
            .checked_sub(pow.target_window)
            .ok_or_else(|| anyhow::anyhow!("difficulty ancestor height underflow"))?;
        let ancestor = self.ancestor(parent.clone(), ancestor_height)?;
        let first = self.suitable_block(&ancestor)?;
        expected_next_bits(
            pow,
            request.block.header.time,
            previous,
            Some(difficulty_point(&first)),
            Some(difficulty_point(&last)),
        )
        .map_err(|error| anyhow::anyhow!("difficulty validation failed: {error}"))
    }

    fn suitable_block(&self, tip: &HeaderRecord) -> Result<HeaderRecord> {
        let mut z = tip.clone();
        let mut y = self.header_parent(&z)?;
        let mut x = self.header_parent(&y)?;
        if x.header.time > z.header.time {
            std::mem::swap(&mut x, &mut z);
        }
        if x.header.time > y.header.time {
            std::mem::swap(&mut x, &mut y);
        }
        if y.header.time > z.header.time {
            std::mem::swap(&mut y, &mut z);
        }
        Ok(y)
    }

    fn median_time_past(&self, tip: &HeaderRecord) -> Result<u64> {
        let mut times = Vec::with_capacity(MEDIAN_TIMESPAN);
        let mut record = tip.clone();
        loop {
            times.push(record.header.time);
            if times.len() == MEDIAN_TIMESPAN || record.height == 0 {
                break;
            }
            record = self.header_parent(&record)?;
        }
        times.sort_unstable();
        Ok(times[times.len() / 2])
    }

    fn ancestor(&self, mut record: HeaderRecord, height: Height) -> Result<HeaderRecord> {
        if height > record.height {
            anyhow::bail!("difficulty ancestor is above the starting header");
        }
        while record.height > height {
            record = self.header_parent(&record)?;
        }
        if record.height != height {
            anyhow::bail!("difficulty ancestor chain is not contiguous");
        }
        Ok(record)
    }

    fn header_parent(&self, record: &HeaderRecord) -> Result<HeaderRecord> {
        if record.height == 0 {
            anyhow::bail!("genesis header has no parent");
        }
        let parent = self
            .chain
            .load_record(&record.header.prev_block)
            .map_err(|error| anyhow::anyhow!("failed to load difficulty parent: {error}"))?
            .ok_or_else(|| anyhow::anyhow!("difficulty parent header is missing"))?;
        if parent.height.checked_add(1) != Some(record.height)
            || parent.hash != record.header.prev_block
        {
            anyhow::bail!("difficulty parent linkage is invalid");
        }
        Ok(parent)
    }

    fn commit_block(&mut self, request: NodeBlockImport) -> Result<NodeBlockMutation> {
        let chainwork = self.validate_import(&request)?;
        self.commit_validated_block(request, chainwork)
    }

    fn commit_validated_block(
        &mut self,
        request: NodeBlockImport,
        chainwork: Uint256,
    ) -> Result<NodeBlockMutation> {
        let block_hash = request.block.hash();
        let mut record = BlockIndexRecord::from_block(&request.block, request.height, chainwork)
            .map_err(|error| anyhow::anyhow!("failed to build block index record: {error}"))?;
        record.status = BlockStatus {
            header_valid: true,
            body_present: true,
            body_valid: true,
            tx_valid: true,
            state_connected: true,
            undo_present: true,
            ..BlockStatus::default()
        };
        let header_record = HeaderRecord {
            hash: block_hash,
            height: request.height,
            chainwork,
            header: request.block.header.clone(),
            status: record.status.clone(),
        };

        let raw_record = RawBlockRecord::from_block(&request.block, request.source);
        let snapshot = self.store.snapshot()?;
        validate_canonical_extension(&snapshot, &request, chainwork)?;
        let generation = next_mining_generation(&snapshot)?;
        let mining_snapshot = Arc::new(MiningSnapshot {
            network_id: self.network.canonical_id(),
            generation,
            tip: HeaderSummary::from_block(&request.block, request.height),
            chainwork,
        });
        let mut next_chain = self.chain.clone();
        next_chain
            .cache_record(header_record.clone())
            .map_err(|error| anyhow::anyhow!("failed to stage header cache: {error}"))?;
        let mut next_blocks = self.blocks.clone();
        next_blocks
            .cache_record(record.clone())
            .map_err(|error| anyhow::anyhow!("failed to stage block cache: {error}"))?;
        let mut batch = self.store.batch();

        write_record_to_batch(&mut batch, &header_record)
            .map_err(|error| anyhow::anyhow!("failed to stage header index: {error}"))?;
        write_block_index_to_batch(&mut batch, &record)
            .map_err(|error| anyhow::anyhow!("failed to stage block index: {error}"))?;
        write_raw_block_to_batch(&mut batch, &raw_record)
            .map_err(|error| anyhow::anyhow!("failed to stage raw block: {error}"))?;
        write_tx_index_for_block_to_batch(&mut batch, &request.block, request.height)
            .map_err(|error| anyhow::anyhow!("failed to stage tx index: {error}"))?;
        connect_block_to_batch(
            &snapshot,
            &mut batch,
            ConnectBlock {
                block_hash,
                height: request.height,
                coinbase_maturity: self.network.params().coinbase_maturity,
                block_reward: self.network.params().block_reward(request.height),
                block: &request.block,
            },
        )
        .map_err(|error| anyhow::anyhow!("failed to stage state update: {error}"))?;
        write_canonical_height_to_batch(&mut batch, request.height, block_hash)
            .map_err(|error| anyhow::anyhow!("failed to stage canonical height: {error}"))?;
        batch.put(
            ColumnFamily::Meta,
            MetaKey::BestBlockHash.as_bytes(),
            block_hash.as_bytes(),
        )?;
        batch.put(
            ColumnFamily::Meta,
            MetaKey::BestHeaderHash.as_bytes(),
            block_hash.as_bytes(),
        )?;
        batch.put(
            ColumnFamily::Meta,
            MetaKey::MiningGeneration.as_bytes(),
            &encode_u64(generation),
        )?;

        self.store.commit(batch)?;
        self.chain = next_chain;
        self.blocks = next_blocks;
        Ok(NodeBlockMutation {
            record,
            mining: DurableMiningState {
                generation,
                snapshot: Some(mining_snapshot),
            },
        })
    }

    fn disconnect_block(&mut self, request: NodeBlockDisconnect) -> Result<NodeBlockMutation> {
        let snapshot = self.store.snapshot()?;
        let best_hash = snapshot
            .get(ColumnFamily::Meta, MetaKey::BestBlockHash.as_bytes())
            .context("failed to read best block before disconnect")?
            .ok_or_else(|| anyhow::anyhow!("cannot disconnect an empty chain"))
            .and_then(|bytes| block_hash_from_bytes(&bytes))?;
        if best_hash != request.block_hash {
            anyhow::bail!(
                "disconnect target {} is not the canonical tip {}",
                request.block_hash.to_hex(),
                best_hash.to_hex()
            );
        }
        let block = self
            .blocks
            .load_block(&request.block_hash)
            .map_err(|error| anyhow::anyhow!("failed to load raw block: {error}"))?
            .ok_or_else(|| anyhow::anyhow!("raw block is missing for {:?}", request.block_hash))?;
        let undo = self
            .state_engine
            .load_undo(&request.block_hash)
            .map_err(|error| anyhow::anyhow!("failed to load block undo: {error}"))?
            .ok_or_else(|| anyhow::anyhow!("undo is missing for {:?}", request.block_hash))?;
        let mut record = self
            .blocks
            .load_block_record(&request.block_hash)
            .map_err(|error| anyhow::anyhow!("failed to load block index record: {error}"))?
            .ok_or_else(|| {
                anyhow::anyhow!("block index is missing for {:?}", request.block_hash)
            })?;

        if record.height != request.height {
            anyhow::bail!(
                "block height mismatch: expected {}, got {}",
                request.height,
                record.height
            );
        }

        record.status.state_connected = false;
        record.status.undo_present = false;
        let header_record = HeaderRecord {
            hash: request.block_hash,
            height: record.height,
            chainwork: record.chainwork,
            header: block.header.clone(),
            status: record.status.clone(),
        };

        let generation = next_mining_generation(&snapshot)?;
        let next_snapshot = if request.height == 0 {
            None
        } else {
            Some(mining_snapshot_for_hash(
                &snapshot,
                self.network.canonical_id(),
                block.header.prev_block,
                generation,
            )?)
        };
        let mut next_chain = self.chain.clone();
        next_chain
            .cache_record(header_record.clone())
            .map_err(|error| {
                anyhow::anyhow!("failed to stage disconnected header cache: {error}")
            })?;
        let mut next_blocks = self.blocks.clone();
        next_blocks.cache_record(record.clone()).map_err(|error| {
            anyhow::anyhow!("failed to stage disconnected block cache: {error}")
        })?;

        let mut batch = self.store.batch();
        disconnect_block_to_batch(
            &mut batch,
            DisconnectBlock {
                block_hash: request.block_hash,
                height: request.height,
            },
            &undo,
        )
        .map_err(|error| anyhow::anyhow!("failed to stage state disconnect: {error}"))?;
        delete_tx_index_for_block_from_batch(&mut batch, &block)
            .map_err(|error| anyhow::anyhow!("failed to stage tx-index deletion: {error}"))?;
        write_block_index_to_batch(&mut batch, &record)
            .map_err(|error| anyhow::anyhow!("failed to stage block index update: {error}"))?;
        write_record_to_batch(&mut batch, &header_record)
            .map_err(|error| anyhow::anyhow!("failed to stage header index update: {error}"))?;
        delete_canonical_height_from_batch(&mut batch, request.height)
            .map_err(|error| anyhow::anyhow!("failed to stage canonical height delete: {error}"))?;

        if request.height == 0 {
            batch.delete(ColumnFamily::Meta, MetaKey::BestBlockHash.as_bytes())?;
        } else {
            batch.put(
                ColumnFamily::Meta,
                MetaKey::BestBlockHash.as_bytes(),
                block.header.prev_block.as_bytes(),
            )?;
        }
        batch.put(
            ColumnFamily::Meta,
            MetaKey::MiningGeneration.as_bytes(),
            &encode_u64(generation),
        )?;

        self.store.commit(batch)?;
        self.chain = next_chain;
        self.blocks = next_blocks;
        Ok(NodeBlockMutation {
            record,
            mining: DurableMiningState {
                generation,
                snapshot: next_snapshot,
            },
        })
    }

    fn apply_reorg(&mut self, request: NodeReorg) -> Result<NodeReorgMutation> {
        let mut summary = NodeReorgSummary::default();
        let mut mining = self.durable_mining_state()?;

        for disconnect in request.disconnect {
            let mutation = self.disconnect_block(disconnect)?;
            summary.disconnected.push(mutation.record);
            mining = mutation.mining;
        }

        for connect in request.connect {
            let mutation = self.commit_block(connect)?;
            summary.connected.push(mutation.record);
            mining = mutation.mining;
        }

        Ok(NodeReorgMutation { summary, mining })
    }
}

impl Default for NodeState {
    fn default() -> Self {
        Self::memory()
    }
}

fn block_hash_from_bytes(bytes: &[u8]) -> Result<BlockHash> {
    let hash: [u8; 32] = bytes
        .try_into()
        .with_context(|| format!("expected 32-byte block hash, got {}", bytes.len()))?;
    Ok(BlockHash::new(hash))
}

fn mining_generation_from_snapshot(snapshot: &impl ReadSnapshot) -> Result<MiningGeneration> {
    snapshot
        .get(ColumnFamily::Meta, MetaKey::MiningGeneration.as_bytes())
        .context("failed to read mining generation")?
        .map(|bytes| {
            decode_u64(&bytes)
                .map_err(|error| anyhow::anyhow!("failed to decode mining generation: {error}"))
        })
        .transpose()
        .map(|generation| generation.unwrap_or(0))
}

fn next_mining_generation(snapshot: &impl ReadSnapshot) -> Result<MiningGeneration> {
    mining_generation_from_snapshot(snapshot)?
        .checked_add(1)
        .ok_or_else(|| anyhow::anyhow!("mining generation exhausted"))
}

fn mining_snapshot_for_hash(
    snapshot: &impl ReadSnapshot,
    network_id: u8,
    hash: BlockHash,
    generation: MiningGeneration,
) -> Result<Arc<MiningSnapshot>> {
    if generation == 0 {
        anyhow::bail!("a durable mining tip cannot have generation zero");
    }
    let record_bytes = snapshot
        .get(ColumnFamily::BlockIndex, hash.as_bytes())
        .context("failed to read mining block index")?
        .ok_or_else(|| anyhow::anyhow!("mining block index is missing for {}", hash.to_hex()))?;
    let record = BlockIndexRecord::decode(&record_bytes)
        .map_err(|error| anyhow::anyhow!("failed to decode mining block index: {error}"))?;
    if record.hash != hash || !record.status.state_connected {
        anyhow::bail!("mining tip {} is not state-connected", hash.to_hex());
    }
    let raw_bytes = snapshot
        .get(ColumnFamily::Blocks, hash.as_bytes())
        .context("failed to read mining raw block")?
        .ok_or_else(|| anyhow::anyhow!("mining raw block is missing for {}", hash.to_hex()))?;
    let raw = RawBlockRecord::decode(&raw_bytes)
        .map_err(|error| anyhow::anyhow!("failed to decode mining raw block: {error}"))?;
    let block = raw
        .decode_block()
        .map_err(|error| anyhow::anyhow!("failed to decode mining block: {error}"))?;

    Ok(Arc::new(MiningSnapshot {
        network_id,
        generation,
        tip: HeaderSummary::from_block(&block, record.height),
        chainwork: record.chainwork,
    }))
}

fn bind_store_network(store: &StoreHandle, network: Network) -> Result<()> {
    let expected = [network.canonical_id()];
    let snapshot = store.snapshot()?;
    match snapshot
        .get(ColumnFamily::Meta, MetaKey::Network.as_bytes())
        .context("failed to read node network binding")?
    {
        Some(actual) if actual == expected => Ok(()),
        Some(actual) => anyhow::bail!(
            "node store network binding {:?} does not match configured {} ({})",
            actual,
            network,
            expected[0]
        ),
        None => {
            let mut batch = store.batch();
            batch.put(ColumnFamily::Meta, MetaKey::Network.as_bytes(), &expected)?;
            store.commit(batch)?;
            Ok(())
        }
    }
}

fn difficulty_point(record: &HeaderRecord) -> DifficultyPoint {
    DifficultyPoint {
        height: record.height,
        time: record.header.time,
        bits: record.header.bits,
        chainwork: record.chainwork,
    }
}

fn current_unix_time() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .context("system clock is before the Unix epoch")
}

fn validate_canonical_extension(
    snapshot: &impl ReadSnapshot,
    request: &NodeBlockImport,
    chainwork: Uint256,
) -> Result<()> {
    let best_hash = snapshot
        .get(ColumnFamily::Meta, MetaKey::BestBlockHash.as_bytes())
        .context("failed to read canonical tip before connect")?
        .map(|bytes| block_hash_from_bytes(&bytes))
        .transpose()?;

    match (request.height, best_hash) {
        (0, None) if chainwork > Uint256::ZERO => Ok(()),
        (0, None) => anyhow::bail!("genesis chainwork must be positive"),
        (0, Some(_)) => anyhow::bail!("cannot connect a second genesis block"),
        (_, None) => anyhow::bail!("non-genesis block cannot connect to an empty chain"),
        (height, Some(best_hash)) => {
            if request.block.header.prev_block != best_hash {
                anyhow::bail!(
                    "block parent {} does not match canonical tip {}",
                    request.block.header.prev_block.to_hex(),
                    best_hash.to_hex()
                );
            }
            let parent_bytes = snapshot
                .get(ColumnFamily::BlockIndex, best_hash.as_bytes())
                .context("failed to read canonical parent index")?
                .ok_or_else(|| anyhow::anyhow!("canonical parent block index is missing"))?;
            let parent = BlockIndexRecord::decode(&parent_bytes)
                .map_err(|error| anyhow::anyhow!("failed to decode canonical parent: {error}"))?;
            let expected_height = parent
                .height
                .checked_add(1)
                .ok_or_else(|| anyhow::anyhow!("canonical height exhausted"))?;
            if height != expected_height {
                anyhow::bail!(
                    "block height {height} does not extend canonical height {}",
                    parent.height
                );
            }
            if chainwork <= parent.chainwork {
                anyhow::bail!("block chainwork must increase over its canonical parent");
            }
            Ok(())
        }
    }
}

fn decode_height_key(bytes: &[u8]) -> Result<Height> {
    let height: [u8; 4] = bytes
        .try_into()
        .with_context(|| format!("expected 4-byte height key, got {}", bytes.len()))?;
    Ok(u32::from_be_bytes(height))
}

#[derive(Clone, Copy, Debug, Default)]
pub struct ShutdownSignal;

impl ShutdownSignal {
    pub fn ctrl_c() -> Self {
        Self
    }

    pub async fn wait(self) {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::warn!(%error, "failed to wait for ctrl-c shutdown signal");
        }
    }
}

pub fn init_logging(filter: &str) -> Result<()> {
    let env_filter =
        EnvFilter::try_new(filter).with_context(|| format!("invalid tracing filter `{filter}`"))?;

    fmt()
        .with_env_filter(env_filter)
        .try_init()
        .map_err(|error| anyhow::anyhow!("failed to initialize tracing subscriber: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_chain::{read_canonical_hash, HeaderImport};
    use hns_consensus::{block_merkle_root, block_witness_root};
    use hns_primitives::{
        Address, Covenant, CovenantKind, Header, Input, Outpoint, Output, Transaction, Txid,
        Witness,
    };
    use hns_rpc::{JsonRpcRequest, RpcService};
    use hns_state::StateView;
    use hns_store::ReadSnapshot;
    use serde_json::{json, Value};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn transaction() -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: Outpoint {
                    txid: Txid::new([9; 32]),
                    index: 0,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value: 10,
                address: Address::new(0, vec![4; 20]).expect("address"),
                covenant: Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            }],
            locktime: 0,
        }
    }

    fn coinbase_transaction() -> Transaction {
        coinbase_transaction_with_address(6, 50)
    }

    fn coinbase_transaction_with_address(address_byte: u8, value: u64) -> Transaction {
        Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: Outpoint {
                    txid: Txid::ZERO,
                    index: u32::MAX,
                },
                sequence: u32::MAX,
                witness: Witness::default(),
            }],
            outputs: vec![Output {
                value,
                address: Address::new(0, vec![address_byte; 20]).expect("address"),
                covenant: Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            }],
            locktime: 0,
        }
    }

    fn block_with_commitments(transactions: Vec<Transaction>) -> hns_primitives::Block {
        let mut block = hns_primitives::Block {
            header: Header {
                nonce: 10,
                ..Header::default()
            },
            transactions,
        };
        block.header.merkle_root = block_merkle_root(&block);
        block.header.witness_root = block_witness_root(&block);
        block
    }

    #[test]
    fn node_rpc_snapshot_reflects_state() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        node.state_mut()
            .chain
            .import_header(HeaderImport {
                header: Header {
                    bits: Network::Regtest.params().pow.bits,
                    ..Header::default()
                },
                height: 0,
                verify_pow: false,
            })
            .expect("header");
        node.state_mut()
            .mempool
            .submit(transaction())
            .expect("submit");

        let rpc = node.rpc_service().expect("rpc service");
        let response = rpc
            .handle(JsonRpcRequest {
                jsonrpc: Some("2.0".to_owned()),
                method: "getmempoolinfo".to_owned(),
                params: Value::Null,
                id: Some(json!(1)),
            })
            .expect("response");

        assert_eq!(response.result.expect("result")["size"], 1);
    }

    #[test]
    fn node_connect_block_commits_indexes_state_and_metadata_atomically() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let block = block_with_commitments(vec![coinbase_transaction()]);
        let txid = block.transactions[0].txid();
        let outpoint = Outpoint { txid, index: 0 };

        let record = node
            .connect_block(NodeBlockImport::fixture(block.clone(), 0, 1))
            .expect("connect block");

        assert!(record.status.body_valid);
        assert!(record.status.tx_valid);
        assert!(record.status.state_connected);
        assert_eq!(
            node.state()
                .blocks
                .load_block(&record.hash)
                .expect("load block"),
            Some(block)
        );
        assert_eq!(
            node.state()
                .blocks
                .load_tx_index(&txid)
                .expect("tx index")
                .expect("tx")
                .block_hash,
            record.hash
        );
        assert!(node
            .state()
            .state_engine
            .coin(&outpoint)
            .expect("coin")
            .is_some());
        assert!(node
            .state()
            .state_engine
            .load_undo(&record.hash)
            .expect("undo")
            .is_some());

        let snapshot = node.state().store.snapshot().expect("snapshot");
        assert_eq!(
            read_canonical_hash(&snapshot, 0).expect("height"),
            Some(record.hash)
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, MetaKey::BestBlockHash.as_bytes())
                .expect("best block"),
            Some(record.hash.as_bytes().to_vec())
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, MetaKey::MiningGeneration.as_bytes())
                .expect("mining generation")
                .map(|bytes| decode_u64(&bytes).expect("decode generation")),
            Some(1)
        );
        assert_eq!(
            node.mining_snapshot().expect("mining snapshot").generation,
            1
        );

        let disconnected = node
            .disconnect_block(NodeBlockDisconnect {
                block_hash: record.hash,
                height: 0,
            })
            .expect("disconnect block");

        assert!(!disconnected.status.state_connected);
        assert!(!disconnected.status.undo_present);
        assert!(node
            .state()
            .state_engine
            .coin(&outpoint)
            .expect("coin removed")
            .is_none());
        assert!(node
            .state()
            .state_engine
            .load_undo(&record.hash)
            .expect("undo removed")
            .is_none());
        assert!(node
            .state()
            .blocks
            .load_tx_index(&txid)
            .expect("tx index removed")
            .is_none());
        assert!(node
            .state()
            .blocks
            .load_block(&record.hash)
            .expect("raw block retained")
            .is_some());

        let snapshot = node.state().store.snapshot().expect("snapshot");
        assert_eq!(read_canonical_hash(&snapshot, 0).expect("height"), None);
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, MetaKey::BestBlockHash.as_bytes())
                .expect("best block removed"),
            None
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, MetaKey::MiningGeneration.as_bytes())
                .expect("mining generation")
                .map(|bytes| decode_u64(&bytes).expect("decode generation")),
            Some(2)
        );
        assert!(node.mining_snapshot().is_none());
    }

    #[test]
    fn node_rejects_non_final_block_without_advancing_the_tip() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let parent = block_with_commitments(vec![coinbase_transaction_with_address(21, 50)]);
        let parent_record = node
            .connect_block(NodeBlockImport::fixture(parent, 0, 1))
            .expect("parent");

        let mut non_final = transaction();
        non_final.locktime = 1;
        non_final.inputs[0].sequence = u32::MAX - 1;
        let mut child =
            block_with_commitments(vec![coinbase_transaction_with_address(22, 50), non_final]);
        child.header.prev_block = parent_record.hash;
        let child_hash = child.hash();
        let error = node
            .connect_block(NodeBlockImport::fixture(child, 1, 2))
            .expect_err("non-final block");

        assert!(error.to_string().contains("non-final transaction"));
        assert_eq!(
            node.state().best_block_tip().expect("tip").expect("tip"),
            ChainTip {
                hash: parent_record.hash,
                height: 0,
                chainwork: Uint256::ONE,
            }
        );
        assert!(node
            .state()
            .blocks
            .load_block(&child_hash)
            .expect("child lookup")
            .is_none());
    }

    #[test]
    fn peer_block_chainwork_is_derived_from_the_header_target() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let parent = block_with_commitments(vec![coinbase_transaction_with_address(11, 50)]);
        let parent_record = node
            .connect_block(NodeBlockImport::fixture(parent, 0, 1))
            .expect("fixture parent");

        let mut child = block_with_commitments(vec![coinbase_transaction_with_address(12, 50)]);
        child.header.prev_block = parent_record.hash;
        child.header.bits = Network::Regtest.params().pow.bits;
        child.header.time = 1;
        while !child.header.verify_pow() {
            child.header.nonce = child.header.nonce.checked_add(1).expect("nonce space");
        }

        let child_record = node
            .connect_block(NodeBlockImport::from_peer(child, 1))
            .expect("peer child");
        assert_eq!(child_record.chainwork, Uint256::from(3u64));
    }

    #[test]
    fn peer_block_cannot_select_its_own_difficulty_bits() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let parent = block_with_commitments(vec![coinbase_transaction_with_address(13, 50)]);
        let parent_record = node
            .connect_block(NodeBlockImport::fixture(parent, 0, 1))
            .expect("fixture parent");
        let mut child = block_with_commitments(vec![coinbase_transaction_with_address(14, 50)]);
        child.header.prev_block = parent_record.hash;
        child.header.bits = Network::Mainnet.params().pow.bits;
        child.header.time = 1;

        assert!(node
            .connect_block(NodeBlockImport::from_peer(child, 1))
            .is_err());
        assert_eq!(
            node.mining_snapshot().expect("parent snapshot").tip.hash,
            parent_record.hash
        );
    }

    #[tokio::test]
    async fn mining_events_are_staged_and_only_commit_after_durable_storage() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let mut subscription = node.subscribe_mining_events();
        let block = block_with_commitments(vec![coinbase_transaction()]);
        let block_hash = block.hash();

        node.connect_block(NodeBlockImport::fixture(block, 0, 1))
            .expect("connect block");

        assert!(matches!(
            subscription.events.recv().await.expect("candidate"),
            hns_mining::ChainEvent::CandidateTipSeen { .. }
        ));
        assert!(matches!(
            subscription.events.recv().await.expect("validated"),
            hns_mining::ChainEvent::BlockValidated { .. }
        ));
        assert!(matches!(
            subscription.events.recv().await.expect("committed"),
            hns_mining::ChainEvent::TipCommitted { .. }
        ));

        let snapshot = node.state().store.snapshot().expect("store snapshot");
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, MetaKey::BestBlockHash.as_bytes())
                .expect("durable tip"),
            Some(block_hash.as_bytes().to_vec())
        );
        assert_eq!(
            subscription
                .latest_snapshot
                .borrow()
                .as_ref()
                .map(|snapshot| (snapshot.generation, snapshot.tip.hash)),
            Some((1, block_hash))
        );
    }

    #[test]
    fn invalid_block_never_reaches_validated_or_committed_stage() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let mut subscription = node.subscribe_mining_events();
        let mut block = block_with_commitments(vec![coinbase_transaction()]);
        block.header.merkle_root[0] ^= 1;

        assert!(node
            .connect_block(NodeBlockImport::fixture(block, 0, 1))
            .is_err());
        assert!(matches!(
            subscription.events.try_recv().expect("candidate"),
            hns_mining::ChainEvent::CandidateTipSeen { .. }
        ));
        assert!(matches!(
            subscription.events.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
        assert!(node.mining_snapshot().is_none());
    }

    #[test]
    fn restart_recovers_the_exact_durable_mining_generation_and_tip() {
        let store = StoreHandle::memory();
        let config = NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        };
        let state =
            NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("state");
        let mut node = NodeService::try_with_state(config.clone(), state).expect("node");
        let block = block_with_commitments(vec![coinbase_transaction()]);
        let expected_hash = block.hash();
        node.connect_block(NodeBlockImport::fixture(block, 0, 1))
            .expect("connect block");
        drop(node);

        let state =
            NodeState::from_store_for_network(store, Network::Regtest).expect("reloaded state");
        let restarted = NodeService::try_with_state(config, state).expect("restarted node");
        let snapshot = restarted.mining_snapshot().expect("recovered snapshot");
        assert_eq!(snapshot.generation, 1);
        assert_eq!(snapshot.tip.hash, expected_hash);
        assert_eq!(snapshot.chainwork, Uint256::ONE);
        assert_eq!(snapshot.network_id, Network::Regtest.canonical_id());
    }

    #[test]
    fn durable_store_rejects_cross_network_reopen() {
        let store = StoreHandle::memory();
        NodeState::from_store_for_network(store.clone(), Network::Regtest).expect("bind regtest");
        assert!(NodeState::from_store_for_network(store, Network::Mainnet).is_err());
    }

    #[test]
    fn node_rpc_snapshot_reads_committed_block_state() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let block = block_with_commitments(vec![coinbase_transaction()]);
        let record = node
            .connect_block(NodeBlockImport::fixture(block.clone(), 0, 1))
            .expect("connect block");
        let txid = block.transactions[0].txid();

        let rpc = node.rpc_service().expect("rpc service");
        let block_count = rpc
            .handle(JsonRpcRequest {
                jsonrpc: Some("2.0".to_owned()),
                method: "getblockcount".to_owned(),
                params: Value::Null,
                id: Some(json!(1)),
            })
            .expect("block count");
        assert_eq!(block_count.result.expect("height"), json!(0));

        let height_hash = rpc
            .handle(JsonRpcRequest {
                jsonrpc: Some("2.0".to_owned()),
                method: "getblockhash".to_owned(),
                params: json!([0]),
                id: Some(json!(2)),
            })
            .expect("block hash");
        assert_eq!(
            height_hash.result.expect("hash"),
            json!(record.hash.to_hex())
        );

        let raw_tx = rpc
            .handle(JsonRpcRequest {
                jsonrpc: Some("2.0".to_owned()),
                method: "getrawtransaction".to_owned(),
                params: json!([txid.to_hex(), true]),
                id: Some(json!(3)),
            })
            .expect("raw tx");
        assert_eq!(raw_tx.result.expect("tx")["confirmations"], 1);

        let coin = rpc
            .handle(JsonRpcRequest {
                jsonrpc: Some("2.0".to_owned()),
                method: "gettxout".to_owned(),
                params: json!([txid.to_hex(), 0]),
                id: Some(json!(4)),
            })
            .expect("coin");
        assert_eq!(coin.result.expect("coin")["value"], 50);
    }

    #[tokio::test]
    async fn node_serves_json_rpc_over_http() {
        let node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let service = node.rpc_service().expect("rpc service");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            serve_rpc_listener(listener, service, async move {
                let _ = shutdown_rx.await;
            })
            .await
        });

        let body = r#"{"jsonrpc":"2.0","method":"getnetworkinfo","params":[],"id":7}"#;
        let request = format!(
            "POST / HTTP/1.1\r\nHost: {addr}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
        stream
            .write_all(request.as_bytes())
            .await
            .expect("write request");
        let mut response = String::new();
        stream
            .read_to_string(&mut response)
            .await
            .expect("read response");

        assert!(response.starts_with("HTTP/1.1 200 OK"), "{response}");
        let (_, response_body) = response.split_once("\r\n\r\n").expect("body split");
        let json: Value = serde_json::from_str(response_body).expect("json response");
        assert_eq!(json["id"], 7);
        assert_eq!(json["result"]["networkactive"], true);

        shutdown_tx.send(()).expect("shutdown");
        server.await.expect("server join").expect("server result");
    }

    #[test]
    fn node_apply_reorg_disconnects_then_connects_new_tip() {
        let mut node = NodeService::new(NodeConfig {
            network: Network::Regtest,
            ..NodeConfig::default()
        });
        let old_block = block_with_commitments(vec![coinbase_transaction_with_address(7, 50)]);
        let old_txid = old_block.transactions[0].txid();
        let old_outpoint = Outpoint {
            txid: old_txid,
            index: 0,
        };
        let old_record = node
            .connect_block(NodeBlockImport::fixture(old_block.clone(), 0, 1))
            .expect("connect old");
        let mut mining = node.subscribe_mining_events();

        let new_block = block_with_commitments(vec![coinbase_transaction_with_address(8, 60)]);
        let new_txid = new_block.transactions[0].txid();
        let new_outpoint = Outpoint {
            txid: new_txid,
            index: 0,
        };
        let summary = node
            .apply_reorg(NodeReorg {
                disconnect: vec![NodeBlockDisconnect {
                    block_hash: old_record.hash,
                    height: 0,
                }],
                connect: vec![NodeBlockImport::fixture(new_block.clone(), 0, 2)],
            })
            .expect("reorg");

        assert_eq!(summary.disconnected.len(), 1);
        assert_eq!(summary.connected.len(), 1);
        assert!(!summary.disconnected[0].status.state_connected);
        assert!(summary.connected[0].status.state_connected);
        assert!(node
            .state()
            .state_engine
            .coin(&old_outpoint)
            .expect("old coin")
            .is_none());
        assert!(node
            .state()
            .state_engine
            .coin(&new_outpoint)
            .expect("new coin")
            .is_some());
        assert!(node
            .state()
            .blocks
            .load_tx_index(&old_txid)
            .expect("old tx index")
            .is_none());
        assert!(node
            .state()
            .blocks
            .load_tx_index(&new_txid)
            .expect("new tx index")
            .is_some());

        let snapshot = node.state().store.snapshot().expect("snapshot");
        assert_eq!(
            read_canonical_hash(&snapshot, 0).expect("height"),
            Some(summary.connected[0].hash)
        );
        assert_eq!(
            snapshot
                .get(ColumnFamily::Meta, MetaKey::BestBlockHash.as_bytes())
                .expect("best block"),
            Some(summary.connected[0].hash.as_bytes().to_vec())
        );
        assert!(matches!(
            mining.events.try_recv().expect("candidate"),
            hns_mining::ChainEvent::CandidateTipSeen { .. }
        ));
        assert!(matches!(
            mining.events.try_recv().expect("validated"),
            hns_mining::ChainEvent::BlockValidated { .. }
        ));
        assert!(matches!(
            mining.events.try_recv().expect("reorg start"),
            hns_mining::ChainEvent::ReorgStarted { .. }
        ));
        assert!(matches!(
            mining.events.try_recv().expect("final tip"),
            hns_mining::ChainEvent::TipCommitted { .. }
        ));
        assert!(matches!(
            mining.events.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
        assert_eq!(
            node.mining_snapshot()
                .expect("final mining snapshot")
                .generation,
            3
        );
    }
}
