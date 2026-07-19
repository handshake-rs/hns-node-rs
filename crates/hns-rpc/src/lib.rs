#![forbid(unsafe_code)]

use hns_chain::{BlockIndexRecord, ChainTip, HeaderRecord};
use hns_mempool::{MempoolEntry, MempoolInfo};
use hns_primitives::{hex_encode, Block, BlockHash, Coin, Height, NameState, Txid};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: Option<String>,
    pub method: String,
    #[serde(default)]
    pub params: Value,
    #[serde(default)]
    pub id: Option<Value>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcErrorObject>,
    #[serde(default)]
    pub id: Option<Value>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RpcErrorObject {
    pub code: i64,
    pub message: String,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum RpcMethod {
    GetBlockchainInfo,
    GetBestBlockHash,
    GetBlockCount,
    GetBlockHash,
    GetBlockHeader,
    GetBlock,
    GetRawTransaction,
    GetTxOut,
    GetMempoolInfo,
    GetRawMempool,
    SendRawTransaction,
    GetPeerInfo,
    GetNetworkInfo,
    GetConnectionCount,
    GetNameInfo,
    GetNameResource,
    GetNameByHash,
}

impl RpcMethod {
    pub fn from_hsd_name(name: &str) -> Option<Self> {
        match name {
            "getblockchaininfo" => Some(Self::GetBlockchainInfo),
            "getbestblockhash" => Some(Self::GetBestBlockHash),
            "getblockcount" => Some(Self::GetBlockCount),
            "getblockhash" => Some(Self::GetBlockHash),
            "getblockheader" => Some(Self::GetBlockHeader),
            "getblock" => Some(Self::GetBlock),
            "getrawtransaction" => Some(Self::GetRawTransaction),
            "gettxout" => Some(Self::GetTxOut),
            "getmempoolinfo" => Some(Self::GetMempoolInfo),
            "getrawmempool" => Some(Self::GetRawMempool),
            "sendrawtransaction" => Some(Self::SendRawTransaction),
            "getpeerinfo" => Some(Self::GetPeerInfo),
            "getnetworkinfo" => Some(Self::GetNetworkInfo),
            "getconnectioncount" => Some(Self::GetConnectionCount),
            "getnameinfo" => Some(Self::GetNameInfo),
            "getnameresource" => Some(Self::GetNameResource),
            "getnamebyhash" => Some(Self::GetNameByHash),
            _ => None,
        }
    }
}

pub trait RpcService {
    fn handle(&self, request: JsonRpcRequest) -> Result<JsonRpcResponse, RpcError>;
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct RpcSnapshot {
    pub network: String,
    pub chain_tip: Option<ChainTip>,
    pub headers: Vec<RpcHeaderEntry>,
    pub blocks: Vec<RpcBlockEntry>,
    pub transactions: Vec<RpcTransactionEntry>,
    pub coins: Vec<Coin>,
    pub names: Vec<NameState>,
    pub mempool_info: MempoolInfo,
    pub mempool_entries: Vec<MempoolEntry>,
    pub peer_count: usize,
}

impl RpcSnapshot {
    fn header_by_height(&self, height: Height) -> Option<&RpcHeaderEntry> {
        self.headers
            .iter()
            .find(|entry| entry.record.height == height)
    }

    fn header_by_hash_hex(&self, hash: &str) -> Option<&RpcHeaderEntry> {
        self.headers
            .iter()
            .find(|entry| entry.record.hash.to_hex().eq_ignore_ascii_case(hash))
    }

    fn block_by_hash_hex(&self, hash: &str) -> Option<&RpcBlockEntry> {
        self.blocks
            .iter()
            .find(|entry| entry.record.hash.to_hex().eq_ignore_ascii_case(hash))
    }

    fn transaction_by_txid_hex(&self, txid: &str) -> Option<&RpcTransactionEntry> {
        self.transactions
            .iter()
            .find(|entry| entry.txid.to_hex().eq_ignore_ascii_case(txid))
    }

    fn coin_by_outpoint_hex(&self, txid: &str, index: u32) -> Option<&Coin> {
        self.coins.iter().find(|coin| {
            coin.outpoint.txid.to_hex().eq_ignore_ascii_case(txid) && coin.outpoint.index == index
        })
    }

    fn name_by_hash_hex(&self, hash: &str) -> Option<&NameState> {
        self.names
            .iter()
            .find(|state| state.name_hash.to_hex().eq_ignore_ascii_case(hash))
    }

    fn name_by_name(&self, name: &str) -> Option<&NameState> {
        self.names
            .iter()
            .find(|state| state.name.as_deref() == Some(name))
    }

    fn confirmations(&self, height: Height) -> u32 {
        self.chain_tip
            .as_ref()
            .and_then(|tip| tip.height.checked_sub(height))
            .map(|depth| depth + 1)
            .unwrap_or(0)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RpcHeaderEntry {
    pub record: HeaderRecord,
}

impl RpcHeaderEntry {
    pub fn new(record: HeaderRecord) -> Self {
        Self { record }
    }

    pub fn raw_hex(&self) -> String {
        hex_encode(&self.record.header.encode())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RpcBlockEntry {
    pub record: BlockIndexRecord,
    pub raw: String,
    pub txids: Vec<Txid>,
}

impl RpcBlockEntry {
    pub fn from_block(record: BlockIndexRecord, block: &Block) -> Self {
        Self {
            record,
            raw: hex_encode(&block.encode()),
            txids: block
                .transactions
                .iter()
                .map(hns_primitives::Transaction::txid)
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct RpcTransactionEntry {
    pub txid: Txid,
    pub raw: String,
    pub block_hash: Option<BlockHash>,
    pub height: Option<Height>,
}

impl RpcTransactionEntry {
    pub fn from_transaction(
        transaction: &hns_primitives::Transaction,
        block_hash: Option<BlockHash>,
        height: Option<Height>,
    ) -> Self {
        Self {
            txid: transaction.txid(),
            raw: hex_encode(&transaction.encode()),
            block_hash,
            height,
        }
    }
}

#[derive(Clone, Debug, Default)]
pub struct BasicRpcService {
    snapshot: RpcSnapshot,
}

impl BasicRpcService {
    pub fn new(snapshot: RpcSnapshot) -> Self {
        Self { snapshot }
    }

    pub fn snapshot(&self) -> &RpcSnapshot {
        &self.snapshot
    }

    fn ok(&self, id: Option<Value>, result: Value) -> JsonRpcResponse {
        JsonRpcResponse {
            jsonrpc: "2.0".to_owned(),
            result: Some(result),
            error: None,
            id,
        }
    }

    fn err(&self, id: Option<Value>, code: i64, message: impl Into<String>) -> JsonRpcResponse {
        JsonRpcResponse {
            jsonrpc: "2.0".to_owned(),
            result: None,
            error: Some(RpcErrorObject {
                code,
                message: message.into(),
            }),
            id,
        }
    }
}

impl RpcService for BasicRpcService {
    fn handle(&self, request: JsonRpcRequest) -> Result<JsonRpcResponse, RpcError> {
        let method = RpcMethod::from_hsd_name(&request.method);
        let id = request.id;

        let Some(method) = method else {
            return Ok(self.err(id, -32601, "method not found"));
        };

        let response = match self.handle_method(method, &request.params) {
            Ok(result) => self.ok(id, result),
            Err(error) => self.err(id, error.code, error.message),
        };

        Ok(response)
    }
}

impl BasicRpcService {
    fn handle_method(&self, method: RpcMethod, params: &Value) -> Result<Value, RpcCallError> {
        let params = rpc_params(params)?;
        let tip = self.snapshot.chain_tip.as_ref();

        match method {
            RpcMethod::GetBlockchainInfo => Ok(json!({
                "chain": self.snapshot.network,
                "blocks": tip.map(|tip| tip.height).unwrap_or(0),
                "headers": tip.map(|tip| tip.height).unwrap_or(0),
                "bestblockhash": tip.map(|tip| tip.hash.to_hex()),
                "chainwork": tip.map(|tip| format!("{:x}", tip.chainwork)).unwrap_or_else(|| "0".to_owned()),
                "initialblockdownload": true,
            })),
            RpcMethod::GetBestBlockHash => Ok(tip
                .map(|tip| json!(tip.hash.to_hex()))
                .unwrap_or(Value::Null)),
            RpcMethod::GetBlockCount => Ok(json!(tip.map(|tip| tip.height).unwrap_or(0))),
            RpcMethod::GetBlockHash => self.get_block_hash(params),
            RpcMethod::GetBlockHeader => self.get_block_header(params),
            RpcMethod::GetBlock => self.get_block(params),
            RpcMethod::GetRawTransaction => self.get_raw_transaction(params),
            RpcMethod::GetTxOut => self.get_tx_out(params),
            RpcMethod::GetMempoolInfo => Ok(json!({
                "size": self.snapshot.mempool_info.transaction_count,
                "bytes": self.snapshot.mempool_info.bytes,
                "totalfee": self.snapshot.mempool_info.total_fee,
            })),
            RpcMethod::GetRawMempool => Ok(json!(self
                .snapshot
                .mempool_entries
                .iter()
                .map(|entry| entry.txid.to_hex())
                .collect::<Vec<_>>())),
            RpcMethod::SendRawTransaction => Err(RpcCallError::new(
                -32601,
                "sendrawtransaction requires a mutable mempool service",
            )),
            RpcMethod::GetPeerInfo => Ok(json!([])),
            RpcMethod::GetNetworkInfo => Ok(json!({
                "version": 0,
                "subversion": "/hsrd:0.1.0/",
                "networkactive": true,
                "connections": self.snapshot.peer_count,
            })),
            RpcMethod::GetConnectionCount => Ok(json!(self.snapshot.peer_count)),
            RpcMethod::GetNameInfo => self.get_name_info(params),
            RpcMethod::GetNameResource => self.get_name_resource(params),
            RpcMethod::GetNameByHash => self.get_name_by_hash(params),
        }
    }

    fn get_block_hash(&self, params: &[Value]) -> Result<Value, RpcCallError> {
        let height = required_height(params, 0, "height")?;
        let entry = self
            .snapshot
            .header_by_height(height)
            .ok_or_else(|| RpcCallError::new(-8, "block height out of range"))?;
        Ok(json!(entry.record.hash.to_hex()))
    }

    fn get_block_header(&self, params: &[Value]) -> Result<Value, RpcCallError> {
        let hash = required_string(params, 0, "hash")?;
        let verbose = optional_bool(params, 1, true)?;
        let entry = self
            .snapshot
            .header_by_hash_hex(&hash)
            .ok_or_else(|| RpcCallError::new(-5, "block header not found"))?;

        if !verbose {
            return Ok(json!(entry.raw_hex()));
        }

        let header = &entry.record.header;
        Ok(json!({
            "hash": entry.record.hash.to_hex(),
            "confirmations": self.snapshot.confirmations(entry.record.height),
            "height": entry.record.height,
            "version": header.version,
            "time": header.time,
            "bits": format!("{:08x}", header.bits),
            "merkleroot": hex_encode(&header.merkle_root),
            "witnessroot": hex_encode(&header.witness_root),
            "treeroot": hex_encode(&header.tree_root),
            "previousblockhash": header.prev_block.to_hex(),
            "chainwork": format!("{:x}", entry.record.chainwork),
        }))
    }

    fn get_block(&self, params: &[Value]) -> Result<Value, RpcCallError> {
        let hash = required_string(params, 0, "hash")?;
        let verbose = optional_bool(params, 1, true)?;
        let entry = self
            .snapshot
            .block_by_hash_hex(&hash)
            .ok_or_else(|| RpcCallError::new(-5, "block not found"))?;

        if !verbose {
            return Ok(json!(entry.raw));
        }

        Ok(json!({
            "hash": entry.record.hash.to_hex(),
            "confirmations": self.snapshot.confirmations(entry.record.height),
            "height": entry.record.height,
            "size": entry.raw.len() / 2,
            "tx": entry.txids.iter().map(|txid| txid.to_hex()).collect::<Vec<_>>(),
            "previousblockhash": entry.record.prev_hash.to_hex(),
            "chainwork": format!("{:x}", entry.record.chainwork),
        }))
    }

    fn get_raw_transaction(&self, params: &[Value]) -> Result<Value, RpcCallError> {
        let txid = required_string(params, 0, "txid")?;
        let verbose = optional_bool(params, 1, false)?;
        let entry = self
            .snapshot
            .transaction_by_txid_hex(&txid)
            .ok_or_else(|| RpcCallError::new(-5, "transaction not found"))?;

        if !verbose {
            return Ok(json!(entry.raw));
        }

        Ok(json!({
            "txid": entry.txid.to_hex(),
            "hash": entry.txid.to_hex(),
            "hex": entry.raw,
            "blockhash": entry.block_hash.map(BlockHash::to_hex),
            "confirmations": entry.height.map(|height| self.snapshot.confirmations(height)).unwrap_or(0),
        }))
    }

    fn get_tx_out(&self, params: &[Value]) -> Result<Value, RpcCallError> {
        let txid = required_string(params, 0, "txid")?;
        let index = required_u32(params, 1, "index")?;
        let Some(coin) = self.snapshot.coin_by_outpoint_hex(&txid, index) else {
            return Ok(Value::Null);
        };

        Ok(json!({
            "bestblock": self.snapshot.chain_tip.as_ref().map(|tip| tip.hash.to_hex()),
            "confirmations": self.snapshot.confirmations(coin.height),
            "value": coin.value,
            "coinbase": coin.coinbase,
            "covenant": {
                "type": coin.covenant.kind.as_u8(),
                "items": coin.covenant.items.iter().map(|item| hex_encode(item)).collect::<Vec<_>>(),
            },
        }))
    }

    fn get_name_info(&self, params: &[Value]) -> Result<Value, RpcCallError> {
        let name = required_string(params, 0, "name")?;
        let state = self
            .snapshot
            .name_by_name(&name)
            .ok_or_else(|| RpcCallError::new(-5, "name not found"))?;
        Ok(name_state_json(state))
    }

    fn get_name_resource(&self, params: &[Value]) -> Result<Value, RpcCallError> {
        let name = required_string(params, 0, "name")?;

        if self.snapshot.name_by_name(&name).is_none() {
            return Err(RpcCallError::new(-5, "name not found"));
        }

        Ok(Value::Null)
    }

    fn get_name_by_hash(&self, params: &[Value]) -> Result<Value, RpcCallError> {
        let hash = required_string(params, 0, "hash")?;
        let state = self
            .snapshot
            .name_by_hash_hex(&hash)
            .ok_or_else(|| RpcCallError::new(-5, "name not found"))?;
        Ok(json!(&state.name))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RpcCallError {
    code: i64,
    message: String,
}

impl RpcCallError {
    fn new(code: i64, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}

fn rpc_params(params: &Value) -> Result<&[Value], RpcCallError> {
    match params {
        Value::Null => Ok(&[]),
        Value::Array(params) => Ok(params),
        _ => Err(RpcCallError::new(-32602, "params must be an array")),
    }
}

fn required_string(params: &[Value], index: usize, name: &str) -> Result<String, RpcCallError> {
    params
        .get(index)
        .and_then(Value::as_str)
        .map(ToOwned::to_owned)
        .ok_or_else(|| RpcCallError::new(-32602, format!("missing or invalid {name} parameter")))
}

fn required_height(params: &[Value], index: usize, name: &str) -> Result<Height, RpcCallError> {
    required_u32(params, index, name)
}

fn required_u32(params: &[Value], index: usize, name: &str) -> Result<u32, RpcCallError> {
    let value = params
        .get(index)
        .and_then(Value::as_u64)
        .ok_or_else(|| RpcCallError::new(-32602, format!("missing or invalid {name} parameter")))?;
    u32::try_from(value)
        .map_err(|_| RpcCallError::new(-32602, format!("{name} parameter exceeds u32")))
}

fn optional_bool(params: &[Value], index: usize, default: bool) -> Result<bool, RpcCallError> {
    match params.get(index) {
        Some(Value::Bool(value)) => Ok(*value),
        Some(_) => Err(RpcCallError::new(-32602, "boolean parameter expected")),
        None => Ok(default),
    }
}

fn name_state_json(state: &NameState) -> Value {
    json!({
        "nameHash": state.name_hash.to_hex(),
        "name": &state.name,
        "height": state.height,
        "state": format!("{:?}", state.state).to_lowercase(),
    })
}

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("rpc service is not implemented in the scaffold")]
    Unimplemented,
    #[error("invalid request: {0}")]
    InvalidRequest(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_chain::{BlockIndexRecord, BlockStatus, HeaderRecord};
    use hns_primitives::{
        Address, Block, BlockHash, Coin, Covenant, CovenantKind, Header, Input, NameHash,
        NameLifecycleState, Outpoint, Output, Transaction, Txid, Witness,
    };

    #[test]
    fn basic_rpc_reports_chain_and_mempool_snapshot() {
        let service = BasicRpcService::new(RpcSnapshot {
            network: "regtest".to_owned(),
            chain_tip: Some(ChainTip {
                hash: BlockHash::new([1; 32]),
                height: 7,
                chainwork: 9u64.into(),
            }),
            mempool_info: MempoolInfo {
                transaction_count: 2,
                bytes: 100,
                total_fee: 3,
            },
            mempool_entries: Vec::new(),
            peer_count: 4,
            ..RpcSnapshot::default()
        });

        let response = service
            .handle(JsonRpcRequest {
                jsonrpc: Some("2.0".to_owned()),
                method: "getblockchaininfo".to_owned(),
                params: Value::Null,
                id: Some(json!(1)),
            })
            .expect("rpc response");

        let result = response.result.expect("result");
        assert_eq!(result["chain"], "regtest");
        assert_eq!(result["blocks"], 7);
        assert_eq!(result["chainwork"], "9");
    }

    #[test]
    fn basic_rpc_rejects_unknown_method() {
        let service = BasicRpcService::default();
        let response = service
            .handle(JsonRpcRequest {
                jsonrpc: Some("2.0".to_owned()),
                method: "unknown".to_owned(),
                params: Value::Null,
                id: None,
            })
            .expect("rpc response");

        assert_eq!(response.error.expect("error").code, -32601);
    }

    fn covenant() -> Covenant {
        Covenant {
            kind: CovenantKind::None,
            items: Vec::new(),
        }
    }

    fn output(value: u64) -> Output {
        Output {
            value,
            address: Address::new(0, vec![2; 20]).expect("address"),
            covenant: covenant(),
        }
    }

    fn transaction() -> Transaction {
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
            outputs: vec![output(10)],
            locktime: 0,
        }
    }

    fn block() -> Block {
        Block {
            header: Header {
                nonce: 1,
                version: 1,
                ..Header::default()
            },
            transactions: vec![transaction()],
        }
    }

    fn rpc_snapshot_with_block() -> RpcSnapshot {
        let block = block();
        let hash = block.hash();
        let header_record = HeaderRecord {
            hash,
            height: 0,
            chainwork: 1u64.into(),
            header: block.header.clone(),
            status: BlockStatus {
                header_valid: true,
                ..BlockStatus::default()
            },
        };
        let block_record =
            BlockIndexRecord::from_block(&block, 0, 1u64.into()).expect("block record");
        let transaction = block.transactions[0].clone();
        let coin = Coin {
            outpoint: Outpoint {
                txid: transaction.txid(),
                index: 0,
            },
            value: transaction.outputs[0].value,
            height: 0,
            coinbase: true,
            covenant: transaction.outputs[0].covenant.clone(),
        };
        let name_hash = NameHash::new([7; 32]);

        RpcSnapshot {
            network: "regtest".to_owned(),
            chain_tip: Some(ChainTip {
                hash,
                height: 0,
                chainwork: 1u64.into(),
            }),
            headers: vec![RpcHeaderEntry::new(header_record)],
            blocks: vec![RpcBlockEntry::from_block(block_record, &block)],
            transactions: vec![RpcTransactionEntry::from_transaction(
                &transaction,
                Some(hash),
                Some(0),
            )],
            coins: vec![coin],
            names: vec![NameState {
                name_hash,
                name: Some("handshake".to_owned()),
                height: 0,
                state: NameLifecycleState::Registered,
            }],
            mempool_info: MempoolInfo::default(),
            mempool_entries: Vec::new(),
            peer_count: 0,
        }
    }

    #[test]
    fn basic_rpc_reads_header_and_block_snapshot_entries() {
        let service = BasicRpcService::new(rpc_snapshot_with_block());
        let hash = service
            .snapshot()
            .chain_tip
            .as_ref()
            .expect("tip")
            .hash
            .to_hex();

        let height_response = service
            .handle(JsonRpcRequest {
                jsonrpc: Some("2.0".to_owned()),
                method: "getblockhash".to_owned(),
                params: json!([0]),
                id: Some(json!(1)),
            })
            .expect("rpc response");
        assert_eq!(height_response.result.expect("hash"), json!(hash));

        let header_response = service
            .handle(JsonRpcRequest {
                jsonrpc: Some("2.0".to_owned()),
                method: "getblockheader".to_owned(),
                params: json!([hash, true]),
                id: Some(json!(2)),
            })
            .expect("rpc response");
        assert_eq!(header_response.result.expect("header")["height"], 0);
    }

    #[test]
    fn basic_rpc_reads_raw_transaction_and_utxo() {
        let service = BasicRpcService::new(rpc_snapshot_with_block());
        let txid = service.snapshot().transactions[0].txid.to_hex();

        let tx_response = service
            .handle(JsonRpcRequest {
                jsonrpc: Some("2.0".to_owned()),
                method: "getrawtransaction".to_owned(),
                params: json!([txid, true]),
                id: Some(json!(1)),
            })
            .expect("rpc response");
        assert_eq!(tx_response.result.expect("tx")["confirmations"], 1);

        let coin_response = service
            .handle(JsonRpcRequest {
                jsonrpc: Some("2.0".to_owned()),
                method: "gettxout".to_owned(),
                params: json!([service.snapshot().coins[0].outpoint.txid.to_hex(), 0]),
                id: Some(json!(2)),
            })
            .expect("rpc response");
        assert_eq!(coin_response.result.expect("coin")["value"], 10);
    }

    #[test]
    fn basic_rpc_reads_name_snapshot_entries() {
        let service = BasicRpcService::new(rpc_snapshot_with_block());
        let hash = service.snapshot().names[0].name_hash.to_hex();

        let by_hash = service
            .handle(JsonRpcRequest {
                jsonrpc: Some("2.0".to_owned()),
                method: "getnamebyhash".to_owned(),
                params: json!([hash]),
                id: Some(json!(1)),
            })
            .expect("rpc response");
        assert_eq!(by_hash.result.expect("name"), json!("handshake"));

        let info = service
            .handle(JsonRpcRequest {
                jsonrpc: Some("2.0".to_owned()),
                method: "getnameinfo".to_owned(),
                params: json!(["handshake"]),
                id: Some(json!(2)),
            })
            .expect("rpc response");
        assert_eq!(info.result.expect("info")["state"], "registered");
    }
}
