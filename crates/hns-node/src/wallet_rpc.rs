//! Versioned authenticated HTTP boundary for the noncustodial wallet backend.
//!
//! This module owns wire projection only. Consensus and optional wallet-index
//! authority remain in the canonical runtime and [`WalletBackend`].

use axum::{http::StatusCode, Json};
use hns_marketplace_protocol::{
    DenuoPublicationAcceptanceExpectation, DenuoPublicationMessageKind,
};
use hns_primitives::{
    hex_encode, Address, Coin, Covenant, NameHash, NameLifecycleState, NameState, Outpoint, Output,
    Transaction, Txid, MAX_TX_SIZE,
};
use hns_state::encode_name_state;
use hns_urkel::ProofKind;
use hns_wallet_index::{
    ContractId, ScriptId, SpendingTransaction, TrackedContractEvent, TrackedContractFunding,
    TrackedContractSpendKind, MAX_QUERY_ENTRIES,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;

use super::wallet_backend::{
    ActiveNameOwnerCoinEvidence, ActiveNameOwnerCoinSourceBinding, BlockHashEvidence,
    BroadcastResult, ConfirmedScriptsCursor, ConfirmedScriptsPage, FeeEstimate, FeeEstimateSource,
    IncomingTransferSourceBinding, IncomingTransfersCursor, IncomingTransfersPage,
    MempoolContractEvent, MempoolContractPage, MempoolScriptPage, NameAction, NameActionContext,
    NameActionContextV2, NameActionIneligibility, NameEvidence, NameOwnerTransaction,
    OutpointSpendingEvidence, TransactionEvidence, TransactionFeeQuote, TransactionPayload,
    TransactionStatus, WalletBackend, WalletBackendError, WalletChainSnapshot,
    WalletContractEventCursor, WalletContractEventPage, WalletContractFundingCursor,
    WalletContractFundingPage, WalletMempoolCursor, ACTIVE_NAME_OWNER_COIN_PROJECTION_VERSION,
    INCOMING_TRANSFER_PROJECTION_VERSION, MAX_FEE_ESTIMATE_TARGET_BLOCKS,
    MAX_NAME_ACTION_INELIGIBILITY_REASONS, MAX_WALLET_CONFIRMED_PAGE_ITEMS,
    MAX_WALLET_FEE_QUOTE_INPUTS, MAX_WALLET_INCOMING_TRANSFER_RETAINED_BLOCK_DECODES,
    MAX_WALLET_INCOMING_TRANSFER_SCRIPT_EXAMINATIONS, MAX_WALLET_MEMPOOL_SCAN,
    MAX_WALLET_OUTPOINT_SPEND_BATCH, MAX_WALLET_RESTORE_SCRIPTS, NAME_ACTION_CONTEXT_V2_VERSION,
    NAME_ACTION_CONTEXT_VERSION,
};

pub const WALLET_RPC_API_VERSION: u16 = 1;
const MAX_REQUEST_ID_BYTES: usize = 128;
const MAX_OPAQUE_CURSOR_BYTES: usize = 4_096;
const MAX_WALLET_RPC_PAGE_ITEMS: usize = 256;
const MAX_WALLET_RPC_MEMPOOL_SCAN: usize = 1_024;
const MAX_WALLET_RPC_OUTPOINTS: usize = 256;
const MAX_WALLET_RPC_RESULT_BYTES: usize = 8 * 1024 * 1024;
const MAX_WALLET_RPC_DENUO_PUBLICATION_BYTES: usize = 16 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletRpcRequest {
    api_version: u16,
    #[serde(default)]
    request_id: Option<String>,
    call: WalletRpcCall,
}

#[derive(Debug, Deserialize)]
#[serde(
    tag = "method",
    content = "params",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum WalletRpcCall {
    Capabilities,
    ChainTip,
    ChainSnapshot,
    BlockHash {
        height: u32,
        expected_chain_epoch: u64,
    },
    ConfirmedScriptsPage {
        script_ids: Vec<String>,
        #[serde(default)]
        cursor: Option<String>,
        limit: usize,
    },
    IncomingTransfersPage {
        script_ids: Vec<String>,
        expected_chain_epoch: u64,
        #[serde(default)]
        cursor: Option<String>,
        limit: usize,
    },
    MempoolScriptsPage {
        script_ids: Vec<String>,
        expected_chain_epoch: u64,
        #[serde(default)]
        cursor: Option<String>,
        scan_limit: usize,
    },
    RawTransaction {
        txid: String,
        expected_chain_epoch: u64,
        #[serde(default)]
        expected_mempool: Option<WireExpectedMempool>,
    },
    TransactionEvidence {
        txid: String,
        expected_chain_epoch: u64,
        #[serde(default)]
        expected_mempool: Option<WireExpectedMempool>,
    },
    SpendingTransaction {
        txid: String,
        output_index: u32,
        expected_chain_epoch: u64,
    },
    SpendingTransactions {
        outpoints: Vec<WireOutpointParam>,
        expected_chain_epoch: u64,
    },
    NameEvidence {
        name_hash: String,
        expected_chain_epoch: u64,
    },
    ActiveNameOwnerCoin {
        name_hash: String,
        expected_chain_epoch: u64,
    },
    NameActionContext {
        action: NameAction,
        name_hash: String,
        expected_chain_epoch: u64,
        expected_mempool: WireExpectedMempool,
    },
    NameActionContextV2 {
        action: NameAction,
        name_hash: String,
        expected_chain_epoch: u64,
        expected_mempool: WireExpectedMempool,
    },
    BroadcastTransaction {
        transaction_hex: String,
    },
    EstimateFeeRate {
        target_blocks: u32,
    },
    QuoteTransactionFee {
        transaction_hex: String,
        target_blocks: u32,
        expected_chain_epoch: u64,
        expected_mempool: WireExpectedMempool,
    },
    DenuoNameMarketPublish {
        envelope_hex: String,
        handoff: WireDenuoPublicationHandoff,
    },
    DenuoNameMarketEvents {
        #[serde(default)]
        expected_instance_nonce: Option<String>,
        after_revision: u64,
        limit: usize,
    },
    DenuoNameMarketSnapshot {
        #[serde(default)]
        expected_revision: Option<u64>,
        offset: usize,
        limit: usize,
    },
    TrackedContractKnown {
        contract_id: String,
    },
    TrackedContractFundings {
        contract_id: String,
        expected_chain_epoch: u64,
        #[serde(default)]
        cursor: Option<String>,
        limit: usize,
    },
    TrackedContractEvents {
        contract_id: String,
        expected_chain_epoch: u64,
        #[serde(default)]
        cursor: Option<String>,
        limit: usize,
    },
    MempoolTrackedContract {
        contract_id: String,
        expected_chain_epoch: u64,
        #[serde(default)]
        cursor: Option<String>,
        scan_limit: usize,
    },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireDenuoPublicationHandoff {
    network_magic: u32,
    network_genesis: String,
    attempt_id: String,
    record_sequence: u64,
    prepared_at_unix: u64,
    envelope_id: String,
    envelope_digest: String,
    content_id: String,
    message_kind: String,
    request_id: u64,
}

fn decode_denuo_handoff(
    wire: WireDenuoPublicationHandoff,
) -> Result<DenuoPublicationAcceptanceExpectation, DispatchError> {
    let message_kind = match wire.message_kind.as_str() {
        "offer" => DenuoPublicationMessageKind::Offer,
        "cancellation" => DenuoPublicationMessageKind::Cancellation,
        _ => {
            return Err(DispatchError::Invalid(
                "Denuo publication handoff kind is invalid",
            ));
        }
    };
    Ok(DenuoPublicationAcceptanceExpectation {
        network_magic: wire.network_magic,
        network_genesis: decode_hex_32(&wire.network_genesis, "Denuo network genesis")?,
        attempt_id: decode_hex_32(&wire.attempt_id, "Denuo handoff attempt ID")?,
        record_sequence: wire.record_sequence,
        prepared_at_unix: wire.prepared_at_unix,
        envelope_id: decode_hex_32(&wire.envelope_id, "Denuo envelope ID")?,
        envelope_digest: decode_hex_32(&wire.envelope_digest, "Denuo envelope digest")?,
        content_id: decode_hex_32(&wire.content_id, "Denuo content ID")?,
        message_kind,
        request_id: wire.request_id,
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireOutpointParam {
    txid: String,
    output_index: u32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireExpectedMempool {
    instance_nonce: String,
    generation: u64,
}

struct ExpectedMempoolBinding {
    instance_nonce: [u8; 32],
    generation: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct WalletRpcResponse {
    api_version: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<WalletRpcError>,
}

#[derive(Debug, Serialize)]
struct WalletRpcError {
    code: &'static str,
    message: String,
    retryable: bool,
}

impl WalletRpcResponse {
    fn success(request_id: Option<String>, result: Value) -> Self {
        Self {
            api_version: WALLET_RPC_API_VERSION,
            request_id,
            result: Some(result),
            error: None,
        }
    }

    fn failure(request_id: Option<String>, error: WalletRpcError) -> Self {
        Self {
            api_version: WALLET_RPC_API_VERSION,
            request_id,
            result: None,
            error: Some(error),
        }
    }
}

#[derive(Debug)]
enum DispatchError {
    Invalid(&'static str),
    ResponseLimit,
    Backend(WalletBackendError),
    Internal,
}

impl From<WalletBackendError> for DispatchError {
    fn from(error: WalletBackendError) -> Self {
        Self::Backend(error)
    }
}

/// Dispatch one request only after the caller has established that the HTTP
/// listener is protected by its exact authorization-header middleware.
pub(crate) async fn dispatch_wallet_rpc(
    backend: Option<&WalletBackend>,
    authenticated_boundary: bool,
    wallet_profile_enabled: bool,
    body: &[u8],
) -> (StatusCode, Json<WalletRpcResponse>) {
    if !authenticated_boundary {
        return wallet_rpc_failure(
            None,
            StatusCode::SERVICE_UNAVAILABLE,
            "authentication_required",
            "wallet RPC is unavailable unless the listener has configured authentication",
            false,
        );
    }
    if !wallet_profile_enabled {
        return wallet_rpc_failure(
            None,
            StatusCode::SERVICE_UNAVAILABLE,
            "wallet_profile_required",
            "wallet RPC requires the durable wallet index profile",
            false,
        );
    }
    let Some(backend) = backend else {
        return wallet_rpc_failure(
            None,
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime_unavailable",
            "wallet RPC requires the canonical native-sync runtime",
            true,
        );
    };
    let request = match serde_json::from_slice::<WalletRpcRequest>(body) {
        Ok(request) => request,
        Err(_) => {
            return wallet_rpc_failure(
                None,
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "wallet RPC request is malformed",
                false,
            )
        }
    };
    let request_id = request.request_id;
    if request_id
        .as_ref()
        .is_some_and(|value| value.len() > MAX_REQUEST_ID_BYTES)
    {
        return wallet_rpc_failure(
            None,
            StatusCode::BAD_REQUEST,
            "invalid_request_id",
            "wallet RPC request_id exceeds 128 bytes",
            false,
        );
    }
    if request.api_version != WALLET_RPC_API_VERSION {
        return wallet_rpc_failure(
            request_id,
            StatusCode::BAD_REQUEST,
            "unsupported_api_version",
            "wallet RPC supports only api_version 1",
            false,
        );
    }

    match dispatch_call(backend, request.call).await {
        Ok(result) => (
            StatusCode::OK,
            Json(WalletRpcResponse::success(request_id, result)),
        ),
        Err(error) => map_dispatch_error(request_id, error),
    }
}

async fn dispatch_call(
    backend: &WalletBackend,
    call: WalletRpcCall,
) -> Result<Value, DispatchError> {
    let result = match call {
        WalletRpcCall::Capabilities => {
            let mut capabilities = serde_json::json!({
            "api_version": WALLET_RPC_API_VERSION,
            "authenticated_listener_required": true,
            "maximum_restore_scripts": MAX_WALLET_RESTORE_SCRIPTS,
            "typed_backend_maximum_confirmed_page_items": MAX_WALLET_CONFIRMED_PAGE_ITEMS,
            "typed_backend_maximum_mempool_scan": MAX_WALLET_MEMPOOL_SCAN,
            "typed_backend_maximum_index_page_items": MAX_QUERY_ENTRIES,
            "maximum_wire_page_items": MAX_WALLET_RPC_PAGE_ITEMS,
            "maximum_wire_mempool_scan": MAX_WALLET_RPC_MEMPOOL_SCAN,
            "maximum_wire_outpoint_spend_batch": MAX_WALLET_RPC_OUTPOINTS,
            "typed_backend_maximum_outpoint_spend_batch": MAX_WALLET_OUTPOINT_SPEND_BATCH,
            "maximum_wire_result_bytes": MAX_WALLET_RPC_RESULT_BYTES,
            "maximum_opaque_cursor_bytes": MAX_OPAQUE_CURSOR_BYTES,
            "maximum_fee_target_blocks": MAX_FEE_ESTIMATE_TARGET_BLOCKS,
            "maximum_fee_quote_inputs": MAX_WALLET_FEE_QUOTE_INPUTS,
            "consensus_maximum_transaction_bytes": MAX_TX_SIZE,
            "transaction_request_also_bound_by_hex_envelope_and_listener_body_limit": true,
            "confirmed_cursor_binding": "chain_epoch_and_script_set",
            "initial_chain_binding": "script_free_chain_snapshot_epoch_and_exact_tip",
            "post_binding_reads_require_expected_chain_epoch": true,
            "mempool_cursor_binding": "chain_epoch_process_instance_nonce_generation_and_query",
            "mempool_page_binding": "chain_epoch_tip_instance_nonce_and_generation",
            "transaction_evidence_binding": "mandatory_chain_epoch_optional_exact_mempool_instance_and_generation",
            "transaction_fee_quote_binding": "mandatory_chain_epoch_and_exact_mempool_instance_and_generation",
            "transaction_fee_quote_units": "atomic_units_per_1000_hsd_policy_virtual_bytes",
            "transaction_fee_quote_caller_evidence": "raw_transaction_only_node_resolves_input_coins_weight_sigops_policy_size_and_rate",
            "transaction_fee_quote_artifact": "exact_supplied_serialized_bytes_requote_final_signed_transaction_before_broadcast",
            "transaction_fee_quote_payment_evidence": "node_resolved_actual_fee_minimum_shortfall_and_meets_minimum_boolean",
            "outpoint_spend_evidence": "ordered_single_immutable_chain_snapshot",
            "transaction_position": "exact_when_block_payload_retained_null_when_pruned",
            "name_views": ["current_state", "proof_state", "current_owner", "proof_owner"],
            "name_state_encoding": "canonical_current_state_hex_and_proof_state_hex",
            "name_action_context_version": NAME_ACTION_CONTEXT_VERSION,
            "name_action_context_actions": ["transfer", "finalize"],
            "name_action_context_binding": "mandatory_chain_epoch_and_exact_mempool_instance_and_generation",
            "name_action_context_maximum_ineligibility_reasons": MAX_NAME_ACTION_INELIGIBILITY_REASONS,
            "name_action_context_ineligibility_reasons": [
                "name_not_registered",
                "name_expired_at_candidate",
                "lifecycle_not_closed",
                "transfer_already_pending",
                "transfer_not_pending",
                "transfer_not_mature",
                "owner_covenant_invalid_for_action",
                "renewal_commitment_invalid",
                "owner_spent_in_mempool"
            ],
            "tracked_contract_descriptor_registration": "unavailable_unpublished_protocol_boundary",
            "tracked_contract_preimage_transport": "opaque_unavailable",
                "tracked_contract_evidence": "node_local_profile_only_not_protocol_authority"
            });
            let object = capabilities
                .as_object_mut()
                .ok_or(DispatchError::Internal)?;
            for (key, value) in [
                (
                    "active_name_owner_coin_projection_version",
                    Value::from(ACTIVE_NAME_OWNER_COIN_PROJECTION_VERSION),
                ),
                (
                    "active_name_owner_coin_source_binding",
                    Value::from("trusted_node_active_utxo_projection"),
                ),
                (
                    "active_name_owner_coin_binding",
                    Value::from("mandatory_chain_epoch_and_exact_tip"),
                ),
                (
                    "active_name_owner_coin_transaction_position",
                    Value::from("always_null_no_raw_block_read"),
                ),
                (
                    "active_name_owner_coin_authority",
                    Value::from(
                        "discovery_and_current_active_utxo_evidence_only_not_cryptographic_proof_or_signing_authority",
                    ),
                ),
                (
                    "name_action_context_v2_version",
                    Value::from(NAME_ACTION_CONTEXT_V2_VERSION),
                ),
                (
                    "name_action_context_v2_binding",
                    Value::from(
                        "mandatory_chain_epoch_and_exact_mempool_instance_and_generation",
                    ),
                ),
                (
                    "name_action_context_v2_owner_projection_version",
                    Value::from(ACTIVE_NAME_OWNER_COIN_PROJECTION_VERSION),
                ),
                (
                    "name_action_context_v2_owner_source_binding",
                    Value::from("trusted_node_active_utxo_projection"),
                ),
                (
                    "name_action_context_v2_owner_transaction",
                    Value::from("not_read_or_returned"),
                ),
                (
                    "name_action_context_v2_transaction_position",
                    Value::from("always_null_no_raw_block_read"),
                ),
                (
                    "name_action_context_v2_authority",
                    Value::from(
                        "public_current_state_and_active_utxo_evidence_only_not_wallet_ownership_cryptographic_proof_or_signing_authority",
                    ),
                ),
                (
                    "incoming_transfer_projection_version",
                    Value::from(INCOMING_TRANSFER_PROJECTION_VERSION),
                ),
                (
                    "incoming_transfer_source_bindings",
                    Value::Array(vec![
                        Value::from("retained_body_verified"),
                        Value::from("pruned_trusted_node_projection"),
                    ]),
                ),
                (
                    "incoming_transfer_cursor_binding",
                    Value::from("chain_epoch_exact_tip_and_complete_sorted_unique_script_set"),
                ),
                (
                    "incoming_transfer_cursor_authentication",
                    Value::from("none_unkeyed_query_binding_only"),
                ),
                (
                    "incoming_transfer_authority",
                    Value::from(
                        "candidate_discovery_only_not_balance_name_authority_or_cryptographic_proof",
                    ),
                ),
                (
                    "incoming_transfer_snapshot_semantics",
                    Value::from(
                        "same_snapshot_per_call_retention_label_may_change_across_pages_without_epoch_change",
                    ),
                ),
                (
                    "maximum_incoming_transfer_script_examinations",
                    Value::from(MAX_WALLET_INCOMING_TRANSFER_SCRIPT_EXAMINATIONS),
                ),
                (
                    "maximum_incoming_transfer_retained_block_decodes",
                    Value::from(MAX_WALLET_INCOMING_TRANSFER_RETAINED_BLOCK_DECODES),
                ),
                (
                    "denuo_name_market_registry",
                    Value::from("denuo-v2"),
                ),
                (
                    "denuo_name_market_transport",
                    Value::from("typed_local_publish_and_monotonic_event_cursor"),
                ),
                (
                    "denuo_name_market_event_authority",
                    Value::from(
                        "untrusted_discovery_input_requires_wallet_signature_current_lock_and_chain_revalidation",
                    ),
                ),
                (
                    "maximum_denuo_name_market_event_page",
                    Value::from(super::MAX_DENUO_NAME_MARKET_EVENT_PAGE),
                ),
            ] {
                object.insert(key.to_owned(), value);
            }
            capabilities
        }
        WalletRpcCall::ChainTip => value(&wire_tip(backend.get_chain_tip().await?))?,
        WalletRpcCall::ChainSnapshot => value(&WireChainSnapshot::from(
            backend.get_chain_snapshot().await?,
        ))?,
        WalletRpcCall::BlockHash {
            height,
            expected_chain_epoch,
        } => {
            let evidence = backend.get_block_hash_evidence(height).await?;
            require_chain_epoch(expected_chain_epoch, evidence.chain_epoch)?;
            value(&WireBlockHashEvidence::from(evidence))?
        }
        WalletRpcCall::ConfirmedScriptsPage {
            script_ids,
            cursor,
            limit,
        } => {
            validate_wire_page_limit(limit)?;
            let scripts = decode_script_ids(script_ids)?;
            let cursor = decode_cursor::<ConfirmedScriptsCursor>(cursor)?;
            let page = backend
                .get_confirmed_scripts_page(scripts, cursor, limit)
                .await?;
            value(&wire_confirmed_page(page)?)?
        }
        WalletRpcCall::IncomingTransfersPage {
            script_ids,
            expected_chain_epoch,
            cursor,
            limit,
        } => {
            validate_wire_page_limit(limit)?;
            let scripts = decode_script_ids(script_ids)?;
            let cursor = decode_cursor::<IncomingTransfersCursor>(cursor)?;
            let page = backend
                .get_incoming_transfers_page(scripts, expected_chain_epoch, cursor, limit)
                .await?;
            value(&wire_incoming_transfers_page(page)?)?
        }
        WalletRpcCall::MempoolScriptsPage {
            script_ids,
            expected_chain_epoch,
            cursor,
            scan_limit,
        } => {
            validate_wire_mempool_scan(scan_limit)?;
            let scripts = decode_script_ids(script_ids)?;
            let cursor = decode_cursor::<WalletMempoolCursor>(cursor)?;
            let page = backend
                .get_mempool_scripts_activity(scripts, cursor, scan_limit)
                .await?;
            require_chain_epoch(expected_chain_epoch, page.chain_epoch)?;
            value(&wire_mempool_script_page(page)?)?
        }
        WalletRpcCall::RawTransaction {
            txid,
            expected_chain_epoch,
            expected_mempool,
        } => {
            let txid = Txid::new(decode_hex_32(&txid, "transaction ID")?);
            let expected_mempool = decode_expected_mempool(expected_mempool)?;
            let evidence = backend.get_transaction_evidence(txid).await?;
            require_transaction_evidence_binding(
                &evidence,
                expected_chain_epoch,
                expected_mempool.as_ref(),
            )?;
            value(&wire_raw_transaction_evidence(evidence)?)?
        }
        WalletRpcCall::TransactionEvidence {
            txid,
            expected_chain_epoch,
            expected_mempool,
        } => {
            let txid = Txid::new(decode_hex_32(&txid, "transaction ID")?);
            let expected_mempool = decode_expected_mempool(expected_mempool)?;
            let evidence = backend.get_transaction_evidence(txid).await?;
            require_transaction_evidence_binding(
                &evidence,
                expected_chain_epoch,
                expected_mempool.as_ref(),
            )?;
            value(&wire_transaction_evidence(evidence))?
        }
        WalletRpcCall::SpendingTransaction {
            txid,
            output_index,
            expected_chain_epoch,
        } => {
            let outpoint = Outpoint {
                txid: Txid::new(decode_hex_32(&txid, "transaction ID")?),
                index: output_index,
            };
            let evidence = backend
                .get_outpoint_spending_evidence(vec![outpoint])
                .await?;
            require_chain_epoch(expected_chain_epoch, evidence.chain_epoch)?;
            value(&wire_outpoint_spending_evidence(evidence))?
        }
        WalletRpcCall::SpendingTransactions {
            outpoints,
            expected_chain_epoch,
        } => {
            if outpoints.is_empty() || outpoints.len() > MAX_WALLET_RPC_OUTPOINTS {
                return Err(DispatchError::Invalid(
                    "outpoints must contain 1..=256 entries",
                ));
            }
            let outpoints = outpoints
                .into_iter()
                .map(|outpoint| {
                    Ok(Outpoint {
                        txid: Txid::new(decode_hex_32(&outpoint.txid, "transaction ID")?),
                        index: outpoint.output_index,
                    })
                })
                .collect::<Result<Vec<_>, DispatchError>>()?;
            let evidence = backend.get_outpoint_spending_evidence(outpoints).await?;
            require_chain_epoch(expected_chain_epoch, evidence.chain_epoch)?;
            value(&wire_outpoint_spending_evidence(evidence))?
        }
        WalletRpcCall::NameEvidence {
            name_hash,
            expected_chain_epoch,
        } => {
            let name_hash = NameHash::new(decode_hex_32(&name_hash, "name hash")?);
            let evidence = backend.get_name_evidence(name_hash).await?;
            require_chain_epoch(expected_chain_epoch, evidence.chain_epoch)?;
            value(&wire_name_evidence(evidence)?)?
        }
        WalletRpcCall::ActiveNameOwnerCoin {
            name_hash,
            expected_chain_epoch,
        } => {
            let name_hash = NameHash::new(decode_hex_32(&name_hash, "name hash")?);
            let evidence = backend
                .get_active_name_owner_coin(name_hash, expected_chain_epoch)
                .await?;
            value(&wire_active_name_owner_coin(evidence))?
        }
        WalletRpcCall::NameActionContext {
            action,
            name_hash,
            expected_chain_epoch,
            expected_mempool,
        } => {
            let name_hash = NameHash::new(decode_hex_32(&name_hash, "name hash")?);
            let expected_mempool = decode_expected_mempool(Some(expected_mempool))?.ok_or(
                DispatchError::Invalid("expected mempool binding is required"),
            )?;
            let context = backend
                .get_name_action_context(
                    action,
                    name_hash,
                    expected_chain_epoch,
                    expected_mempool.instance_nonce,
                    expected_mempool.generation,
                )
                .await?;
            value(&wire_name_action_context(context)?)?
        }
        WalletRpcCall::NameActionContextV2 {
            action,
            name_hash,
            expected_chain_epoch,
            expected_mempool,
        } => {
            let name_hash = NameHash::new(decode_hex_32(&name_hash, "name hash")?);
            let expected_mempool = decode_expected_mempool(Some(expected_mempool))?.ok_or(
                DispatchError::Invalid("expected mempool binding is required"),
            )?;
            let context = backend
                .get_name_action_context_v2(
                    action,
                    name_hash,
                    expected_chain_epoch,
                    expected_mempool.instance_nonce,
                    expected_mempool.generation,
                )
                .await?;
            value(&wire_name_action_context_v2(context)?)?
        }
        WalletRpcCall::BroadcastTransaction { transaction_hex } => {
            let raw = decode_hex_bounded(&transaction_hex, MAX_TX_SIZE, "raw transaction")?;
            let transaction = Transaction::decode(&raw)
                .map_err(|_| DispatchError::Invalid("raw transaction is not canonical"))?;
            value(&WireBroadcastResult::from(
                &backend.broadcast_transaction(transaction).await?,
            ))?
        }
        WalletRpcCall::EstimateFeeRate { target_blocks } => value(&WireFeeEstimate::from(
            &backend.estimate_fee_rate(target_blocks).await?,
        ))?,
        WalletRpcCall::QuoteTransactionFee {
            transaction_hex,
            target_blocks,
            expected_chain_epoch,
            expected_mempool,
        } => {
            let raw = decode_hex_bounded(&transaction_hex, MAX_TX_SIZE, "raw transaction")?;
            let transaction = Transaction::decode(&raw)
                .map_err(|_| DispatchError::Invalid("raw transaction is not canonical"))?;
            let expected_mempool = decode_expected_mempool(Some(expected_mempool))?.ok_or(
                DispatchError::Invalid("expected mempool binding is required"),
            )?;
            value(&WireTransactionFeeQuote::from(
                &backend
                    .quote_transaction_fee(
                        transaction,
                        target_blocks,
                        expected_chain_epoch,
                        expected_mempool.instance_nonce,
                        expected_mempool.generation,
                    )
                    .await?,
            ))?
        }
        WalletRpcCall::DenuoNameMarketPublish {
            envelope_hex,
            handoff,
        } => {
            let envelope = decode_hex_bounded(
                &envelope_hex,
                MAX_WALLET_RPC_DENUO_PUBLICATION_BYTES,
                "Denuo name-market publication",
            )?;
            let handoff = decode_denuo_handoff(handoff)?;
            let now = super::current_unix_time().map_err(|_| DispatchError::Internal)?;
            let (admission, propagation, receipt) = backend
                .publish_denuo_name_market(&envelope, handoff, now)
                .await?;
            serde_json::json!({
                "revision": admission.revision,
                "kind": admission.kind.as_str(),
                "content_hash": hex_encode(&admission.content_hash),
                "inserted": admission.inserted,
                "accepted_at_unix": now,
                "acceptance_receipt_hex": hex_encode(&receipt),
                "propagation": {
                    "attempted": propagation.attempted,
                    "written": propagation.queued,
                    "failed": propagation.failed.len(),
                }
            })
        }
        WalletRpcCall::DenuoNameMarketEvents {
            expected_instance_nonce,
            after_revision,
            limit,
        } => {
            if limit == 0 || limit > super::MAX_DENUO_NAME_MARKET_EVENT_PAGE {
                return Err(DispatchError::Invalid(
                    "Denuo name-market event limit must be within 1..=256",
                ));
            }
            let expected_instance_nonce = expected_instance_nonce
                .map(|nonce| decode_hex_32(&nonce, "Denuo instance nonce"))
                .transpose()?;
            if expected_instance_nonce == Some([0; 32]) {
                return Err(DispatchError::Invalid("Denuo instance nonce is invalid"));
            }
            let page = backend.get_denuo_name_market_events(
                expected_instance_nonce,
                after_revision,
                limit,
            )?;
            serde_json::json!({
                "instance_nonce": hex_encode(&page.instance_nonce),
                "cursor_reset": page.cursor_reset,
                "oldest_revision": page.oldest_revision,
                "head_revision": page.head_revision,
                "events": page.events.into_iter().map(|event| serde_json::json!({
                    "revision": event.revision,
                    "received_at_unix": event.received_at_unix,
                    "kind": event.kind.as_str(),
                    "content_hash": hex_encode(&event.content_hash),
                    "envelope_hex": hex_encode(&event.envelope_bytes),
                })).collect::<Vec<_>>()
            })
        }
        WalletRpcCall::DenuoNameMarketSnapshot {
            expected_revision,
            offset,
            limit,
        } => {
            if limit == 0 || limit > super::MAX_DENUO_NAME_MARKET_SNAPSHOT_PAGE {
                return Err(DispatchError::Invalid(
                    "Denuo name-market snapshot limit must be within 1..=256",
                ));
            }
            let page = backend.get_denuo_name_market_snapshot(expected_revision, offset, limit)?;
            serde_json::json!({
                "instance_nonce": hex_encode(&page.instance_nonce),
                "snapshot_revision": page.snapshot_revision,
                "next_offset": page.next_offset,
                "records": page.records.into_iter().map(|record| serde_json::json!({
                    "kind": record.kind.as_str(),
                    "content_hash": hex_encode(&record.content_hash),
                    "envelope_hex": hex_encode(&record.envelope_bytes),
                })).collect::<Vec<_>>()
            })
        }
        WalletRpcCall::TrackedContractKnown { contract_id } => {
            let id = ContractId::from_bytes(decode_hex_32(&contract_id, "contract ID")?);
            serde_json::json!({
                "contract_id": hex_encode(id.as_bytes()),
                "known": backend.get_tracked_contract(id).await?.is_some(),
                "descriptor": "opaque_unpublished_protocol_boundary"
            })
        }
        WalletRpcCall::TrackedContractFundings {
            contract_id,
            expected_chain_epoch,
            cursor,
            limit,
        } => {
            validate_wire_page_limit(limit)?;
            let id = ContractId::from_bytes(decode_hex_32(&contract_id, "contract ID")?);
            let cursor = decode_cursor::<WalletContractFundingCursor>(cursor)?;
            let page = backend
                .get_tracked_contract_fundings(id, cursor, limit)
                .await?;
            require_chain_epoch(expected_chain_epoch, page.chain_epoch)?;
            value(&wire_contract_funding_page(page)?)?
        }
        WalletRpcCall::TrackedContractEvents {
            contract_id,
            expected_chain_epoch,
            cursor,
            limit,
        } => {
            validate_wire_page_limit(limit)?;
            let id = ContractId::from_bytes(decode_hex_32(&contract_id, "contract ID")?);
            let cursor = decode_cursor::<WalletContractEventCursor>(cursor)?;
            let page = backend
                .get_tracked_contract_events(id, cursor, limit)
                .await?;
            require_chain_epoch(expected_chain_epoch, page.chain_epoch)?;
            value(&wire_contract_event_page(page)?)?
        }
        WalletRpcCall::MempoolTrackedContract {
            contract_id,
            expected_chain_epoch,
            cursor,
            scan_limit,
        } => {
            validate_wire_mempool_scan(scan_limit)?;
            let id = ContractId::from_bytes(decode_hex_32(&contract_id, "contract ID")?);
            let cursor = decode_cursor::<WalletMempoolCursor>(cursor)?;
            let page = backend
                .get_mempool_tracked_contract_activity(id, cursor, scan_limit)
                .await?;
            require_chain_epoch(expected_chain_epoch, page.chain_epoch)?;
            value(&wire_mempool_contract_page(page)?)?
        }
    };
    Ok(result)
}

fn map_dispatch_error(
    request_id: Option<String>,
    error: DispatchError,
) -> (StatusCode, Json<WalletRpcResponse>) {
    match error {
        DispatchError::Invalid(message) => wallet_rpc_failure(
            request_id,
            StatusCode::BAD_REQUEST,
            "invalid_params",
            message,
            false,
        ),
        DispatchError::ResponseLimit => wallet_rpc_failure(
            request_id,
            StatusCode::PAYLOAD_TOO_LARGE,
            "response_projection_limit",
            "wallet RPC result exceeds the 8 MiB wire budget; use a smaller page where applicable",
            true,
        ),
        DispatchError::Internal => wallet_rpc_failure(
            request_id,
            StatusCode::INTERNAL_SERVER_ERROR,
            "internal_projection_failure",
            "wallet RPC could not encode its bounded response",
            true,
        ),
        DispatchError::Backend(error) => map_backend_error(request_id, error),
    }
}

fn map_backend_error(
    request_id: Option<String>,
    error: WalletBackendError,
) -> (StatusCode, Json<WalletRpcResponse>) {
    match error {
        WalletBackendError::IndexDisabled(_) => wallet_rpc_failure(
            request_id,
            StatusCode::SERVICE_UNAVAILABLE,
            "index_unavailable",
            "the required optional wallet index is not enabled",
            false,
        ),
        WalletBackendError::PayloadPruned => wallet_rpc_failure(
            request_id,
            StatusCode::GONE,
            "payload_pruned",
            "the confirmed transaction payload has been pruned",
            false,
        ),
        WalletBackendError::UnknownContract => wallet_rpc_failure(
            request_id,
            StatusCode::NOT_FOUND,
            "unknown_contract",
            "the tracked-contract registration is unknown",
            false,
        ),
        WalletBackendError::InvalidContract => wallet_rpc_failure(
            request_id,
            StatusCode::CONFLICT,
            "invalid_contract",
            "the tracked-contract registration is invalid or conflicts",
            false,
        ),
        WalletBackendError::ContractCapacity
        | WalletBackendError::ContractRetirementCapacity
        | WalletBackendError::ContractRetirementHistoryCapacity => wallet_rpc_failure(
            request_id,
            StatusCode::INSUFFICIENT_STORAGE,
            "contract_registry_full",
            "the active tracked-contract registry is full",
            false,
        ),
        WalletBackendError::ContractNotRetirable
        | WalletBackendError::ContractRollbackRequired
        | WalletBackendError::PermanentContractAbandonmentRequired => wallet_rpc_failure(
            request_id,
            StatusCode::CONFLICT,
            "contract_not_retirable",
            "the tracked-contract registration is not eligible for retirement",
            false,
        ),
        WalletBackendError::StaleMempoolGeneration { .. }
        | WalletBackendError::StaleMempoolInstance
        | WalletBackendError::StaleContractLifecycle { .. }
        | WalletBackendError::StaleContractRollbackBoundary
        | WalletBackendError::StaleChainEpoch { .. }
        | WalletBackendError::StaleCanonicalRead => wallet_rpc_failure(
            request_id,
            StatusCode::CONFLICT,
            "stale_snapshot",
            "the bound lifecycle, chain, or mempool generation changed; restart this reconciliation",
            true,
        ),
        WalletBackendError::InvalidMempoolCursor
        | WalletBackendError::InvalidConfirmedCursor
        | WalletBackendError::InvalidIncomingTransferCursor => {
            wallet_rpc_failure(
                request_id,
                StatusCode::BAD_REQUEST,
                "invalid_cursor",
                "the opaque continuation does not belong to this query",
                false,
            )
        }
        WalletBackendError::InvalidConfirmedPageLimit
        | WalletBackendError::InvalidIncomingTransferPageLimit
        | WalletBackendError::InvalidIndexPageLimit
        | WalletBackendError::InvalidMempoolScanLimit
        | WalletBackendError::InvalidOutpointBatch
        | WalletBackendError::InvalidScriptSet
        | WalletBackendError::InvalidFeeTarget => wallet_rpc_failure(
            request_id,
            StatusCode::BAD_REQUEST,
            "invalid_bounds",
            "the request violates a wallet RPC collection bound",
            false,
        ),
        WalletBackendError::MempoolResultLimit => wallet_rpc_failure(
            request_id,
            StatusCode::PAYLOAD_TOO_LARGE,
            "result_limit",
            "the bounded mempool result contains too many relevant items",
            true,
        ),
        WalletBackendError::InvalidFeeQuoteTransaction => wallet_rpc_failure(
            request_id,
            StatusCode::UNPROCESSABLE_ENTITY,
            "invalid_fee_quote_transaction",
            "the raw transaction is not eligible for a Handshake fee quote",
            false,
        ),
        WalletBackendError::FeeQuoteInputUnavailable => wallet_rpc_failure(
            request_id,
            StatusCode::CONFLICT,
            "fee_quote_input_unavailable",
            "an input coin is unavailable in the bound active chain and mempool snapshot",
            true,
        ),
        WalletBackendError::Rejected(reason) => wallet_rpc_failure(
            request_id,
            StatusCode::UNPROCESSABLE_ENTITY,
            "transaction_rejected",
            &bounded_message(&reason),
            false,
        ),
        WalletBackendError::Orphan(_) => wallet_rpc_failure(
            request_id,
            StatusCode::CONFLICT,
            "transaction_orphan",
            "the transaction has unresolved inputs and was not relayed as accepted",
            true,
        ),
        WalletBackendError::NameHasNoOwner => wallet_rpc_failure(
            request_id,
            StatusCode::NOT_FOUND,
            "name_has_no_owner",
            "the current name state has no owner",
            false,
        ),
        WalletBackendError::NameStateMissing => wallet_rpc_failure(
            request_id,
            StatusCode::NOT_FOUND,
            "name_state_missing",
            "the requested name has no current active-chain state",
            false,
        ),
        WalletBackendError::ChainUninitialized => wallet_rpc_failure(
            request_id,
            StatusCode::CONFLICT,
            "chain_uninitialized",
            "wallet name evidence requires an initialized active chain",
            true,
        ),
        WalletBackendError::OwnerOutputMissing => wallet_rpc_failure(
            request_id,
            StatusCode::INTERNAL_SERVER_ERROR,
            "owner_output_missing",
            "the indexed owner transaction does not contain its selected output",
            false,
        ),
        WalletBackendError::DenuoNameMarket(_) => wallet_rpc_failure(
            request_id,
            StatusCode::CONFLICT,
            "denuo_name_market_rejected",
            "the local Denuo V2 relay rejected the publication or event cursor",
            true,
        ),
        WalletBackendError::Corrupt(_) => wallet_rpc_failure(
            request_id,
            StatusCode::INTERNAL_SERVER_ERROR,
            "backend_inconsistent",
            "wallet index evidence is inconsistent with the active chain",
            false,
        ),
        WalletBackendError::Node(_) => wallet_rpc_failure(
            request_id,
            StatusCode::SERVICE_UNAVAILABLE,
            "backend_unavailable",
            "the canonical wallet backend is temporarily unavailable",
            true,
        ),
    }
}

fn wallet_rpc_failure(
    request_id: Option<String>,
    status: StatusCode,
    code: &'static str,
    message: &str,
    retryable: bool,
) -> (StatusCode, Json<WalletRpcResponse>) {
    (
        status,
        Json(WalletRpcResponse::failure(
            request_id,
            WalletRpcError {
                code,
                message: message.to_owned(),
                retryable,
            },
        )),
    )
}

fn bounded_message(message: &str) -> String {
    message.chars().take(256).collect()
}

fn value<T: Serialize>(value: &T) -> Result<Value, DispatchError> {
    let encoded = serde_json::to_vec(value).map_err(|_| DispatchError::Internal)?;
    if encoded.len() > MAX_WALLET_RPC_RESULT_BYTES {
        return Err(DispatchError::ResponseLimit);
    }
    serde_json::from_slice(&encoded).map_err(|_| DispatchError::Internal)
}

fn validate_wire_page_limit(limit: usize) -> Result<(), DispatchError> {
    if (1..=MAX_WALLET_RPC_PAGE_ITEMS).contains(&limit) {
        Ok(())
    } else {
        Err(DispatchError::Invalid(
            "wallet RPC page limit must be between 1 and 256",
        ))
    }
}

fn validate_wire_mempool_scan(scan_limit: usize) -> Result<(), DispatchError> {
    if (1..=MAX_WALLET_RPC_MEMPOOL_SCAN).contains(&scan_limit) {
        Ok(())
    } else {
        Err(DispatchError::Invalid(
            "wallet RPC mempool scan_limit must be between 1 and 1024",
        ))
    }
}

fn require_chain_epoch(expected: u64, actual: u64) -> Result<(), DispatchError> {
    if expected == actual {
        Ok(())
    } else {
        Err(WalletBackendError::StaleChainEpoch { expected, actual }.into())
    }
}

fn decode_expected_mempool(
    expected: Option<WireExpectedMempool>,
) -> Result<Option<ExpectedMempoolBinding>, DispatchError> {
    expected
        .map(|expected| {
            Ok(ExpectedMempoolBinding {
                instance_nonce: decode_hex_32(&expected.instance_nonce, "mempool instance nonce")?,
                generation: expected.generation,
            })
        })
        .transpose()
}

fn require_transaction_evidence_binding(
    evidence: &TransactionEvidence,
    expected_chain_epoch: u64,
    expected_mempool: Option<&ExpectedMempoolBinding>,
) -> Result<(), DispatchError> {
    require_chain_epoch(expected_chain_epoch, evidence.chain_epoch)?;
    let Some(expected_mempool) = expected_mempool else {
        return Ok(());
    };
    if expected_mempool.instance_nonce != evidence.mempool_instance_nonce {
        return Err(WalletBackendError::StaleMempoolInstance.into());
    }
    if expected_mempool.generation != evidence.mempool_generation {
        return Err(WalletBackendError::StaleMempoolGeneration {
            expected: expected_mempool.generation,
            actual: evidence.mempool_generation,
        }
        .into());
    }
    Ok(())
}

fn decode_script_ids(encoded: Vec<String>) -> Result<Vec<ScriptId>, DispatchError> {
    if encoded.is_empty() || encoded.len() > MAX_WALLET_RESTORE_SCRIPTS {
        return Err(DispatchError::Invalid(
            "script_ids must contain 1..=10000 entries",
        ));
    }
    encoded
        .into_iter()
        .map(|value| decode_hex_32(&value, "script ID").map(ScriptId::from_bytes))
        .collect()
}

fn decode_hex_32(encoded: &str, label: &'static str) -> Result<[u8; 32], DispatchError> {
    let raw = decode_hex_bounded(encoded, 32, label)?;
    raw.try_into()
        .map_err(|_| DispatchError::Invalid("identity must contain exactly 32 bytes"))
}

fn decode_hex_bounded(
    encoded: &str,
    maximum_bytes: usize,
    label: &'static str,
) -> Result<Vec<u8>, DispatchError> {
    if !encoded.len().is_multiple_of(2) || encoded.len() > maximum_bytes.saturating_mul(2) {
        return Err(DispatchError::Invalid(match label {
            "raw transaction" => "raw transaction hexadecimal length is invalid",
            "opaque cursor" => "opaque cursor hexadecimal length is invalid",
            _ => "identity must contain exactly 64 hexadecimal characters",
        }));
    }
    let mut raw = Vec::with_capacity(encoded.len() / 2);
    for pair in encoded.as_bytes().chunks_exact(2) {
        let high = hex_nibble(pair[0]).ok_or(DispatchError::Invalid(match label {
            "raw transaction" => "raw transaction is not hexadecimal",
            "opaque cursor" => "opaque cursor is not hexadecimal",
            _ => "identity is not hexadecimal",
        }))?;
        let low = hex_nibble(pair[1]).ok_or(DispatchError::Invalid(match label {
            "raw transaction" => "raw transaction is not hexadecimal",
            "opaque cursor" => "opaque cursor is not hexadecimal",
            _ => "identity is not hexadecimal",
        }))?;
        raw.push((high << 4) | low);
    }
    Ok(raw)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_cursor<T: DeserializeOwned>(cursor: Option<String>) -> Result<Option<T>, DispatchError> {
    cursor
        .map(|cursor| {
            let raw = decode_hex_bounded(&cursor, MAX_OPAQUE_CURSOR_BYTES, "opaque cursor")?;
            serde_json::from_slice(&raw)
                .map_err(|_| DispatchError::Invalid("opaque cursor is malformed"))
        })
        .transpose()
}

fn encode_cursor<T: Serialize>(cursor: Option<&T>) -> Result<Option<String>, DispatchError> {
    cursor
        .map(|cursor| {
            let raw = serde_json::to_vec(cursor).map_err(|_| DispatchError::Internal)?;
            if raw.len() > MAX_OPAQUE_CURSOR_BYTES {
                return Err(DispatchError::Internal);
            }
            Ok(hex_encode(&raw))
        })
        .transpose()
}

#[derive(Serialize)]
struct WireTip {
    hash: String,
    height: u32,
    median_time_past: u64,
    tree_root: String,
}

impl From<super::wallet_backend::WalletChainTip> for WireTip {
    fn from(tip: super::wallet_backend::WalletChainTip) -> Self {
        Self {
            hash: tip.hash.to_hex(),
            height: tip.height,
            median_time_past: tip.median_time_past,
            tree_root: hex_encode(tip.tree_root.as_bytes()),
        }
    }
}

fn wire_tip(tip: Option<super::wallet_backend::WalletChainTip>) -> Option<WireTip> {
    tip.map(WireTip::from)
}

#[derive(Serialize)]
struct WireChainSnapshot {
    chain_epoch: u64,
    tip: Option<WireTip>,
}

impl From<WalletChainSnapshot> for WireChainSnapshot {
    fn from(snapshot: WalletChainSnapshot) -> Self {
        Self {
            chain_epoch: snapshot.chain_epoch,
            tip: wire_tip(snapshot.tip),
        }
    }
}

#[derive(Serialize)]
struct WireBlockHashEvidence {
    chain_epoch: u64,
    tip: Option<WireTip>,
    height: u32,
    hash: Option<String>,
}

impl From<BlockHashEvidence> for WireBlockHashEvidence {
    fn from(evidence: BlockHashEvidence) -> Self {
        Self {
            chain_epoch: evidence.chain_epoch,
            tip: wire_tip(evidence.tip),
            height: evidence.height,
            hash: evidence.hash.map(|hash| hash.to_hex()),
        }
    }
}

#[derive(Serialize)]
struct WireOutpoint {
    txid: String,
    index: u32,
}

impl From<&Outpoint> for WireOutpoint {
    fn from(outpoint: &Outpoint) -> Self {
        Self {
            txid: outpoint.txid.to_hex(),
            index: outpoint.index,
        }
    }
}

#[derive(Serialize)]
struct WireAddress {
    version: u8,
    hash: String,
}

impl From<&Address> for WireAddress {
    fn from(address: &Address) -> Self {
        Self {
            version: address.version,
            hash: hex_encode(&address.hash),
        }
    }
}

#[derive(Serialize)]
struct WireCovenant {
    kind: u8,
    items: Vec<String>,
}

impl From<&Covenant> for WireCovenant {
    fn from(covenant: &Covenant) -> Self {
        Self {
            kind: covenant.kind.as_u8(),
            items: covenant.items.iter().map(|item| hex_encode(item)).collect(),
        }
    }
}

#[derive(Serialize)]
struct WireOutput {
    value: u64,
    address: WireAddress,
    covenant: WireCovenant,
}

impl From<&Output> for WireOutput {
    fn from(output: &Output) -> Self {
        Self {
            value: output.value,
            address: WireAddress::from(&output.address),
            covenant: WireCovenant::from(&output.covenant),
        }
    }
}

#[derive(Serialize)]
struct WireCoin {
    outpoint: WireOutpoint,
    value: u64,
    height: u32,
    coinbase: bool,
    address: WireAddress,
    covenant: WireCovenant,
}

impl From<&Coin> for WireCoin {
    fn from(coin: &Coin) -> Self {
        Self {
            outpoint: WireOutpoint::from(&coin.outpoint),
            value: coin.value,
            height: coin.height,
            coinbase: coin.coinbase,
            address: WireAddress::from(&coin.address),
            covenant: WireCovenant::from(&coin.covenant),
        }
    }
}

#[derive(Serialize)]
struct WireInclusion {
    block_hash: String,
    height: u32,
    transaction_index: Option<u32>,
    confirmations: u32,
}

impl From<&super::wallet_backend::TransactionInclusion> for WireInclusion {
    fn from(inclusion: &super::wallet_backend::TransactionInclusion) -> Self {
        Self {
            block_hash: inclusion.block_hash.to_hex(),
            height: inclusion.height,
            transaction_index: inclusion.transaction_position,
            confirmations: inclusion.confirmations,
        }
    }
}

#[derive(Serialize)]
struct WireConfirmedHistory {
    script_index: usize,
    txid: String,
    block_hash: String,
    height: u32,
    transaction_position: u32,
    block_time: Option<u64>,
    received: bool,
    spent: bool,
}

#[derive(Serialize)]
struct WireConfirmedUtxo {
    script_index: usize,
    coin: WireCoin,
}

#[derive(Serialize)]
struct WireConfirmedPage {
    chain_epoch: u64,
    tip: Option<WireTip>,
    history: Vec<WireConfirmedHistory>,
    utxos: Vec<WireConfirmedUtxo>,
    script_examinations: usize,
    continuation: Option<String>,
}

fn wire_confirmed_page(page: ConfirmedScriptsPage) -> Result<WireConfirmedPage, DispatchError> {
    Ok(WireConfirmedPage {
        chain_epoch: page.chain_epoch,
        tip: wire_tip(page.tip),
        history: page
            .history
            .into_iter()
            .map(|row| WireConfirmedHistory {
                script_index: row.script_index,
                txid: row.entry.txid.to_hex(),
                block_hash: row.entry.block_hash.to_hex(),
                height: row.entry.height,
                transaction_position: row.entry.transaction_position,
                block_time: row.block_time,
                received: row.entry.direction.received,
                spent: row.entry.direction.spent,
            })
            .collect(),
        utxos: page
            .utxos
            .into_iter()
            .map(|row| WireConfirmedUtxo {
                script_index: row.script_index,
                coin: WireCoin::from(&row.entry.coin),
            })
            .collect(),
        script_examinations: page.script_examinations,
        continuation: encode_cursor(page.continuation.as_ref())?,
    })
}

#[derive(Serialize)]
struct WireIncomingTransferRecipient {
    version: u8,
    hash: String,
}

#[derive(Serialize)]
struct WireIncomingTransferInclusion {
    block_hash: String,
    height: u32,
    transaction_index: u32,
    confirmations: u32,
}

#[derive(Serialize)]
struct WireIncomingTransfer {
    script_index: usize,
    recipient: WireIncomingTransferRecipient,
    name_hash: String,
    start_height: u32,
    transfer_coin: WireCoin,
    inclusion: WireIncomingTransferInclusion,
    source_output_count: u32,
    source_binding: &'static str,
}

#[derive(Serialize)]
struct WireIncomingTransfersPage {
    projection_version: u8,
    chain_epoch: u64,
    tip: Option<WireTip>,
    entries: Vec<WireIncomingTransfer>,
    script_examinations: usize,
    continuation: Option<String>,
}

const fn wire_incoming_transfer_source_binding(
    binding: IncomingTransferSourceBinding,
) -> &'static str {
    match binding {
        IncomingTransferSourceBinding::RetainedBodyVerified => "retained_body_verified",
        IncomingTransferSourceBinding::PrunedTrustedNodeProjection => {
            "pruned_trusted_node_projection"
        }
    }
}

fn wire_incoming_transfers_page(
    page: IncomingTransfersPage,
) -> Result<WireIncomingTransfersPage, DispatchError> {
    Ok(WireIncomingTransfersPage {
        projection_version: page.projection_version,
        chain_epoch: page.chain_epoch,
        tip: wire_tip(page.tip),
        entries: page
            .entries
            .into_iter()
            .map(|row| {
                Ok(WireIncomingTransfer {
                    script_index: row.script_index,
                    recipient: WireIncomingTransferRecipient {
                        version: row.entry.recipient_version,
                        hash: hex_encode(&row.entry.recipient_hash),
                    },
                    name_hash: hex_encode(&row.entry.name_hash),
                    start_height: row.entry.start_height,
                    transfer_coin: WireCoin::from(&row.entry.coin),
                    inclusion: WireIncomingTransferInclusion {
                        block_hash: row.inclusion.block_hash.to_hex(),
                        height: row.inclusion.height,
                        transaction_index: row
                            .inclusion
                            .transaction_position
                            .ok_or(DispatchError::Internal)?,
                        confirmations: row.inclusion.confirmations,
                    },
                    source_output_count: row.source_output_count,
                    source_binding: wire_incoming_transfer_source_binding(row.source_binding),
                })
            })
            .collect::<Result<Vec<_>, DispatchError>>()?,
        script_examinations: page.script_examinations,
        continuation: encode_cursor(page.continuation.as_ref())?,
    })
}

#[derive(Serialize)]
struct WireMempoolScriptOutput {
    script_index: usize,
    outpoint: WireOutpoint,
    value: u64,
}

#[derive(Serialize)]
struct WireMempoolScriptSpend {
    script_index: usize,
    outpoint: WireOutpoint,
}

#[derive(Serialize)]
struct WireMempoolScriptActivity {
    txid: String,
    admitted_at: u64,
    received: Vec<WireMempoolScriptOutput>,
    spent: Vec<WireMempoolScriptSpend>,
}

#[derive(Serialize)]
struct WireMempoolScriptPage {
    chain_epoch: u64,
    tip: Option<WireTip>,
    instance_nonce: String,
    generation: u64,
    entries: Vec<WireMempoolScriptActivity>,
    continuation: Option<String>,
}

fn wire_mempool_script_page(
    page: MempoolScriptPage,
) -> Result<WireMempoolScriptPage, DispatchError> {
    Ok(WireMempoolScriptPage {
        chain_epoch: page.chain_epoch,
        tip: wire_tip(page.tip),
        instance_nonce: hex_encode(&page.instance_nonce),
        generation: page.generation,
        entries: page
            .entries
            .into_iter()
            .map(|entry| WireMempoolScriptActivity {
                txid: entry.txid.to_hex(),
                admitted_at: entry.admitted_at,
                received: entry
                    .received
                    .into_iter()
                    .map(|output| WireMempoolScriptOutput {
                        script_index: output.script_index,
                        outpoint: WireOutpoint::from(&output.outpoint),
                        value: output.value,
                    })
                    .collect(),
                spent: entry
                    .spent
                    .into_iter()
                    .map(|spend| WireMempoolScriptSpend {
                        script_index: spend.script_index,
                        outpoint: WireOutpoint::from(&spend.outpoint),
                    })
                    .collect(),
            })
            .collect(),
        continuation: encode_cursor(page.continuation.as_ref())?,
    })
}

#[derive(Serialize)]
struct WireTransactionEvidence {
    chain_epoch: u64,
    mempool_instance_nonce: String,
    mempool_generation: u64,
    tip: Option<WireTip>,
    status: &'static str,
    inclusion: Option<WireInclusion>,
    payload: &'static str,
    transaction_hex: Option<String>,
}

fn wire_transaction_evidence(evidence: TransactionEvidence) -> WireTransactionEvidence {
    let status = match evidence.status {
        TransactionStatus::Mempool => "mempool",
        TransactionStatus::Confirmed(_) => "confirmed",
        TransactionStatus::Unknown => "unknown",
    };
    let (payload, transaction_hex) = match evidence.payload {
        TransactionPayload::Retained(transaction) => {
            ("retained", Some(hex_encode(&transaction.encode())))
        }
        TransactionPayload::Pruned => ("pruned", None),
        TransactionPayload::Absent => ("absent", None),
    };
    WireTransactionEvidence {
        chain_epoch: evidence.chain_epoch,
        mempool_instance_nonce: hex_encode(&evidence.mempool_instance_nonce),
        mempool_generation: evidence.mempool_generation,
        tip: wire_tip(evidence.tip),
        status,
        inclusion: evidence.inclusion.as_ref().map(WireInclusion::from),
        payload,
        transaction_hex,
    }
}

#[derive(Serialize)]
struct WireRawTransactionEvidence {
    chain_epoch: u64,
    tip: Option<WireTip>,
    mempool_instance_nonce: String,
    mempool_generation: u64,
    transaction_hex: Option<String>,
}

fn wire_raw_transaction_evidence(
    evidence: TransactionEvidence,
) -> Result<WireRawTransactionEvidence, DispatchError> {
    let transaction_hex = match evidence.payload {
        TransactionPayload::Retained(transaction) => Some(hex_encode(&transaction.encode())),
        TransactionPayload::Pruned => return Err(WalletBackendError::PayloadPruned.into()),
        TransactionPayload::Absent => None,
    };
    Ok(WireRawTransactionEvidence {
        chain_epoch: evidence.chain_epoch,
        tip: wire_tip(evidence.tip),
        mempool_instance_nonce: hex_encode(&evidence.mempool_instance_nonce),
        mempool_generation: evidence.mempool_generation,
        transaction_hex,
    })
}

#[derive(Serialize)]
struct WireBroadcastResult {
    txid: String,
    newly_admitted: bool,
    attempted_peers: usize,
    queued_peers: usize,
    failed_peers: usize,
}

impl From<&BroadcastResult> for WireBroadcastResult {
    fn from(result: &BroadcastResult) -> Self {
        Self {
            txid: result.txid.to_hex(),
            newly_admitted: result.newly_admitted,
            attempted_peers: result.attempted_peers,
            queued_peers: result.queued_peers,
            failed_peers: result.failed_peers,
        }
    }
}

#[derive(Serialize)]
struct WireFeeEstimate {
    target_blocks: u32,
    atomic_units_per_kvb: u64,
    sampled_transactions: usize,
    source: &'static str,
}

impl From<&FeeEstimate> for WireFeeEstimate {
    fn from(estimate: &FeeEstimate) -> Self {
        Self {
            target_blocks: estimate.target_blocks,
            atomic_units_per_kvb: estimate.atomic_units_per_kvb,
            sampled_transactions: estimate.sampled_transactions,
            source: match estimate.source {
                FeeEstimateSource::MinimumRelay => "minimum_relay",
                FeeEstimateSource::Mempool => "mempool",
            },
        }
    }
}

#[derive(Serialize)]
struct WireTransactionFeeQuote {
    txid: String,
    chain_epoch: u64,
    tip: Option<WireTip>,
    mempool_instance_nonce: String,
    mempool_generation: u64,
    target_blocks: u32,
    rate_atomic_units_per_1000_policy_vbytes: u64,
    rate_sample_count: usize,
    rate_source: &'static str,
    transaction_weight: usize,
    transaction_sigops: u32,
    sigop_adjusted_policy_vbytes: usize,
    minimum_policy_fee_atomic_units: u64,
    actual_fee_atomic_units: u64,
    meets_minimum_policy_fee: bool,
    minimum_policy_fee_shortfall_atomic_units: u64,
}

impl From<&TransactionFeeQuote> for WireTransactionFeeQuote {
    fn from(quote: &TransactionFeeQuote) -> Self {
        Self {
            txid: quote.txid.to_hex(),
            chain_epoch: quote.chain_epoch,
            tip: wire_tip(quote.tip.clone()),
            mempool_instance_nonce: hex_encode(&quote.mempool_instance_nonce),
            mempool_generation: quote.mempool_generation,
            target_blocks: quote.target_blocks,
            rate_atomic_units_per_1000_policy_vbytes: quote
                .rate_atomic_units_per_1000_policy_vbytes,
            rate_sample_count: quote.rate_sample_count,
            rate_source: match quote.rate_source {
                FeeEstimateSource::MinimumRelay => "minimum_relay",
                FeeEstimateSource::Mempool => "mempool",
            },
            transaction_weight: quote.transaction_weight,
            transaction_sigops: quote.transaction_sigops,
            sigop_adjusted_policy_vbytes: quote.sigop_adjusted_policy_vbytes,
            minimum_policy_fee_atomic_units: quote.minimum_policy_fee_atomic_units,
            actual_fee_atomic_units: quote.actual_fee_atomic_units,
            meets_minimum_policy_fee: quote.meets_minimum_policy_fee,
            minimum_policy_fee_shortfall_atomic_units: quote
                .minimum_policy_fee_shortfall_atomic_units,
        }
    }
}

#[derive(Serialize)]
struct WireSpendingTransaction {
    txid: String,
    input_position: u32,
    block_hash: String,
    height: u32,
}

impl From<&SpendingTransaction> for WireSpendingTransaction {
    fn from(transaction: &SpendingTransaction) -> Self {
        Self {
            txid: transaction.txid.to_hex(),
            input_position: transaction.input_position,
            block_hash: transaction.block_hash.to_hex(),
            height: transaction.height,
        }
    }
}

#[derive(Serialize)]
struct WireOutpointSpendingEntry {
    outpoint: WireOutpoint,
    spending: Option<WireSpendingTransaction>,
}

#[derive(Serialize)]
struct WireOutpointSpendingEvidence {
    chain_epoch: u64,
    tip: Option<WireTip>,
    entries: Vec<WireOutpointSpendingEntry>,
}

fn wire_outpoint_spending_evidence(
    evidence: OutpointSpendingEvidence,
) -> WireOutpointSpendingEvidence {
    WireOutpointSpendingEvidence {
        chain_epoch: evidence.chain_epoch,
        tip: wire_tip(evidence.tip),
        entries: evidence
            .entries
            .into_iter()
            .map(|entry| WireOutpointSpendingEntry {
                outpoint: WireOutpoint::from(&entry.outpoint),
                spending: entry.spending.as_ref().map(WireSpendingTransaction::from),
            })
            .collect(),
    }
}

#[derive(Serialize)]
struct WireNameState {
    name_hash: String,
    name_hex: String,
    height: u32,
    renewal: u32,
    owner: WireOutpoint,
    value: u64,
    highest: u64,
    data_hex: String,
    transfer: u32,
    revoked: u32,
    claimed: u32,
    renewals: u32,
    registered: bool,
    expired: bool,
    weak: bool,
}

impl From<&NameState> for WireNameState {
    fn from(state: &NameState) -> Self {
        Self {
            name_hash: state.name_hash.to_hex(),
            name_hex: hex_encode(&state.name),
            height: state.height,
            renewal: state.renewal,
            owner: WireOutpoint::from(&state.owner),
            value: state.value,
            highest: state.highest,
            data_hex: hex_encode(&state.data),
            transfer: state.transfer,
            revoked: state.revoked,
            claimed: state.claimed,
            renewals: state.renewals,
            registered: state.registered,
            expired: state.expired,
            weak: state.weak,
        }
    }
}

#[derive(Serialize)]
struct WireActiveNameOwnerCoin {
    projection_version: u8,
    chain_epoch: u64,
    tip: WireTip,
    current_state_hex: String,
    current_state: WireNameState,
    owner_coin: WireCoin,
    inclusion: WireInclusion,
    source_binding: &'static str,
}

const fn wire_active_name_owner_coin_source_binding(
    binding: ActiveNameOwnerCoinSourceBinding,
) -> &'static str {
    binding.as_str()
}

fn wire_active_name_owner_coin(evidence: ActiveNameOwnerCoinEvidence) -> WireActiveNameOwnerCoin {
    WireActiveNameOwnerCoin {
        projection_version: evidence.projection_version,
        chain_epoch: evidence.chain_epoch,
        tip: WireTip::from(evidence.tip),
        current_state_hex: hex_encode(&evidence.current_state_bytes),
        current_state: WireNameState::from(&evidence.current_state),
        owner_coin: WireCoin::from(&evidence.owner_coin),
        inclusion: WireInclusion::from(&evidence.inclusion),
        source_binding: wire_active_name_owner_coin_source_binding(evidence.source_binding),
    }
}

#[derive(Serialize)]
struct WireNameProof {
    root: String,
    name_hash: String,
    kind: &'static str,
    proof_hex: String,
}

#[derive(Serialize)]
struct WireNameOwner {
    name_state: WireNameState,
    owner: WireOutpoint,
    transaction_hex: String,
    owner_output: WireOutput,
    inclusion: WireInclusion,
}

impl From<&NameOwnerTransaction> for WireNameOwner {
    fn from(owner: &NameOwnerTransaction) -> Self {
        Self {
            name_state: WireNameState::from(&owner.name_state),
            owner: WireOutpoint::from(&owner.owner),
            transaction_hex: hex_encode(&owner.transaction.encode()),
            owner_output: WireOutput::from(&owner.owner_output),
            inclusion: WireInclusion::from(&owner.inclusion),
        }
    }
}

#[derive(Serialize)]
struct WireNameEvidence {
    chain_epoch: u64,
    tip: Option<WireTip>,
    current_state_hex: Option<String>,
    proof_state_hex: Option<String>,
    current_state: Option<WireNameState>,
    proof_state: Option<WireNameState>,
    proof: WireNameProof,
    current_owner: Option<WireNameOwner>,
    proof_owner: Option<WireNameOwner>,
    data_semantics: &'static str,
}

fn wire_name_evidence(evidence: NameEvidence) -> Result<WireNameEvidence, DispatchError> {
    let kind = match evidence.proof.proof.kind {
        ProofKind::Inclusion => "inclusion",
        ProofKind::NonInclusion => "non_inclusion",
    };
    let current_state_hex = evidence
        .current_state
        .as_ref()
        .map(encode_name_state)
        .transpose()
        .map_err(|_| DispatchError::Internal)?
        .map(|raw| hex_encode(&raw));
    let proof_state_hex = evidence
        .proof_state
        .as_ref()
        .map(encode_name_state)
        .transpose()
        .map_err(|_| DispatchError::Internal)?
        .map(|raw| hex_encode(&raw));
    Ok(WireNameEvidence {
        chain_epoch: evidence.chain_epoch,
        tip: wire_tip(evidence.tip),
        current_state_hex,
        proof_state_hex,
        current_state: evidence.current_state.as_ref().map(WireNameState::from),
        proof_state: evidence.proof_state.as_ref().map(WireNameState::from),
        proof: WireNameProof {
            root: hex_encode(evidence.proof.root.as_bytes()),
            name_hash: evidence.proof.proof.name_hash.to_hex(),
            kind,
            proof_hex: hex_encode(&evidence.proof.proof.raw),
        },
        current_owner: evidence.current_owner.as_ref().map(WireNameOwner::from),
        proof_owner: evidence.proof_owner.as_ref().map(WireNameOwner::from),
        data_semantics: "projected_data_hex_is_resource_bytes_not_encoded_name_state",
    })
}

#[derive(Serialize)]
struct WireNameActionChainIdentity {
    network: String,
    network_id: u8,
    genesis_hash: String,
    consensus_profile: String,
}

#[derive(Serialize)]
struct WireNameActionMempool {
    instance_nonce: String,
    generation: u64,
    owner_spender_txid: Option<String>,
}

#[derive(Serialize)]
struct WireNameActionTransfer {
    lockup_blocks: u32,
    current_transfer_height: Option<u32>,
    finalize_maturity_height: Option<u32>,
    finalize_eligible_at_candidate: bool,
}

#[derive(Serialize)]
struct WireNameActionRenewal {
    maturity_blocks: u32,
    period_blocks: u32,
    hsd_selected_height: u32,
    hsd_selected_hash: String,
    valid_at_candidate: bool,
}

#[derive(Serialize)]
struct WireNameActionEligibility {
    eligible: bool,
    reasons: Vec<&'static str>,
}

#[derive(Serialize)]
struct WireNameActionContext {
    context_version: u8,
    action: &'static str,
    chain_identity: WireNameActionChainIdentity,
    chain_epoch: u64,
    tip: WireTip,
    candidate_inclusion_height: u32,
    mempool: WireNameActionMempool,
    name_hash: String,
    current_state_hex: String,
    current_state: WireNameState,
    owner: WireNameOwner,
    lifecycle: &'static str,
    transfer: WireNameActionTransfer,
    renewal: WireNameActionRenewal,
    eligibility: WireNameActionEligibility,
}

fn wire_name_action_context(
    context: NameActionContext,
) -> Result<WireNameActionContext, DispatchError> {
    if context.ineligibility_reasons.len() > MAX_NAME_ACTION_INELIGIBILITY_REASONS {
        return Err(DispatchError::Internal);
    }
    let current_state_hex = encode_name_state(&context.current_state)
        .map_err(|_| DispatchError::Internal)
        .map(|raw| hex_encode(&raw))?;
    let eligible = context.eligible();
    let reasons = context
        .ineligibility_reasons
        .iter()
        .copied()
        .map(wire_name_action_ineligibility)
        .collect();
    Ok(WireNameActionContext {
        context_version: context.context_version,
        action: wire_name_action(context.action),
        chain_identity: WireNameActionChainIdentity {
            network: context.network.to_string(),
            network_id: context.network_id,
            genesis_hash: context.genesis_hash.to_hex(),
            consensus_profile: context.consensus_profile,
        },
        chain_epoch: context.chain_epoch,
        tip: WireTip {
            hash: context.tip.hash.to_hex(),
            height: context.tip.height,
            median_time_past: context.tip.median_time_past,
            tree_root: hex_encode(context.tip.tree_root.as_bytes()),
        },
        candidate_inclusion_height: context.candidate_inclusion_height,
        mempool: WireNameActionMempool {
            instance_nonce: hex_encode(&context.mempool_instance_nonce),
            generation: context.mempool_generation,
            owner_spender_txid: context.owner_spender_txid.map(Txid::to_hex),
        },
        name_hash: context.name_hash.to_hex(),
        current_state_hex,
        current_state: WireNameState::from(&context.current_state),
        owner: WireNameOwner::from(&context.owner),
        lifecycle: wire_name_lifecycle(context.lifecycle),
        transfer: WireNameActionTransfer {
            lockup_blocks: context.transfer.lockup_blocks,
            current_transfer_height: context.transfer.current_transfer_height,
            finalize_maturity_height: context.transfer.finalize_maturity_height,
            finalize_eligible_at_candidate: context.transfer.finalize_eligible_at_candidate,
        },
        renewal: WireNameActionRenewal {
            maturity_blocks: context.renewal.maturity_blocks,
            period_blocks: context.renewal.period_blocks,
            hsd_selected_height: context.renewal.hsd_selected_height,
            hsd_selected_hash: context.renewal.hsd_selected_hash.to_hex(),
            valid_at_candidate: context.renewal.valid_at_candidate,
        },
        eligibility: WireNameActionEligibility { eligible, reasons },
    })
}

#[derive(Serialize)]
struct WireNameActionActiveOwnerCoin {
    projection_version: u8,
    owner_coin: WireCoin,
    inclusion: WireInclusion,
    source_binding: &'static str,
}

#[derive(Serialize)]
struct WireNameActionContextV2 {
    context_version: u8,
    action: &'static str,
    chain_identity: WireNameActionChainIdentity,
    chain_epoch: u64,
    tip: WireTip,
    candidate_inclusion_height: u32,
    mempool: WireNameActionMempool,
    name_hash: String,
    current_state_hex: String,
    current_state: WireNameState,
    active_owner: WireNameActionActiveOwnerCoin,
    lifecycle: &'static str,
    transfer: WireNameActionTransfer,
    renewal: WireNameActionRenewal,
    eligibility: WireNameActionEligibility,
}

fn wire_name_action_context_v2(
    context: NameActionContextV2,
) -> Result<WireNameActionContextV2, DispatchError> {
    let encoded_state =
        encode_name_state(&context.current_state).map_err(|_| DispatchError::Internal)?;
    if context.context_version != NAME_ACTION_CONTEXT_V2_VERSION
        || context.active_owner.projection_version != ACTIVE_NAME_OWNER_COIN_PROJECTION_VERSION
        || context
            .active_owner
            .inclusion
            .transaction_position
            .is_some()
        || context.name_hash != context.current_state.name_hash
        || context.current_state_bytes != encoded_state
        || context.active_owner.owner_coin.outpoint != context.current_state.owner
        || context.active_owner.owner_coin.height != context.active_owner.inclusion.height
        || context.ineligibility_reasons.len() > MAX_NAME_ACTION_INELIGIBILITY_REASONS
    {
        return Err(DispatchError::Internal);
    }

    let eligible = context.eligible();
    let reasons = context
        .ineligibility_reasons
        .iter()
        .copied()
        .map(wire_name_action_ineligibility)
        .collect();
    Ok(WireNameActionContextV2 {
        context_version: context.context_version,
        action: wire_name_action(context.action),
        chain_identity: WireNameActionChainIdentity {
            network: context.network.to_string(),
            network_id: context.network_id,
            genesis_hash: context.genesis_hash.to_hex(),
            consensus_profile: context.consensus_profile,
        },
        chain_epoch: context.chain_epoch,
        tip: WireTip {
            hash: context.tip.hash.to_hex(),
            height: context.tip.height,
            median_time_past: context.tip.median_time_past,
            tree_root: hex_encode(context.tip.tree_root.as_bytes()),
        },
        candidate_inclusion_height: context.candidate_inclusion_height,
        mempool: WireNameActionMempool {
            instance_nonce: hex_encode(&context.mempool_instance_nonce),
            generation: context.mempool_generation,
            owner_spender_txid: context.owner_spender_txid.map(Txid::to_hex),
        },
        name_hash: context.name_hash.to_hex(),
        current_state_hex: hex_encode(&context.current_state_bytes),
        current_state: WireNameState::from(&context.current_state),
        active_owner: WireNameActionActiveOwnerCoin {
            projection_version: context.active_owner.projection_version,
            owner_coin: WireCoin::from(&context.active_owner.owner_coin),
            inclusion: WireInclusion::from(&context.active_owner.inclusion),
            source_binding: wire_active_name_owner_coin_source_binding(
                context.active_owner.source_binding,
            ),
        },
        lifecycle: wire_name_lifecycle(context.lifecycle),
        transfer: WireNameActionTransfer {
            lockup_blocks: context.transfer.lockup_blocks,
            current_transfer_height: context.transfer.current_transfer_height,
            finalize_maturity_height: context.transfer.finalize_maturity_height,
            finalize_eligible_at_candidate: context.transfer.finalize_eligible_at_candidate,
        },
        renewal: WireNameActionRenewal {
            maturity_blocks: context.renewal.maturity_blocks,
            period_blocks: context.renewal.period_blocks,
            hsd_selected_height: context.renewal.hsd_selected_height,
            hsd_selected_hash: context.renewal.hsd_selected_hash.to_hex(),
            valid_at_candidate: context.renewal.valid_at_candidate,
        },
        eligibility: WireNameActionEligibility { eligible, reasons },
    })
}

const fn wire_name_action(action: NameAction) -> &'static str {
    match action {
        NameAction::Transfer => "transfer",
        NameAction::Finalize => "finalize",
    }
}

const fn wire_name_lifecycle(lifecycle: NameLifecycleState) -> &'static str {
    match lifecycle {
        NameLifecycleState::Opening => "opening",
        NameLifecycleState::Locked => "locked",
        NameLifecycleState::Bidding => "bidding",
        NameLifecycleState::Reveal => "reveal",
        NameLifecycleState::Closed => "closed",
        NameLifecycleState::Revoked => "revoked",
    }
}

const fn wire_name_action_ineligibility(reason: NameActionIneligibility) -> &'static str {
    match reason {
        NameActionIneligibility::NameNotRegistered => "name_not_registered",
        NameActionIneligibility::NameExpiredAtCandidate => "name_expired_at_candidate",
        NameActionIneligibility::LifecycleNotClosed => "lifecycle_not_closed",
        NameActionIneligibility::TransferAlreadyPending => "transfer_already_pending",
        NameActionIneligibility::TransferNotPending => "transfer_not_pending",
        NameActionIneligibility::TransferNotMature => "transfer_not_mature",
        NameActionIneligibility::OwnerCovenantInvalidForAction => {
            "owner_covenant_invalid_for_action"
        }
        NameActionIneligibility::RenewalCommitmentInvalid => "renewal_commitment_invalid",
        NameActionIneligibility::OwnerSpentInMempool => "owner_spent_in_mempool",
    }
}

#[derive(Serialize)]
struct WireTrackedFunding {
    contract_id: String,
    coin: WireCoin,
    block_hash: String,
    height: u32,
    transaction_position: u32,
    output_position: u32,
}

impl From<&TrackedContractFunding> for WireTrackedFunding {
    fn from(funding: &TrackedContractFunding) -> Self {
        Self {
            contract_id: hex_encode(funding.contract_id.as_bytes()),
            coin: WireCoin::from(&funding.coin),
            block_hash: funding.block_hash.to_hex(),
            height: funding.height,
            transaction_position: funding.transaction_position,
            output_position: funding.output_position,
        }
    }
}

fn wire_spend_kind(kind: &TrackedContractSpendKind) -> &'static str {
    match kind {
        TrackedContractSpendKind::Unrecognized => "unrecognized",
        TrackedContractSpendKind::ShakedexFulfillment => "shakedex_fulfillment",
        TrackedContractSpendKind::ShakedexRecovery => "shakedex_recovery",
        TrackedContractSpendKind::HtlcRedemption { .. } => "hns_htlc_redemption_preimage_opaque",
        TrackedContractSpendKind::HtlcRefund => "hns_htlc_refund",
    }
}

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum WireTrackedEvent {
    Funding {
        funding: WireTrackedFunding,
    },
    Spend {
        contract_id: String,
        funding: WireTrackedFunding,
        spending_txid: String,
        block_hash: String,
        height: u32,
        transaction_position: u32,
        input_position: u32,
        kind: &'static str,
    },
}

fn wire_tracked_event(event: &TrackedContractEvent) -> WireTrackedEvent {
    match event {
        TrackedContractEvent::Funding(funding) => WireTrackedEvent::Funding {
            funding: WireTrackedFunding::from(funding),
        },
        TrackedContractEvent::Spend {
            contract_id,
            funding,
            spending_txid,
            block_hash,
            height,
            transaction_position,
            input_position,
            kind,
        } => WireTrackedEvent::Spend {
            contract_id: hex_encode(contract_id.as_bytes()),
            funding: WireTrackedFunding::from(funding),
            spending_txid: spending_txid.to_hex(),
            block_hash: block_hash.to_hex(),
            height: *height,
            transaction_position: *transaction_position,
            input_position: *input_position,
            kind: wire_spend_kind(kind),
        },
    }
}

#[derive(Serialize)]
struct WireContractFundingPage {
    chain_epoch: u64,
    tip: Option<WireTip>,
    entries: Vec<WireTrackedFunding>,
    continuation: Option<String>,
}

fn wire_contract_funding_page(
    page: WalletContractFundingPage,
) -> Result<WireContractFundingPage, DispatchError> {
    Ok(WireContractFundingPage {
        chain_epoch: page.chain_epoch,
        tip: wire_tip(page.tip),
        entries: page.entries.iter().map(WireTrackedFunding::from).collect(),
        continuation: encode_cursor(page.continuation.as_ref())?,
    })
}

#[derive(Serialize)]
struct WireContractEventPage {
    chain_epoch: u64,
    tip: Option<WireTip>,
    entries: Vec<WireTrackedEvent>,
    continuation: Option<String>,
    preimage_transport: &'static str,
}

fn wire_contract_event_page(
    page: WalletContractEventPage,
) -> Result<WireContractEventPage, DispatchError> {
    Ok(WireContractEventPage {
        chain_epoch: page.chain_epoch,
        tip: wire_tip(page.tip),
        entries: page.entries.iter().map(wire_tracked_event).collect(),
        continuation: encode_cursor(page.continuation.as_ref())?,
        preimage_transport: "opaque_unavailable",
    })
}

#[derive(Serialize)]
#[serde(tag = "event", rename_all = "snake_case")]
enum WireMempoolContractEvent {
    Funding {
        outpoint: WireOutpoint,
        value: u64,
    },
    Spend {
        funding_outpoint: WireOutpoint,
        input_position: u32,
        kind: &'static str,
    },
}

#[derive(Serialize)]
struct WireMempoolContractActivity {
    txid: String,
    admitted_at: u64,
    events: Vec<WireMempoolContractEvent>,
}

#[derive(Serialize)]
struct WireMempoolContractPage {
    chain_epoch: u64,
    tip: Option<WireTip>,
    instance_nonce: String,
    generation: u64,
    entries: Vec<WireMempoolContractActivity>,
    continuation: Option<String>,
    preimage_transport: &'static str,
}

fn wire_mempool_contract_page(
    page: MempoolContractPage,
) -> Result<WireMempoolContractPage, DispatchError> {
    Ok(WireMempoolContractPage {
        chain_epoch: page.chain_epoch,
        tip: wire_tip(page.tip),
        instance_nonce: hex_encode(&page.instance_nonce),
        generation: page.generation,
        entries: page
            .entries
            .into_iter()
            .map(|activity| WireMempoolContractActivity {
                txid: activity.txid.to_hex(),
                admitted_at: activity.admitted_at,
                events: activity
                    .events
                    .into_iter()
                    .map(|event| match event {
                        MempoolContractEvent::Funding { outpoint, value } => {
                            WireMempoolContractEvent::Funding {
                                outpoint: WireOutpoint::from(&outpoint),
                                value,
                            }
                        }
                        MempoolContractEvent::Spend {
                            funding_outpoint,
                            input_position,
                            kind,
                        } => WireMempoolContractEvent::Spend {
                            funding_outpoint: WireOutpoint::from(&funding_outpoint),
                            input_position,
                            kind: wire_spend_kind(&kind),
                        },
                    })
                    .collect(),
            })
            .collect(),
        continuation: encode_cursor(page.continuation.as_ref())?,
        preimage_transport: "opaque_unavailable",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_tip_wire_projection_remains_exact() {
        let projected = serde_json::to_value(
            wire_tip(Some(crate::wallet_backend::WalletChainTip {
                hash: hns_primitives::BlockHash::new([0x11; 32]),
                height: 42,
                median_time_past: 1_700_000_123,
                tree_root: hns_state::TreeRoot::new([0x22; 32]),
            }))
            .expect("present tip"),
        )
        .expect("serialize tip");
        assert_eq!(
            projected,
            serde_json::json!({
                "hash": "11".repeat(32),
                "height": 42,
                "median_time_past": 1_700_000_123u64,
                "tree_root": "22".repeat(32),
            })
        );
    }

    #[test]
    fn chain_snapshot_request_and_response_are_strict_and_exactly_bound() {
        let request: WalletRpcRequest = serde_json::from_value(serde_json::json!({
            "api_version": 1,
            "request_id": "initial-binding-1",
            "call": {
                "method": "chain_snapshot"
            }
        }))
        .expect("strict chain-snapshot request");
        assert!(matches!(request.call, WalletRpcCall::ChainSnapshot));

        assert!(
            serde_json::from_value::<WalletRpcRequest>(serde_json::json!({
                "api_version": 1,
                "call": {
                    "method": "chain_snapshot",
                    "params": {
                        "script_ids": []
                    }
                }
            }))
            .is_err()
        );

        let result = value(&WireChainSnapshot::from(WalletChainSnapshot {
            chain_epoch: 17,
            tip: Some(crate::wallet_backend::WalletChainTip {
                hash: hns_primitives::BlockHash::new([0x33; 32]),
                height: 42,
                median_time_past: 1_700_000_123,
                tree_root: hns_state::TreeRoot::new([0x44; 32]),
            }),
        }))
        .expect("bounded chain-snapshot result");
        let response = serde_json::to_value(WalletRpcResponse::success(
            Some("initial-binding-1".to_owned()),
            result,
        ))
        .expect("serialize chain-snapshot response");
        assert_eq!(
            response,
            serde_json::json!({
                "api_version": 1,
                "request_id": "initial-binding-1",
                "result": {
                    "chain_epoch": 17,
                    "tip": {
                        "hash": "33".repeat(32),
                        "height": 42,
                        "median_time_past": 1_700_000_123u64,
                        "tree_root": "44".repeat(32),
                    }
                }
            })
        );
    }

    #[test]
    fn active_name_owner_coin_request_requires_epoch_and_rejects_extensions() {
        let request: WalletRpcRequest = serde_json::from_value(serde_json::json!({
            "api_version": 1,
            "request_id": "active-name-owner-1",
            "call": {
                "method": "active_name_owner_coin",
                "params": {
                    "name_hash": "11".repeat(32),
                    "expected_chain_epoch": 7
                }
            }
        }))
        .expect("strict active-name-owner request");
        let WalletRpcCall::ActiveNameOwnerCoin {
            name_hash,
            expected_chain_epoch,
        } = request.call
        else {
            panic!("active-name-owner method");
        };
        assert_eq!(name_hash, "11".repeat(32));
        assert_eq!(expected_chain_epoch, 7);

        for invalid_params in [
            serde_json::json!({
                "name_hash": "11".repeat(32)
            }),
            serde_json::json!({
                "name_hash": "11".repeat(32),
                "expected_chain_epoch": 7,
                "unbound_extension": true
            }),
        ] {
            assert!(
                serde_json::from_value::<WalletRpcRequest>(serde_json::json!({
                    "api_version": 1,
                    "call": {
                        "method": "active_name_owner_coin",
                        "params": invalid_params
                    }
                }))
                .is_err()
            );
        }
    }

    #[test]
    fn active_name_owner_coin_wire_projection_is_exact_and_pruning_safe() {
        let name_hash = NameHash::new([0x11; 32]);
        let owner = Outpoint {
            txid: Txid::new([0x22; 32]),
            index: 2,
        };
        let covenant = Covenant {
            kind: hns_primitives::CovenantKind::Transfer,
            items: vec![
                name_hash.as_bytes().to_vec(),
                12_u32.to_le_bytes().to_vec(),
                vec![0],
                vec![0x44; 20],
            ],
        };
        let mut current_state = NameState::null(name_hash);
        current_state.name = b"alpha".to_vec();
        current_state.height = 12;
        current_state.renewal = 15;
        current_state.owner = owner.clone();
        current_state.value = 4_200;
        current_state.highest = 4_300;
        current_state.data = vec![0xaa, 0xbb];
        current_state.transfer = 41;
        current_state.renewals = 3;
        current_state.registered = true;
        let current_state_bytes = encode_name_state(&current_state).expect("encode NameState");
        let coin = Coin {
            outpoint: owner,
            value: 4_200,
            height: 41,
            coinbase: false,
            address: Address::new(0, vec![0x55; 20]).expect("address"),
            covenant,
        };
        let projected =
            serde_json::to_value(wire_active_name_owner_coin(ActiveNameOwnerCoinEvidence {
                projection_version: ACTIVE_NAME_OWNER_COIN_PROJECTION_VERSION,
                chain_epoch: 17,
                tip: crate::wallet_backend::WalletChainTip {
                    hash: hns_primitives::BlockHash::new([0x33; 32]),
                    height: 50,
                    median_time_past: 1_700_000_123,
                    tree_root: hns_state::TreeRoot::new([0x66; 32]),
                },
                current_state_bytes: current_state_bytes.clone(),
                current_state,
                owner_coin: coin,
                inclusion: crate::wallet_backend::TransactionInclusion {
                    block_hash: hns_primitives::BlockHash::new([0x77; 32]),
                    height: 41,
                    transaction_position: None,
                    confirmations: 10,
                },
                source_binding: ActiveNameOwnerCoinSourceBinding::TrustedNodeActiveUtxoProjection,
            }))
            .expect("serialize active-name-owner projection");
        assert_eq!(
            projected,
            serde_json::json!({
                "projection_version": 1,
                "chain_epoch": 17,
                "tip": {
                    "hash": "33".repeat(32),
                    "height": 50,
                    "median_time_past": 1_700_000_123u64,
                    "tree_root": "66".repeat(32)
                },
                "current_state_hex": hex_encode(&current_state_bytes),
                "current_state": {
                    "name_hash": "11".repeat(32),
                    "name_hex": "616c706861",
                    "height": 12,
                    "renewal": 15,
                    "owner": {
                        "txid": "22".repeat(32),
                        "index": 2
                    },
                    "value": 4_200,
                    "highest": 4_300,
                    "data_hex": "aabb",
                    "transfer": 41,
                    "revoked": 0,
                    "claimed": 0,
                    "renewals": 3,
                    "registered": true,
                    "expired": false,
                    "weak": false
                },
                "owner_coin": {
                    "outpoint": {
                        "txid": "22".repeat(32),
                        "index": 2
                    },
                    "value": 4_200,
                    "height": 41,
                    "coinbase": false,
                    "address": {
                        "version": 0,
                        "hash": "55".repeat(20)
                    },
                    "covenant": {
                        "kind": hns_primitives::CovenantKind::Transfer.as_u8(),
                        "items": [
                            "11".repeat(32),
                            "0c000000",
                            "00",
                            "44".repeat(20)
                        ]
                    }
                },
                "inclusion": {
                    "block_hash": "77".repeat(32),
                    "height": 41,
                    "transaction_index": null,
                    "confirmations": 10
                },
                "source_binding": "trusted_node_active_utxo_projection"
            })
        );
    }

    #[test]
    fn incoming_transfer_request_requires_epoch_and_rejects_extensions() {
        let request: WalletRpcRequest = serde_json::from_value(serde_json::json!({
            "api_version": 1,
            "request_id": "incoming-transfer-1",
            "call": {
                "method": "incoming_transfers_page",
                "params": {
                    "script_ids": ["11".repeat(32)],
                    "expected_chain_epoch": 7,
                    "cursor": null,
                    "limit": 32
                }
            }
        }))
        .expect("strict incoming-transfer request");
        let WalletRpcCall::IncomingTransfersPage {
            script_ids,
            expected_chain_epoch,
            cursor,
            limit,
        } = request.call
        else {
            panic!("incoming-transfer method");
        };
        assert_eq!(script_ids, vec!["11".repeat(32)]);
        assert_eq!(expected_chain_epoch, 7);
        assert_eq!(cursor, None);
        assert_eq!(limit, 32);

        for invalid_params in [
            serde_json::json!({
                "script_ids": ["11".repeat(32)],
                "limit": 32
            }),
            serde_json::json!({
                "script_ids": ["11".repeat(32)],
                "expected_chain_epoch": 7,
                "limit": 32,
                "unbound_extension": true
            }),
        ] {
            assert!(
                serde_json::from_value::<WalletRpcRequest>(serde_json::json!({
                    "api_version": 1,
                    "call": {
                        "method": "incoming_transfers_page",
                        "params": invalid_params
                    }
                }))
                .is_err()
            );
        }
    }

    #[test]
    fn incoming_transfer_wire_projection_is_exact_and_non_authoritative() {
        let block_hash = hns_primitives::BlockHash::new([0x33; 32]);
        let coin = Coin {
            outpoint: Outpoint {
                txid: Txid::new([0x22; 32]),
                index: 2,
            },
            value: 4_200,
            height: 41,
            coinbase: false,
            address: Address::new(0, vec![0x55; 20]).expect("address"),
            covenant: Covenant {
                kind: hns_primitives::CovenantKind::Transfer,
                items: vec![vec![0xaa, 0xbb]],
            },
        };
        let page = IncomingTransfersPage {
            projection_version: INCOMING_TRANSFER_PROJECTION_VERSION,
            chain_epoch: 17,
            tip: None,
            entries: vec![crate::wallet_backend::WalletIncomingTransfer {
                script_index: 2,
                entry: hns_wallet_index::IncomingTransferEntry {
                    recipient_version: 0,
                    recipient_hash: vec![0x44; 20],
                    name_hash: [0x11; 32],
                    start_height: 12,
                    coin,
                    block_hash,
                    height: 41,
                    transaction_position: 7,
                },
                source_output_count: 3,
                inclusion: crate::wallet_backend::TransactionInclusion {
                    block_hash,
                    height: 41,
                    transaction_position: Some(7),
                    confirmations: 9,
                },
                source_binding: IncomingTransferSourceBinding::RetainedBodyVerified,
            }],
            script_examinations: 4,
            continuation: None,
        };
        let projected = serde_json::to_value(
            wire_incoming_transfers_page(page).expect("incoming-transfer projection"),
        )
        .expect("serialize incoming-transfer projection");
        assert_eq!(
            projected,
            serde_json::json!({
                "projection_version": 1,
                "chain_epoch": 17,
                "tip": null,
                "entries": [{
                    "script_index": 2,
                    "recipient": {
                        "version": 0,
                        "hash": "44".repeat(20)
                    },
                    "name_hash": "11".repeat(32),
                    "start_height": 12,
                    "transfer_coin": {
                        "outpoint": {
                            "txid": "22".repeat(32),
                            "index": 2
                        },
                        "value": 4_200,
                        "height": 41,
                        "coinbase": false,
                        "address": {
                            "version": 0,
                            "hash": "55".repeat(20)
                        },
                        "covenant": {
                            "kind": hns_primitives::CovenantKind::Transfer.as_u8(),
                            "items": ["aabb"]
                        }
                    },
                    "inclusion": {
                        "block_hash": "33".repeat(32),
                        "height": 41,
                        "transaction_index": 7,
                        "confirmations": 9
                    },
                    "source_output_count": 3,
                    "source_binding": "retained_body_verified"
                }],
                "script_examinations": 4,
                "continuation": null
            })
        );
        assert_eq!(
            wire_incoming_transfer_source_binding(
                IncomingTransferSourceBinding::PrunedTrustedNodeProjection
            ),
            "pruned_trusted_node_projection"
        );
    }

    #[test]
    fn name_action_context_request_is_strict_and_exactly_bound() {
        let request: WalletRpcRequest = serde_json::from_value(serde_json::json!({
            "api_version": 1,
            "request_id": "name-action-1",
            "call": {
                "method": "name_action_context",
                "params": {
                    "action": "finalize",
                    "name_hash": "11".repeat(32),
                    "expected_chain_epoch": 7,
                    "expected_mempool": {
                        "instance_nonce": "22".repeat(32),
                        "generation": 9
                    }
                }
            }
        }))
        .expect("strict name-action request");
        let WalletRpcCall::NameActionContext {
            action,
            name_hash,
            expected_chain_epoch,
            expected_mempool,
        } = request.call
        else {
            panic!("name-action method");
        };
        assert_eq!(action, NameAction::Finalize);
        assert_eq!(name_hash, "11".repeat(32));
        assert_eq!(expected_chain_epoch, 7);
        assert_eq!(expected_mempool.instance_nonce, "22".repeat(32));
        assert_eq!(expected_mempool.generation, 9);

        assert!(
            serde_json::from_value::<WalletRpcRequest>(serde_json::json!({
                "api_version": 1,
                "call": {
                    "method": "name_action_context",
                    "params": {
                        "action": "transfer",
                        "name_hash": "11".repeat(32),
                        "expected_chain_epoch": 7,
                        "expected_mempool": {
                            "instance_nonce": "22".repeat(32),
                            "generation": 9
                        },
                        "unbound_extension": true
                    }
                }
            }))
            .is_err()
        );
    }

    #[test]
    fn name_action_context_v2_request_is_additive_strict_and_exactly_bound() {
        let request: WalletRpcRequest = serde_json::from_value(serde_json::json!({
            "api_version": 1,
            "request_id": "name-action-v2-1",
            "call": {
                "method": "name_action_context_v2",
                "params": {
                    "action": "finalize",
                    "name_hash": "11".repeat(32),
                    "expected_chain_epoch": 7,
                    "expected_mempool": {
                        "instance_nonce": "22".repeat(32),
                        "generation": 9
                    }
                }
            }
        }))
        .expect("strict name-action-v2 request");
        let WalletRpcCall::NameActionContextV2 {
            action,
            name_hash,
            expected_chain_epoch,
            expected_mempool,
        } = request.call
        else {
            panic!("name-action-v2 method");
        };
        assert_eq!(action, NameAction::Finalize);
        assert_eq!(name_hash, "11".repeat(32));
        assert_eq!(expected_chain_epoch, 7);
        assert_eq!(expected_mempool.instance_nonce, "22".repeat(32));
        assert_eq!(expected_mempool.generation, 9);

        for invalid_params in [
            serde_json::json!({
                "action": "finalize",
                "name_hash": "11".repeat(32),
                "expected_chain_epoch": 7
            }),
            serde_json::json!({
                "action": "finalize",
                "name_hash": "11".repeat(32),
                "expected_chain_epoch": 7,
                "expected_mempool": {
                    "instance_nonce": "22".repeat(32),
                    "generation": 9
                },
                "wallet_owned": true
            }),
            serde_json::json!({
                "action": "update",
                "name_hash": "11".repeat(32),
                "expected_chain_epoch": 7,
                "expected_mempool": {
                    "instance_nonce": "22".repeat(32),
                    "generation": 9
                }
            }),
            serde_json::json!({
                "action": "transfer",
                "name_hash": "11".repeat(32),
                "expected_chain_epoch": 7,
                "expected_mempool": {
                    "instance_nonce": "22".repeat(32),
                    "generation": 9,
                    "unbound_extension": true
                }
            }),
        ] {
            assert!(
                serde_json::from_value::<WalletRpcRequest>(serde_json::json!({
                    "api_version": 1,
                    "call": {
                        "method": "name_action_context_v2",
                        "params": invalid_params
                    }
                }))
                .is_err()
            );
        }

        let legacy: WalletRpcRequest = serde_json::from_value(serde_json::json!({
            "api_version": 1,
            "call": {
                "method": "name_action_context",
                "params": {
                    "action": "transfer",
                    "name_hash": "11".repeat(32),
                    "expected_chain_epoch": 7,
                    "expected_mempool": {
                        "instance_nonce": "22".repeat(32),
                        "generation": 9
                    }
                }
            }
        }))
        .expect("legacy name-action request remains valid");
        assert!(matches!(
            legacy.call,
            WalletRpcCall::NameActionContext { .. }
        ));
    }

    #[test]
    fn name_action_context_v2_wire_is_coin_backed_and_contains_no_owner_transaction() {
        let name_hash = hns_primitives::hash_name("alpha").expect("name hash");
        let owner = Outpoint {
            txid: Txid::new([0x22; 32]),
            index: 3,
        };
        let mut current_state = NameState::null(name_hash);
        current_state.name = b"alpha".to_vec();
        current_state.height = 2;
        current_state.renewal = 12;
        current_state.owner = owner.clone();
        current_state.value = 4_200;
        current_state.highest = 4_200;
        current_state.transfer = 41;
        current_state.registered = true;
        let current_state_bytes = encode_name_state(&current_state).expect("name state");
        let owner_coin = Coin {
            outpoint: owner,
            value: 4_200,
            height: 41,
            coinbase: false,
            address: Address::new(0, vec![0x55; 20]).expect("address"),
            covenant: Covenant {
                kind: hns_primitives::CovenantKind::Transfer,
                items: vec![
                    name_hash.as_bytes().to_vec(),
                    2_u32.to_le_bytes().to_vec(),
                    vec![0],
                    vec![0x44; 20],
                ],
            },
        };
        let network = hns_consensus::Network::Regtest;
        let context = NameActionContextV2 {
            context_version: NAME_ACTION_CONTEXT_V2_VERSION,
            action: NameAction::Finalize,
            network,
            network_id: network.canonical_id(),
            genesis_hash: network.params().genesis_hash,
            consensus_profile: hns_consensus::HSD_CONSENSUS_PROFILE.to_owned(),
            chain_epoch: 17,
            tip: crate::wallet_backend::WalletChainTip {
                hash: hns_primitives::BlockHash::new([0x66; 32]),
                height: 400,
                median_time_past: 1_700_000_123,
                tree_root: hns_state::TreeRoot::new([0x77; 32]),
            },
            candidate_inclusion_height: 401,
            mempool_instance_nonce: [0x88; 32],
            mempool_generation: 9,
            owner_spender_txid: None,
            name_hash,
            current_state_bytes: current_state_bytes.clone(),
            current_state: current_state.clone(),
            active_owner: crate::wallet_backend::NameActionActiveOwnerCoin {
                projection_version: ACTIVE_NAME_OWNER_COIN_PROJECTION_VERSION,
                owner_coin,
                inclusion: crate::wallet_backend::TransactionInclusion {
                    block_hash: hns_primitives::BlockHash::new([0x33; 32]),
                    height: 41,
                    transaction_position: None,
                    confirmations: 360,
                },
                source_binding: ActiveNameOwnerCoinSourceBinding::TrustedNodeActiveUtxoProjection,
            },
            lifecycle: NameLifecycleState::Closed,
            transfer: crate::wallet_backend::NameTransferContext {
                lockup_blocks: 288,
                current_transfer_height: Some(41),
                finalize_maturity_height: Some(329),
                finalize_eligible_at_candidate: true,
            },
            renewal: crate::wallet_backend::NameRenewalContext {
                maturity_blocks: 10,
                period_blocks: 50,
                hsd_selected_height: 380,
                hsd_selected_hash: hns_primitives::BlockHash::new([0x99; 32]),
                valid_at_candidate: true,
            },
            ineligibility_reasons: Vec::new(),
        };

        let projected = serde_json::to_value(
            wire_name_action_context_v2(context.clone()).expect("v2 projection"),
        )
        .expect("serialize v2 projection");
        assert_eq!(projected["context_version"], 2);
        assert_eq!(projected["action"], "finalize");
        assert_eq!(projected["chain_epoch"], 17);
        assert_eq!(projected["name_hash"], name_hash.to_hex());
        assert_eq!(
            projected["current_state_hex"],
            hex_encode(&current_state_bytes)
        );
        assert_eq!(projected["active_owner"]["projection_version"], 1);
        assert_eq!(
            projected["active_owner"]["owner_coin"]["outpoint"],
            serde_json::json!({"txid": "22".repeat(32), "index": 3})
        );
        assert_eq!(projected["active_owner"]["owner_coin"]["value"], 4_200);
        assert_eq!(projected["active_owner"]["inclusion"]["height"], 41);
        assert_eq!(
            projected["active_owner"]["inclusion"]["transaction_index"],
            Value::Null
        );
        assert_eq!(
            projected["active_owner"]["source_binding"],
            "trusted_node_active_utxo_projection"
        );
        assert_eq!(
            projected["eligibility"],
            serde_json::json!({
                "eligible": true,
                "reasons": []
            })
        );
        assert!(projected.get("owner").is_none());
        let encoded = serde_json::to_string(&projected).expect("wire JSON");
        assert!(!encoded.contains("transaction_hex"));
        assert!(!encoded.contains("owner_output"));
        assert!(!encoded.contains("wallet_owned"));

        let assert_rejected = |candidate| {
            assert!(matches!(
                wire_name_action_context_v2(candidate),
                Err(DispatchError::Internal)
            ));
        };

        let mut invalid_version = context.clone();
        invalid_version.context_version = NAME_ACTION_CONTEXT_VERSION;
        assert_rejected(invalid_version);
        let mut invalid_projection = context.clone();
        invalid_projection.active_owner.projection_version = 2;
        assert_rejected(invalid_projection);
        let mut invalid_position = context.clone();
        invalid_position.active_owner.inclusion.transaction_position = Some(0);
        assert_rejected(invalid_position);
        let mut invalid_name_hash = context.clone();
        invalid_name_hash.name_hash = NameHash::new([0xbb; 32]);
        assert_rejected(invalid_name_hash);
        let mut invalid_state = context.clone();
        invalid_state.current_state_bytes.push(0);
        assert_rejected(invalid_state);
        let mut invalid_owner = context.clone();
        invalid_owner.active_owner.owner_coin.outpoint.index += 1;
        assert_rejected(invalid_owner);
        let mut invalid_height = context.clone();
        invalid_height.active_owner.inclusion.height += 1;
        assert_rejected(invalid_height);
        let mut excessive_reasons = context;
        excessive_reasons.ineligibility_reasons = vec![
            NameActionIneligibility::NameNotRegistered;
            MAX_NAME_ACTION_INELIGIBILITY_REASONS + 1
        ];
        assert_rejected(excessive_reasons);
    }

    #[tokio::test]
    async fn capabilities_freeze_name_action_v1_and_advertise_pruning_safe_v2() {
        let config = crate::NodeConfig {
            network: hns_consensus::Network::Regtest,
            wallet_index: true,
            ..crate::NodeConfig::default()
        };
        let node = crate::NodeService::try_new(config).expect("node");
        let runtime =
            crate::NodeRuntime::spawn(node, crate::DEFAULT_CANONICAL_WRITER_QUEUE_CAPACITY)
                .expect("runtime");
        let (peers, _events) = hns_p2p::LivePeerManager::new(hns_p2p::LivePeerConfig::for_network(
            hns_consensus::Network::Regtest,
        ))
        .expect("peers");
        let backend = runtime.wallet_backend(peers);
        let capabilities = dispatch_call(&backend, WalletRpcCall::Capabilities)
            .await
            .expect("capabilities");

        assert_eq!(capabilities["name_action_context_version"], 1);
        assert_eq!(
            capabilities["name_action_context_actions"],
            serde_json::json!(["transfer", "finalize"])
        );
        assert_eq!(
            capabilities["name_action_context_binding"],
            "mandatory_chain_epoch_and_exact_mempool_instance_and_generation"
        );
        assert_eq!(
            capabilities["name_action_context_maximum_ineligibility_reasons"],
            9
        );
        assert_eq!(capabilities["name_action_context_v2_version"], 2);
        assert_eq!(
            capabilities["name_action_context_v2_binding"],
            "mandatory_chain_epoch_and_exact_mempool_instance_and_generation"
        );
        assert_eq!(
            capabilities["name_action_context_v2_owner_projection_version"],
            1
        );
        assert_eq!(
            capabilities["name_action_context_v2_owner_source_binding"],
            "trusted_node_active_utxo_projection"
        );
        assert_eq!(
            capabilities["name_action_context_v2_owner_transaction"],
            "not_read_or_returned"
        );
        assert_eq!(
            capabilities["name_action_context_v2_transaction_position"],
            "always_null_no_raw_block_read"
        );
        assert_eq!(
            capabilities["name_action_context_v2_authority"],
            "public_current_state_and_active_utxo_evidence_only_not_wallet_ownership_cryptographic_proof_or_signing_authority"
        );

        drop(backend);
        runtime.shutdown_unclean().await.expect("shutdown");
    }

    #[test]
    fn name_action_wire_vocabulary_and_consensus_profile_are_stable() {
        let reasons = [
            NameActionIneligibility::NameNotRegistered,
            NameActionIneligibility::NameExpiredAtCandidate,
            NameActionIneligibility::LifecycleNotClosed,
            NameActionIneligibility::TransferAlreadyPending,
            NameActionIneligibility::TransferNotPending,
            NameActionIneligibility::TransferNotMature,
            NameActionIneligibility::OwnerCovenantInvalidForAction,
            NameActionIneligibility::RenewalCommitmentInvalid,
            NameActionIneligibility::OwnerSpentInMempool,
        ]
        .map(wire_name_action_ineligibility);
        assert_eq!(reasons.len(), MAX_NAME_ACTION_INELIGIBILITY_REASONS);
        assert_eq!(
            reasons,
            [
                "name_not_registered",
                "name_expired_at_candidate",
                "lifecycle_not_closed",
                "transfer_already_pending",
                "transfer_not_pending",
                "transfer_not_mature",
                "owner_covenant_invalid_for_action",
                "renewal_commitment_invalid",
                "owner_spent_in_mempool",
            ]
        );
        assert_eq!(
            hns_consensus::HSD_CONSENSUS_PROFILE,
            "hns-consensus/name-policy-v1"
        );
    }
}
