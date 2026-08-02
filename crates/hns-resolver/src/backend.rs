use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use hns_rpc::{JsonRpcRequest, JsonRpcResponse, RpcDnsResource};
use reqwest::header::{HeaderValue, AUTHORIZATION};
use serde_json::json;
use tokio::sync::Semaphore;

const MAX_RPC_RESPONSE_BYTES: usize = 16 * 1_024;

#[derive(Debug, thiserror::Error)]
pub enum BackendError {
    #[error("resolver backend is at its concurrency limit")]
    Overloaded,
    #[error("hsrd RPC transport failed: {0}")]
    Transport(#[from] reqwest::Error),
    #[error("hsrd RPC rejected getdnsresource ({code}): {message}")]
    Rpc { code: i64, message: String },
    #[error("hsrd RPC response omitted both result and error")]
    MissingResult,
    #[error("hsrd RPC response exceeds {MAX_RPC_RESPONSE_BYTES} bytes")]
    ResponseTooLarge,
    #[error("invalid getdnsresource response: {0}")]
    InvalidResponse(#[from] serde_json::Error),
    #[error("invalid hsrd JSON-RPC response: {0}")]
    InvalidProtocol(&'static str),
    #[error("invalid hsrd RPC endpoint: {0}")]
    InvalidEndpoint(&'static str),
    #[error("hsrd maximum concurrent requests must be non-zero")]
    InvalidCapacity,
}

#[async_trait]
pub trait NameResourceSource: Send + Sync {
    async fn resource(&self, name: &str) -> Result<RpcDnsResource, BackendError>;
}

#[derive(Clone)]
pub struct HsrdRpcClient {
    endpoint: reqwest::Url,
    authorization: Option<HeaderValue>,
    client: reqwest::Client,
    capacity: Arc<Semaphore>,
}

impl std::fmt::Debug for HsrdRpcClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HsrdRpcClient")
            .field("endpoint", &self.endpoint)
            .field(
                "authorization",
                &self.authorization.as_ref().map(|_| "<redacted>"),
            )
            .field("available_capacity", &self.capacity.available_permits())
            .finish()
    }
}

impl HsrdRpcClient {
    pub fn new(
        endpoint: impl Into<String>,
        authorization: Option<HeaderValue>,
        timeout: Duration,
        maximum_concurrent_requests: usize,
    ) -> Result<Self, BackendError> {
        if maximum_concurrent_requests == 0 {
            return Err(BackendError::InvalidCapacity);
        }
        let endpoint = endpoint.into();
        let endpoint = reqwest::Url::parse(&endpoint)
            .map_err(|_| BackendError::InvalidEndpoint("URL is malformed"))?;
        if endpoint.scheme() != "http" {
            return Err(BackendError::InvalidEndpoint(
                "scheme must be http; keep RPC on a private transport",
            ));
        }
        if !endpoint.username().is_empty() || endpoint.password().is_some() {
            return Err(BackendError::InvalidEndpoint(
                "credentials belong in the authorization header file",
            ));
        }
        let client = reqwest::Client::builder()
            .timeout(timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()?;
        Ok(Self {
            endpoint,
            authorization,
            client,
            capacity: Arc::new(Semaphore::new(maximum_concurrent_requests)),
        })
    }
}

#[async_trait]
impl NameResourceSource for HsrdRpcClient {
    async fn resource(&self, name: &str) -> Result<RpcDnsResource, BackendError> {
        let _permit = Arc::clone(&self.capacity)
            .try_acquire_owned()
            .map_err(|_| BackendError::Overloaded)?;
        let request = JsonRpcRequest {
            jsonrpc: Some("2.0".to_owned()),
            method: "getdnsresource".to_owned(),
            params: json!([name]),
            id: Some(json!("hns-resolverd")),
        };
        let mut builder = self.client.post(self.endpoint.clone()).json(&request);
        if let Some(authorization) = &self.authorization {
            builder = builder.header(AUTHORIZATION, authorization.clone());
        }
        let mut response = builder.send().await?.error_for_status()?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RPC_RESPONSE_BYTES as u64)
        {
            return Err(BackendError::ResponseTooLarge);
        }
        let mut body = Vec::with_capacity(
            response
                .content_length()
                .unwrap_or(0)
                .min(MAX_RPC_RESPONSE_BYTES as u64) as usize,
        );
        while let Some(chunk) = response.chunk().await? {
            let remaining = MAX_RPC_RESPONSE_BYTES.saturating_sub(body.len());
            if chunk.len() > remaining {
                return Err(BackendError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        decode_response(name, &body)
    }
}

fn decode_response(name: &str, body: &[u8]) -> Result<RpcDnsResource, BackendError> {
    let response = serde_json::from_slice::<JsonRpcResponse>(body)?;
    if response.jsonrpc != "2.0" {
        return Err(BackendError::InvalidProtocol("jsonrpc must equal \"2.0\""));
    }
    if response.id.as_ref() != Some(&json!("hns-resolverd")) {
        return Err(BackendError::InvalidProtocol(
            "response id does not match request",
        ));
    }
    if let Some(error) = response.error {
        return Err(BackendError::Rpc {
            code: error.code,
            message: error.message,
        });
    }
    let result = response.result.ok_or(BackendError::MissingResult)?;
    let result = serde_json::from_value::<RpcDnsResource>(result)?;
    if result.name != name {
        return Err(BackendError::InvalidProtocol(
            "resource name does not match request",
        ));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };

    #[test]
    fn client_rejects_invalid_configuration_before_network_use() {
        assert!(matches!(
            HsrdRpcClient::new("http://127.0.0.1:12037/", None, Duration::from_secs(1), 0),
            Err(BackendError::InvalidCapacity)
        ));
        assert!(matches!(
            HsrdRpcClient::new("file:///tmp/hsrd", None, Duration::from_secs(1), 1),
            Err(BackendError::InvalidEndpoint(_))
        ));
        assert!(matches!(
            HsrdRpcClient::new("https://127.0.0.1:12037/", None, Duration::from_secs(1), 1),
            Err(BackendError::InvalidEndpoint(_))
        ));
        assert!(matches!(
            HsrdRpcClient::new(
                "http://secret@127.0.0.1:12037/",
                None,
                Duration::from_secs(1),
                1
            ),
            Err(BackendError::InvalidEndpoint(_))
        ));
    }

    #[tokio::test]
    async fn client_rejects_oversized_rpc_response_before_buffering_it() {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind HTTP fixture");
        let address = listener.local_addr().expect("fixture address");
        let fixture = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept request");
            let mut request = [0; 2_048];
            let _ = stream.read(&mut request).await.expect("read request");
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 16385\r\n\r\n")
                .await
                .expect("write response");
        });
        let client = HsrdRpcClient::new(
            format!("http://{address}/"),
            None,
            Duration::from_secs(1),
            1,
        )
        .expect("client");

        assert!(matches!(
            client.resource("handshake").await,
            Err(BackendError::ResponseTooLarge)
        ));
        fixture.await.expect("fixture task");
    }

    #[test]
    fn response_validation_binds_result_to_request_id_and_name() {
        let response = |id, name| {
            serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": id,
                "result": {
                    "name": name,
                    "resource": null,
                    "context": {
                        "network": "regtest",
                        "active_height": 1,
                        "best_header_height": 1,
                        "active_state_root": "11".repeat(32),
                        "chain_epoch": 1,
                        "synchronized": true
                    }
                }
            }))
            .expect("encode response")
        };

        assert!(decode_response("handshake", &response("hns-resolverd", "handshake")).is_ok());
        assert!(matches!(
            decode_response("handshake", &response("another-client", "handshake")),
            Err(BackendError::InvalidProtocol(_))
        ));
        assert!(matches!(
            decode_response("handshake", &response("hns-resolverd", "wrong-name")),
            Err(BackendError::InvalidProtocol(_))
        ));
    }
}
