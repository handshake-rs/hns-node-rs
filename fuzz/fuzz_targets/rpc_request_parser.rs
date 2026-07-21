#![no_main]

use hns_rpc::{JsonRpcRequest, RpcMethod};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(request) = serde_json::from_slice::<JsonRpcRequest>(data) {
        let _ = RpcMethod::from_hsd_name(&request.method);
    }
});
