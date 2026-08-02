#![forbid(unsafe_code)]

mod backend;
mod recursor;
mod root;

pub use backend::{BackendError, HsrdRpcClient, NameResourceSource};
pub use recursor::{ResolverConfig, ResolverRuntime};
pub use root::{HandshakeRoot, RootAnswer, DEFAULT_RESOURCE_TTL};
