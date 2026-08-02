#![forbid(unsafe_code)]

mod backend;
mod dnssec;
mod icann;
mod recursor;
mod root;

pub use backend::{BackendError, HsrdRpcClient, NameResourceSource};
pub use icann::{
    IcannError, IcannLookup, IcannReferral, ValidatingIcann, DEFAULT_ICANN_ROOT_SERVERS,
};
pub use recursor::{ResolverConfig, ResolverRuntime};
pub use root::{HandshakeRoot, RootAnswer, DEFAULT_RESOURCE_TTL};
