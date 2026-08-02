use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use hickory_server::{
    dnssec::NxProofKind,
    net::{runtime::TokioRuntimeProvider, NetError},
    proto::{
        op::{Query, ResponseCode},
        rr::{LowerName, Name, RecordType, TSigResponseContext},
    },
    resolver::{
        config::{ConnectionConfig, ResolverOpts},
        recursor::{DnssecConfig, DnssecPolicy, Recursor, RecursorOptions},
        ConnectionProvider, PoolContext, TtlConfig,
    },
    server::{Request, RequestInfo},
    zone_handler::{
        AuthLookup, AxfrPolicy, Catalog, LookupControlFlow, LookupError, LookupOptions,
        Nsec3QueryInfo, ZoneHandler, ZoneType,
    },
    Server,
};
use hns_rpc::{RpcDnsContext, RpcDnsResource};
use tokio::{
    net::TcpListener,
    net::UdpSocket,
    sync::{RwLock, Semaphore},
};
use tracing::{info, warn};

use crate::{
    dnssec::RootDnssec, HandshakeRoot, IcannLookup, NameResourceSource, ValidatingIcann,
    DEFAULT_ICANN_ROOT_SERVERS,
};

const TCP_RESPONSE_BUFFER_SIZE: usize = 128;

type HnsRecursor = Recursor<InternalRootProvider>;

/// Hickory 0.26 accepts root hints as IP addresses and normally connects to
/// port 53. The Handshake root authority is intentionally private and bound to
/// an ephemeral loopback port, so this provider rewrites only that root-hint
/// endpoint while preserving Hickory's maintained transport implementation.
#[derive(Clone)]
struct InternalRootProvider {
    runtime: TokioRuntimeProvider,
    root_addr: SocketAddr,
}

impl InternalRootProvider {
    fn new(root_addr: SocketAddr) -> Self {
        Self {
            runtime: TokioRuntimeProvider::default(),
            root_addr,
        }
    }
}

impl ConnectionProvider for InternalRootProvider {
    type Conn = <TokioRuntimeProvider as ConnectionProvider>::Conn;
    type FutureConn = <TokioRuntimeProvider as ConnectionProvider>::FutureConn;
    type RuntimeProvider = TokioRuntimeProvider;

    fn new_connection(
        &self,
        ip: IpAddr,
        config: &ConnectionConfig,
        context: &PoolContext,
    ) -> Result<Self::FutureConn, NetError> {
        let mut config = config.clone();
        if ip == self.root_addr.ip() && config.port == 53 {
            config.port = self.root_addr.port();
        }
        self.runtime.new_connection(ip, &config, context)
    }

    fn runtime_provider(&self) -> &Self::RuntimeProvider {
        &self.runtime
    }
}

#[derive(Clone, Debug)]
pub struct ResolverConfig {
    pub listen: SocketAddr,
    pub require_synchronized: bool,
    pub maximum_concurrent_queries: usize,
    pub name_server_cache_size: usize,
    pub record_cache_size: usize,
    pub maximum_positive_ttl: Duration,
    pub maximum_negative_ttl: Duration,
    pub recursion_limit: u8,
    pub name_server_recursion_limit: u8,
    pub deny_private_name_servers: bool,
    pub tcp_request_timeout: Duration,
    pub chain_state_poll_interval: Duration,
    pub icann_fallback: bool,
    pub icann_root_servers: Vec<IpAddr>,
    pub icann_timeout: Duration,
    pub icann_maximum_concurrent_queries: usize,
    pub icann_cache_size: usize,
}

impl Default for ResolverConfig {
    fn default() -> Self {
        Self {
            listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 5350)),
            require_synchronized: true,
            maximum_concurrent_queries: 256,
            name_server_cache_size: 1_024,
            // Hickory defaults to over one million entries. A local Handshake
            // edge resolver should have an explicit, much smaller envelope.
            record_cache_size: 32_768,
            // Handshake resources advertise a six-hour TTL for compatibility.
            // A local edge resolver rechecks its own cache more frequently so
            // resource updates and shallow reorgs do not remain stale for six
            // hours inside the daemon.
            maximum_positive_ttl: Duration::from_secs(30 * 60),
            maximum_negative_ttl: Duration::from_secs(5 * 60),
            recursion_limit: 12,
            name_server_recursion_limit: 16,
            deny_private_name_servers: true,
            tcp_request_timeout: Duration::from_secs(10),
            chain_state_poll_interval: Duration::from_secs(1),
            icann_fallback: true,
            icann_root_servers: DEFAULT_ICANN_ROOT_SERVERS.to_vec(),
            icann_timeout: Duration::from_secs(3),
            icann_maximum_concurrent_queries: 16,
            icann_cache_size: 4_096,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ChainIdentity {
    network: String,
    active_height: Option<u32>,
    active_state_root: Option<String>,
    chain_epoch: u64,
}

impl From<&RpcDnsContext> for ChainIdentity {
    fn from(context: &RpcDnsContext) -> Self {
        Self {
            network: context.network.clone(),
            active_height: context.active_height,
            active_state_root: context.active_state_root.clone(),
            chain_epoch: context.chain_epoch,
        }
    }
}

#[derive(Debug)]
struct ChainGate {
    ready: AtomicBool,
    generation: AtomicU64,
}

impl ChainGate {
    fn new(initial: Option<&RpcDnsResource>, require_synchronized: bool) -> Self {
        let ready =
            initial.is_some_and(|response| !require_synchronized || response.context.synchronized);
        Self {
            ready: AtomicBool::new(ready),
            generation: AtomicU64::new(u64::from(initial.is_some())),
        }
    }
}

pub struct ResolverRuntime {
    pub listen_addr: SocketAddr,
    pub internal_root_addr: SocketAddr,
    root: Server<HandshakeRoot>,
    public: Server<Catalog>,
    source: Arc<dyn NameResourceSource>,
    recursor: Arc<RwLock<Arc<HnsRecursor>>>,
    gate: Arc<ChainGate>,
    config: ResolverConfig,
    initial_identity: Option<ChainIdentity>,
}

impl ResolverRuntime {
    pub async fn bind(
        source: Arc<dyn NameResourceSource>,
        config: ResolverConfig,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            config.maximum_concurrent_queries > 0,
            "maximum concurrent queries must be non-zero"
        );
        anyhow::ensure!(
            config.name_server_cache_size > 0 && config.record_cache_size > 0,
            "resolver cache sizes must be non-zero"
        );
        anyhow::ensure!(
            !config.maximum_positive_ttl.is_zero() && !config.maximum_negative_ttl.is_zero(),
            "resolver cache TTL limits must be non-zero"
        );
        anyhow::ensure!(
            !config.chain_state_poll_interval.is_zero(),
            "chain-state poll interval must be non-zero"
        );
        if config.icann_fallback {
            anyhow::ensure!(
                !config.icann_root_servers.is_empty(),
                "ICANN fallback requires at least one root server"
            );
        }

        let initial = match source.resource("a").await {
            Ok(response) => Some(response),
            Err(error) => {
                warn!(%error, "initial hsrd chain-state probe failed; DNS starts fail closed");
                None
            }
        };
        let initial_identity = initial
            .as_ref()
            .map(|response| ChainIdentity::from(&response.context));
        let gate = Arc::new(ChainGate::new(
            initial.as_ref(),
            config.require_synchronized,
        ));

        let root_tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let internal_root_addr = root_tcp.local_addr()?;
        let root_udp = UdpSocket::bind(internal_root_addr).await?;
        let mut root_handler = HandshakeRoot::new(Arc::clone(&source), config.require_synchronized);
        if config.icann_fallback {
            let icann: Arc<dyn IcannLookup> = Arc::new(ValidatingIcann::new(
                &config.icann_root_servers,
                config.icann_timeout,
                config.icann_maximum_concurrent_queries,
                config.icann_cache_size,
            )?);
            root_handler = root_handler.with_icann(icann);
        }
        let mut root = Server::new(root_handler);
        root.register_socket(root_udp);
        root.register_listener(
            root_tcp,
            config.tcp_request_timeout,
            TCP_RESPONSE_BUFFER_SIZE,
        );

        let recursor = Arc::new(build_recursor(internal_root_addr, &config)?);
        let recursor = Arc::new(RwLock::new(recursor));
        let authority = RecursiveAuthority {
            origin: LowerName::from(Name::root()),
            recursor: Arc::clone(&recursor),
            capacity: Arc::new(Semaphore::new(config.maximum_concurrent_queries)),
            gate: Arc::clone(&gate),
        };
        let mut catalog = Catalog::new();
        catalog.upsert(
            LowerName::from(Name::root()),
            vec![Arc::new(authority) as Arc<dyn ZoneHandler>],
        );

        let public_tcp = TcpListener::bind(config.listen).await?;
        let listen_addr = public_tcp.local_addr()?;
        let public_udp = UdpSocket::bind(listen_addr).await?;
        let mut public = Server::new(catalog);
        public.register_socket(public_udp);
        public.register_listener(
            public_tcp,
            config.tcp_request_timeout,
            TCP_RESPONSE_BUFFER_SIZE,
        );

        Ok(Self {
            listen_addr,
            internal_root_addr,
            root,
            public,
            source,
            recursor,
            gate,
            config,
            initial_identity,
        })
    }

    pub async fn serve_until(
        mut self,
        shutdown: impl Future<Output = ()> + Send,
    ) -> anyhow::Result<()> {
        info!(listen = %self.listen_addr, "hns-resolverd listening on UDP and TCP");
        info!(root = %self.internal_root_addr, "internal Handshake root authority ready");
        let monitor = monitor_chain_state(
            Arc::clone(&self.source),
            Arc::clone(&self.recursor),
            Arc::clone(&self.gate),
            self.internal_root_addr,
            self.config.clone(),
            self.initial_identity.clone(),
        );
        tokio::pin!(monitor);
        tokio::pin!(shutdown);
        let result = tokio::select! {
            result = self.root.block_until_done() => result.map_err(anyhow::Error::from),
            result = self.public.block_until_done() => result.map_err(anyhow::Error::from),
            result = &mut monitor => result,
            () = &mut shutdown => Ok(()),
        };
        let public_shutdown = self.public.shutdown_gracefully().await;
        let root_shutdown = self.root.shutdown_gracefully().await;
        result?;
        public_shutdown?;
        root_shutdown?;
        Ok(())
    }
}

fn build_recursor(
    internal_root_addr: SocketAddr,
    config: &ResolverConfig,
) -> anyhow::Result<HnsRecursor> {
    let mut resolver_options = ResolverOpts::default();
    resolver_options.positive_max_ttl = Some(config.maximum_positive_ttl);
    resolver_options.negative_max_ttl = Some(config.maximum_negative_ttl);
    let mut options = RecursorOptions {
        ns_cache_size: config.name_server_cache_size,
        response_cache_size: u64::try_from(config.record_cache_size)
            .map_err(|_| anyhow::anyhow!("resolver record cache size exceeds u64"))?,
        recursion_limit: config.recursion_limit,
        ns_recursion_limit: config.name_server_recursion_limit,
        cache_policy: TtlConfig::from_opts(&resolver_options),
        case_randomization: true,
        ..RecursorOptions::default()
    };
    if !config.deny_private_name_servers {
        options.deny_server.clear();
    }
    let mut dnssec = DnssecConfig::default();
    dnssec.trust_anchor = Some(RootDnssec::trust_anchors());
    Recursor::new(
        &[internal_root_addr.ip()],
        DnssecPolicy::ValidateWithStaticKey(dnssec),
        None,
        options,
        InternalRootProvider::new(internal_root_addr),
    )
    .map_err(anyhow::Error::from)
}

async fn monitor_chain_state(
    source: Arc<dyn NameResourceSource>,
    recursor: Arc<RwLock<Arc<HnsRecursor>>>,
    gate: Arc<ChainGate>,
    internal_root_addr: SocketAddr,
    config: ResolverConfig,
    mut identity: Option<ChainIdentity>,
) -> anyhow::Result<()> {
    loop {
        tokio::time::sleep(config.chain_state_poll_interval).await;
        let response = match source.resource("a").await {
            Ok(response) => response,
            Err(error) => {
                if gate.ready.swap(false, Ordering::AcqRel) {
                    warn!(%error, "hsrd chain-state probe failed; DNS is fail closed");
                }
                continue;
            }
        };
        let next_identity = ChainIdentity::from(&response.context);
        if identity.as_ref() != Some(&next_identity) {
            gate.ready.store(false, Ordering::Release);
            let replacement = Arc::new(build_recursor(internal_root_addr, &config)?);
            *recursor.write().await = replacement;
            identity = Some(next_identity);
            gate.generation.fetch_add(1, Ordering::AcqRel);
            info!(
                network = %response.context.network,
                active_height = ?response.context.active_height,
                chain_epoch = response.context.chain_epoch,
                "hsrd chain generation changed; recursive caches replaced"
            );
        }
        gate.ready.store(
            !config.require_synchronized || response.context.synchronized,
            Ordering::Release,
        );
    }
}

struct RecursiveAuthority {
    origin: LowerName,
    recursor: Arc<RwLock<Arc<HnsRecursor>>>,
    capacity: Arc<Semaphore>,
    gate: Arc<ChainGate>,
}

#[async_trait]
impl ZoneHandler for RecursiveAuthority {
    fn zone_type(&self) -> ZoneType {
        ZoneType::External
    }

    fn axfr_policy(&self) -> AxfrPolicy {
        AxfrPolicy::Deny
    }

    fn can_validate_dnssec(&self) -> bool {
        true
    }

    fn origin(&self) -> &LowerName {
        &self.origin
    }

    async fn lookup(
        &self,
        name: &LowerName,
        record_type: RecordType,
        _request_info: Option<&RequestInfo<'_>>,
        lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        if !self.gate.ready.load(Ordering::Acquire) {
            return LookupControlFlow::Continue(Err(LookupError::ResponseCode(
                ResponseCode::ServFail,
            )));
        }
        let Ok(_permit) = Arc::clone(&self.capacity).try_acquire_owned() else {
            return LookupControlFlow::Continue(Err(LookupError::ResponseCode(
                ResponseCode::ServFail,
            )));
        };
        let generation = self.gate.generation.load(Ordering::Acquire);
        let recursor = {
            let current = self.recursor.read().await;
            Arc::clone(&current)
        };
        let query = Query::query(name.into(), record_type);
        let result = recursor
            .resolve(query, Instant::now(), lookup_options.dnssec_ok)
            .await;
        if !self.gate.ready.load(Ordering::Acquire)
            || self.gate.generation.load(Ordering::Acquire) != generation
        {
            return LookupControlFlow::Continue(Err(LookupError::ResponseCode(
                ResponseCode::ServFail,
            )));
        }
        match result {
            Ok(response) => LookupControlFlow::Continue(Ok(AuthLookup::Response(response))),
            Err(error) => LookupControlFlow::Continue(Err(LookupError::from(error))),
        }
    }

    async fn search(
        &self,
        request: &Request,
        lookup_options: LookupOptions,
    ) -> (LookupControlFlow<AuthLookup>, Option<TSigResponseContext>) {
        let request_info = match request.request_info() {
            Ok(info) => info,
            Err(error) => return (LookupControlFlow::Break(Err(error)), None),
        };
        (
            self.lookup(
                request_info.query.name(),
                request_info.query.query_type(),
                Some(&request_info),
                lookup_options,
            )
            .await,
            None,
        )
    }

    async fn nsec_records(
        &self,
        _name: &LowerName,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        LookupControlFlow::Continue(Err(LookupError::ResponseCode(ResponseCode::NotImp)))
    }

    async fn nsec3_records(
        &self,
        _info: Nsec3QueryInfo<'_>,
        _lookup_options: LookupOptions,
    ) -> LookupControlFlow<AuthLookup> {
        LookupControlFlow::Continue(Err(LookupError::ResponseCode(ResponseCode::NotImp)))
    }

    fn nx_proof_kind(&self) -> Option<&NxProofKind> {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BackendError;
    use hickory_server::proto::op::{Message, MessageType, OpCode};
    use hns_rpc::{RpcDnsContext, RpcDnsResource};
    use std::sync::atomic::AtomicU64;
    use tokio::{sync::oneshot, time::timeout};

    struct MissingSource;

    #[async_trait]
    impl NameResourceSource for MissingSource {
        async fn resource(&self, name: &str) -> Result<RpcDnsResource, BackendError> {
            Ok(RpcDnsResource {
                name: name.to_owned(),
                resource: None,
                context: RpcDnsContext {
                    network: "regtest".to_owned(),
                    active_height: Some(7),
                    best_header_height: Some(7),
                    active_state_root: Some("22".repeat(32)),
                    chain_epoch: 4,
                    synchronized: true,
                },
            })
        }
    }

    struct MutableSource {
        state: AtomicU64,
        probes: AtomicU64,
        missing_lookups: AtomicU64,
    }

    #[async_trait]
    impl NameResourceSource for MutableSource {
        async fn resource(&self, name: &str) -> Result<RpcDnsResource, BackendError> {
            if name == "missing" {
                self.missing_lookups.fetch_add(1, Ordering::Relaxed);
            }
            let state = self.state.load(Ordering::Acquire);
            let (epoch, synchronized) = match state {
                1 => (1, true),
                2 => (1, false),
                3 => (2, true),
                _ => panic!("invalid mutable source state"),
            };
            if name == "a" {
                self.probes.fetch_add(1, Ordering::Release);
            }
            Ok(RpcDnsResource {
                name: name.to_owned(),
                resource: None,
                context: RpcDnsContext {
                    network: "regtest".to_owned(),
                    active_height: Some(epoch as u32),
                    best_header_height: Some(epoch as u32 + u32::from(!synchronized)),
                    active_state_root: Some(format!("{epoch:064x}")),
                    chain_epoch: epoch,
                    synchronized,
                },
            })
        }
    }

    async fn udp_response(listen: SocketAddr, id: u16) -> Message {
        udp_query(listen, id, "missing.", RecordType::A).await
    }

    async fn udp_query(
        listen: SocketAddr,
        id: u16,
        name: &str,
        record_type: RecordType,
    ) -> Message {
        let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .expect("bind client");
        let mut query = Message::new(id, MessageType::Query, OpCode::Query);
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(
            Name::from_ascii(name).expect("query name"),
            record_type,
        ));
        socket
            .send_to(&query.to_vec().expect("encode query"), listen)
            .await
            .expect("send query");
        let mut buffer = [0; 1_232];
        let (length, _) = timeout(Duration::from_secs(10), socket.recv_from(&mut buffer))
            .await
            .expect("DNS response timeout")
            .expect("receive response");
        Message::from_vec(&buffer[..length]).expect("decode response")
    }

    async fn wait_for_probe_after(source: &MutableSource, previous: u64) {
        for _ in 0..50 {
            if source.probes.load(Ordering::Acquire) > previous {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        panic!("chain-state monitor did not complete another probe");
    }

    #[tokio::test]
    async fn udp_daemon_recurses_through_the_hsrd_backed_root() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("hickory_recursor=trace,hickory_server=debug,hns_resolver=trace")
            .with_test_writer()
            .try_init();
        let runtime = ResolverRuntime::bind(
            Arc::new(MissingSource),
            ResolverConfig {
                listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                maximum_concurrent_queries: 4,
                name_server_cache_size: 8,
                record_cache_size: 32,
                ..ResolverConfig::default()
            },
        )
        .await
        .expect("bind resolver");
        let listen = runtime.listen_addr;
        let (shutdown_send, shutdown_receive) = oneshot::channel();
        let server = tokio::spawn(runtime.serve_until(async {
            let _ = shutdown_receive.await;
        }));

        let response = udp_response(listen, 77).await;

        assert_eq!(response.id, 77);
        assert_eq!(response.response_code, ResponseCode::NXDomain);
        assert!(response.recursion_available);
        shutdown_send.send(()).expect("request shutdown");
        timeout(Duration::from_secs(3), server)
            .await
            .expect("resolver shutdown timeout")
            .expect("resolver task")
            .expect("graceful resolver shutdown");
    }

    #[tokio::test]
    async fn synchronization_gate_and_chain_generation_invalidate_cached_answers() {
        let source = Arc::new(MutableSource {
            state: AtomicU64::new(1),
            probes: AtomicU64::new(0),
            missing_lookups: AtomicU64::new(0),
        });
        let runtime = ResolverRuntime::bind(
            source.clone(),
            ResolverConfig {
                listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                chain_state_poll_interval: Duration::from_millis(10),
                maximum_concurrent_queries: 4,
                name_server_cache_size: 8,
                record_cache_size: 32,
                ..ResolverConfig::default()
            },
        )
        .await
        .expect("bind resolver");
        let listen = runtime.listen_addr;
        let (shutdown_send, shutdown_receive) = oneshot::channel();
        let server = tokio::spawn(runtime.serve_until(async {
            let _ = shutdown_receive.await;
        }));

        assert_eq!(
            udp_response(listen, 78).await.response_code,
            ResponseCode::NXDomain
        );
        assert_eq!(source.missing_lookups.load(Ordering::Relaxed), 1);

        source.state.store(2, Ordering::Release);
        let probes = source.probes.load(Ordering::Acquire);
        wait_for_probe_after(&source, probes).await;
        assert_eq!(
            udp_response(listen, 79).await.response_code,
            ResponseCode::ServFail
        );
        assert_eq!(source.missing_lookups.load(Ordering::Relaxed), 1);

        source.state.store(3, Ordering::Release);
        let probes = source.probes.load(Ordering::Acquire);
        wait_for_probe_after(&source, probes).await;
        assert_eq!(
            udp_response(listen, 80).await.response_code,
            ResponseCode::NXDomain
        );
        assert_eq!(source.missing_lookups.load(Ordering::Relaxed), 2);

        shutdown_send.send(()).expect("request shutdown");
        timeout(Duration::from_secs(3), server)
            .await
            .expect("resolver shutdown timeout")
            .expect("resolver task")
            .expect("graceful resolver shutdown");
    }

    #[tokio::test]
    #[ignore = "requires live ICANN DNS connectivity"]
    async fn udp_daemon_resolves_through_validated_icann_fallback() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter("hickory_resolver=info,hickory_server=info,hns_resolver=trace")
            .with_test_writer()
            .try_init();
        let runtime = ResolverRuntime::bind(
            Arc::new(MissingSource),
            ResolverConfig {
                listen: SocketAddr::from((Ipv4Addr::LOCALHOST, 0)),
                maximum_concurrent_queries: 8,
                name_server_cache_size: 64,
                record_cache_size: 256,
                icann_timeout: Duration::from_secs(5),
                ..ResolverConfig::default()
            },
        )
        .await
        .expect("bind resolver");
        let listen = runtime.listen_addr;
        let (shutdown_send, shutdown_receive) = oneshot::channel();
        let server = tokio::spawn(runtime.serve_until(async {
            let _ = shutdown_receive.await;
        }));

        let response = udp_query(listen, 81, "example.com.", RecordType::A).await;
        assert_eq!(response.response_code, ResponseCode::NoError);
        assert!(response
            .answers
            .iter()
            .any(|record| record.record_type() == RecordType::A));

        shutdown_send.send(()).expect("request shutdown");
        timeout(Duration::from_secs(3), server)
            .await
            .expect("resolver shutdown timeout")
            .expect("resolver task")
            .expect("graceful resolver shutdown");
    }
}
