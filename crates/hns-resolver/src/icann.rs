use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use hickory_server::{
    net::runtime::TokioRuntimeProvider,
    proto::{
        dnssec::Proof,
        op::{Message, Query},
        rr::{Name, RData, Record, RecordType},
    },
    resolver::{
        config::ResolverOpts,
        recursor::{DnssecConfig, DnssecPolicy, Recursor, RecursorOptions},
        TtlConfig,
    },
};
use tokio::{sync::Semaphore, task::JoinSet};

const MAX_REFERRAL_RECORDS: usize = 256;
const MAX_ROOT_SERVERS: usize = 64;
const MAX_NAME_SERVERS: usize = 32;
const MAX_GLUE_NAME_SERVERS: usize = 4;

/// Current InterNIC root hints. Operators can override this list without
/// rebuilding; it is deliberately kept independent of the OS resolver.
pub const DEFAULT_ICANN_ROOT_SERVERS: [IpAddr; 13] = [
    IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4)),
    IpAddr::V4(Ipv4Addr::new(170, 247, 170, 2)),
    IpAddr::V4(Ipv4Addr::new(192, 33, 4, 12)),
    IpAddr::V4(Ipv4Addr::new(199, 7, 91, 13)),
    IpAddr::V4(Ipv4Addr::new(192, 203, 230, 10)),
    IpAddr::V4(Ipv4Addr::new(192, 5, 5, 241)),
    IpAddr::V4(Ipv4Addr::new(192, 112, 36, 4)),
    IpAddr::V4(Ipv4Addr::new(198, 97, 190, 53)),
    IpAddr::V4(Ipv4Addr::new(192, 36, 148, 17)),
    IpAddr::V4(Ipv4Addr::new(192, 58, 128, 30)),
    IpAddr::V4(Ipv4Addr::new(193, 0, 14, 129)),
    IpAddr::V4(Ipv4Addr::new(199, 7, 83, 42)),
    IpAddr::V4(Ipv4Addr::new(202, 12, 27, 33)),
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IcannReferral {
    pub name_servers: Vec<Record>,
    pub delegation_signers: Vec<Record>,
    pub glue: Vec<Record>,
}

#[derive(Debug, thiserror::Error)]
pub enum IcannError {
    #[error("ICANN root query failed: {0}")]
    Query(String),
    #[error("ICANN root query timed out")]
    Timeout,
    #[error("ICANN root query capacity exhausted")]
    Capacity,
    #[error("ICANN root returned an invalid referral: {0}")]
    Invalid(&'static str),
}

#[async_trait]
pub trait IcannLookup: Send + Sync {
    async fn referral(&self, tld: &Name) -> Result<IcannReferral, IcannError>;
}

pub struct ValidatingIcann {
    recursor: Arc<Recursor<TokioRuntimeProvider>>,
    capacity: Arc<Semaphore>,
    timeout: Duration,
}

impl ValidatingIcann {
    pub fn new(
        root_servers: &[IpAddr],
        timeout: Duration,
        maximum_concurrent_queries: usize,
        cache_size: usize,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(!root_servers.is_empty(), "ICANN root server list is empty");
        anyhow::ensure!(
            root_servers.len() <= MAX_ROOT_SERVERS,
            "ICANN root server list exceeds {MAX_ROOT_SERVERS} addresses"
        );
        anyhow::ensure!(
            maximum_concurrent_queries > 0,
            "ICANN query concurrency must be non-zero"
        );
        anyhow::ensure!(cache_size > 0, "ICANN referral cache must be non-zero");
        anyhow::ensure!(!timeout.is_zero(), "ICANN query timeout must be non-zero");

        let root_servers = root_servers
            .iter()
            .copied()
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let mut resolver_options = ResolverOpts::default();
        resolver_options.positive_max_ttl = Some(Duration::from_secs(30 * 60));
        resolver_options.negative_max_ttl = Some(Duration::from_secs(5 * 60));
        let options = RecursorOptions {
            ns_cache_size: (cache_size / 4).max(1),
            response_cache_size: u64::try_from(cache_size)
                .map_err(|_| anyhow::anyhow!("ICANN cache size exceeds u64"))?,
            recursion_limit: 12,
            ns_recursion_limit: 16,
            cache_policy: TtlConfig::from_opts(&resolver_options),
            case_randomization: true,
            ..RecursorOptions::default()
        };
        let mut dnssec = DnssecConfig::default();
        // Hickory's default anchors contain both IANA KSK-2017 and the
        // pre-published KSK-2024 rollover key.
        dnssec.trust_anchor = None;
        let recursor = Recursor::new(
            &root_servers,
            DnssecPolicy::ValidateWithStaticKey(dnssec),
            None,
            options,
            TokioRuntimeProvider::default(),
        )
        .map_err(|error| anyhow::anyhow!("could not build ICANN recursor: {error}"))?;
        Ok(Self {
            recursor: Arc::new(recursor),
            capacity: Arc::new(Semaphore::new(maximum_concurrent_queries)),
            timeout,
        })
    }

    pub fn production(
        timeout: Duration,
        maximum_concurrent_queries: usize,
        cache_size: usize,
    ) -> anyhow::Result<Self> {
        Self::new(
            &DEFAULT_ICANN_ROOT_SERVERS,
            timeout,
            maximum_concurrent_queries,
            cache_size,
        )
    }
}

#[async_trait]
impl IcannLookup for ValidatingIcann {
    async fn referral(&self, tld: &Name) -> Result<IcannReferral, IcannError> {
        if tld.is_root() || tld.num_labels() != 1 {
            return Err(IcannError::Invalid("query is not a TLD"));
        }
        let _permit = Arc::clone(&self.capacity)
            .try_acquire_owned()
            .map_err(|_| IcannError::Capacity)?;
        tokio::time::timeout(self.timeout, self.resolve_referral(tld))
            .await
            .map_err(|_| IcannError::Timeout)?
    }
}

impl ValidatingIcann {
    async fn resolve_referral(&self, tld: &Name) -> Result<IcannReferral, IcannError> {
        let ns_lookup = self.resolve(tld, RecordType::NS).await?;
        let name_servers = ns_lookup
            .answers
            .iter()
            .filter(|record| record.name == *tld && record.record_type() == RecordType::NS)
            .cloned()
            .collect::<Vec<_>>();
        if name_servers.is_empty() || name_servers.len() > MAX_NAME_SERVERS {
            return Err(IcannError::Invalid("invalid authoritative TLD NS RRset"));
        }
        if name_servers
            .iter()
            .any(|record| matches!(record.proof, Proof::Bogus | Proof::Indeterminate))
        {
            return Err(IcannError::Invalid("TLD NS RRset was not validated"));
        }

        let (delegation_signers, authenticated_no_ds) = match self
            .recursor
            .resolve(
                Query::query(tld.clone(), RecordType::DS),
                Instant::now(),
                true,
            )
            .await
        {
            Ok(lookup) => {
                let records = lookup
                    .answers
                    .iter()
                    .filter(|record| record.name == *tld && record.record_type() == RecordType::DS)
                    .cloned()
                    .collect::<Vec<_>>();
                if records.is_empty() {
                    return Err(IcannError::Invalid("empty ICANN DS answer"));
                }
                (records, false)
            }
            Err(error) if error.is_no_records_found() && !error.is_nx_domain() => {
                // A validating Recursor returns NODATA only after its IANA
                // chain has authenticated the NSEC/NSEC3 denial.
                (Vec::new(), true)
            }
            Err(error) => return Err(IcannError::Query(error.to_string())),
        };

        let mut targets = name_servers
            .iter()
            .filter_map(|record| match &record.data {
                RData::NS(target) => Some(target.0.clone()),
                _ => None,
            })
            .collect::<HashSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        targets.sort_unstable();
        targets.truncate(MAX_GLUE_NAME_SERVERS);
        let mut lookups = JoinSet::new();
        for target in targets {
            for record_type in [RecordType::A, RecordType::AAAA] {
                let recursor = Arc::clone(&self.recursor);
                let target = target.clone();
                lookups.spawn(async move {
                    recursor
                        .resolve(Query::query(target, record_type), Instant::now(), true)
                        .await
                });
            }
        }
        let mut glue = Vec::new();
        while let Some(result) = lookups.join_next().await {
            if let Ok(Ok(lookup)) = result {
                glue.extend(
                    lookup
                        .answers
                        .iter()
                        .filter(|record| {
                            matches!(record.record_type(), RecordType::A | RecordType::AAAA)
                        })
                        .cloned(),
                );
            }
        }

        validate_referral(
            tld,
            name_servers,
            delegation_signers,
            glue,
            authenticated_no_ds,
        )
    }

    async fn resolve(&self, name: &Name, record_type: RecordType) -> Result<Message, IcannError> {
        self.recursor
            .resolve(
                Query::query(name.clone(), record_type),
                Instant::now(),
                true,
            )
            .await
            .map_err(|error| IcannError::Query(error.to_string()))
    }
}

fn validate_referral(
    tld: &Name,
    name_servers: Vec<Record>,
    delegation_signers: Vec<Record>,
    glue: Vec<Record>,
    authenticated_no_ds: bool,
) -> Result<IcannReferral, IcannError> {
    let record_count = name_servers.len() + delegation_signers.len() + glue.len();
    if record_count > MAX_REFERRAL_RECORDS {
        return Err(IcannError::Invalid("referral exceeds the record limit"));
    }

    let mut targets = HashSet::new();
    for record in &name_servers {
        if record.name != *tld || record.record_type() != RecordType::NS {
            return Err(IcannError::Invalid(
                "referral NS owner does not match the TLD",
            ));
        }
        let RData::NS(target) = &record.data else {
            return Err(IcannError::Invalid("referral contains malformed NS data"));
        };
        targets.insert(target.0.clone());
        if matches!(record.proof, Proof::Bogus | Proof::Indeterminate) {
            return Err(IcannError::Invalid("TLD NS RRset was not validated"));
        }
    }
    if name_servers.is_empty() {
        return Err(IcannError::Invalid("referral has an empty NS RRset"));
    }

    if delegation_signers.is_empty() {
        if !authenticated_no_ds {
            return Err(IcannError::Invalid(
                "unsigned delegation lacks authenticated denial of DS",
            ));
        }
    } else if delegation_signers.iter().any(|record| {
        record.name != *tld
            || record.record_type() != RecordType::DS
            || record.proof != Proof::Secure
    }) {
        return Err(IcannError::Invalid("delegation DS RRset is not secure"));
    }

    let glue = glue
        .into_iter()
        .filter(|record| {
            targets.contains(&record.name)
                && matches!(record.record_type(), RecordType::A | RecordType::AAAA)
                && matches!(record.proof, Proof::Secure | Proof::Insecure)
        })
        .collect();

    Ok(IcannReferral {
        name_servers,
        delegation_signers,
        glue,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_server::proto::{
        dnssec::{rdata::DNSSECRData, rdata::DS, Algorithm, DigestType},
        rr::rdata::{A, NS},
    };

    fn referral_records() -> (Name, Vec<Record>, Vec<Record>) {
        let owner = Name::from_ascii("com.").expect("owner");
        let target = Name::from_ascii("a.gtld-servers.net.").expect("target");
        let mut ns = Record::from_rdata(owner.clone(), 86_400, RData::NS(NS(target.clone())));
        ns.proof = Proof::Secure;
        let mut glue = Record::from_rdata(target, 86_400, RData::A(A::new(192, 5, 6, 30)));
        glue.proof = Proof::Secure;
        (owner, vec![ns], vec![glue])
    }

    #[test]
    fn production_root_hints_have_distinct_addresses() {
        let unique = DEFAULT_ICANN_ROOT_SERVERS
            .iter()
            .copied()
            .collect::<std::collections::HashSet<_>>();
        assert_eq!(unique.len(), 13);
    }

    #[test]
    fn authenticated_denial_of_ds_accepts_an_unsigned_delegation() {
        let (owner, ns, glue) = referral_records();
        let referral =
            validate_referral(&owner, ns, Vec::new(), glue, true).expect("secure referral");
        assert_eq!(referral.name_servers.len(), 1);
        assert!(referral.delegation_signers.is_empty());
        assert_eq!(referral.glue.len(), 1);
    }

    #[test]
    fn insecure_denial_of_ds_is_rejected() {
        let (owner, ns, glue) = referral_records();
        assert!(matches!(
            validate_referral(&owner, ns, Vec::new(), glue, false),
            Err(IcannError::Invalid(
                "unsigned delegation lacks authenticated denial of DS"
            ))
        ));
    }

    #[test]
    fn bogus_delegation_signer_is_rejected() {
        let (owner, ns, glue) = referral_records();
        let mut ds = Record::from_rdata(
            owner.clone(),
            86_400,
            RData::DNSSEC(DNSSECRData::DS(DS::new(
                12_345,
                Algorithm::ECDSAP256SHA256,
                DigestType::SHA256,
                vec![7; 32],
            ))),
        );
        ds.proof = Proof::Bogus;
        assert!(matches!(
            validate_referral(&owner, ns, vec![ds], glue, false),
            Err(IcannError::Invalid("delegation DS RRset is not secure"))
        ));
    }

    #[tokio::test]
    #[ignore = "requires live ICANN root connectivity"]
    async fn live_com_referral_validates_from_iana_trust_anchors() {
        let client =
            ValidatingIcann::production(Duration::from_secs(5), 2, 64).expect("ICANN client");
        let referral = client
            .referral(&Name::from_ascii("com.").expect("owner"))
            .await
            .expect("validated live referral");
        assert!(!referral.name_servers.is_empty());
        assert!(!referral.delegation_signers.is_empty());
    }

    #[tokio::test]
    #[ignore = "requires live ICANN root connectivity"]
    async fn live_unsigned_tld_requires_authenticated_ds_denial() {
        let client =
            ValidatingIcann::production(Duration::from_secs(5), 2, 64).expect("ICANN client");
        let referral = client
            .referral(&Name::from_ascii("kp.").expect("owner"))
            .await
            .expect("validated live unsigned referral");
        assert!(!referral.name_servers.is_empty());
        assert!(referral.delegation_signers.is_empty());
    }
}
