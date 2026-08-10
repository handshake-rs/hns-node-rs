use std::{
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr},
    str::{self, FromStr},
    sync::Arc,
};

use async_trait::async_trait;
use data_encoding::BASE32HEX_NOPAD;
use hickory_server::{
    net::runtime::Time,
    proto::{
        dnssec::{rdata::DNSSECRData, rdata::DS, rdata::NSEC, Algorithm, DigestType},
        op::{Header, Metadata, ResponseCode},
        rr::{
            rdata::{A, AAAA, NS, SOA, TXT},
            Name, RData, Record, RecordType,
        },
    },
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
    zone_handler::MessageResponseBuilder,
};
use hns_consensus::reserved_name;
use hns_covenants::{Resource, ResourceName, ResourceRecord};
use hns_primitives::verify_name;
use tracing::{debug, warn};

use crate::{dnssec::RootDnssec, IcannLookup, IcannReferral, NameResourceSource};

/// One name-tree interval at the target ten-minute block cadence.
pub const DEFAULT_RESOURCE_TTL: u32 = 21_600;
const ROOT_NS_TTL: u32 = 518_400;
const ROOT_SOA_TTL: u32 = 86_400;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootAnswer {
    pub response_code: ResponseCode,
    pub authoritative: bool,
    pub answers: Vec<Record>,
    pub authorities: Vec<Record>,
    pub soa: Vec<Record>,
    pub additionals: Vec<Record>,
}

impl RootAnswer {
    fn empty(response_code: ResponseCode, authoritative: bool) -> Self {
        Self {
            response_code,
            authoritative,
            answers: Vec::new(),
            authorities: Vec::new(),
            soa: Vec::new(),
            additionals: Vec::new(),
        }
    }

    fn servfail() -> Self {
        Self::empty(ResponseCode::ServFail, false)
    }
}

pub struct HandshakeRoot {
    source: Arc<dyn NameResourceSource>,
    require_synchronized: bool,
    dnssec: RootDnssec,
    icann: Option<Arc<dyn IcannLookup>>,
}

impl HandshakeRoot {
    pub fn new(source: Arc<dyn NameResourceSource>, require_synchronized: bool) -> Self {
        Self {
            source,
            require_synchronized,
            dnssec: RootDnssec::new().expect("embedded Handshake DNSSEC keys are valid"),
            icann: None,
        }
    }

    pub fn with_icann(mut self, icann: Arc<dyn IcannLookup>) -> Self {
        self.icann = Some(icann);
        self
    }

    pub async fn answer(&self, qname: &Name, qtype: RecordType) -> RootAnswer {
        if qname.is_root() {
            let mut answer = root_zone_answer(qtype);
            if matches!(qtype, RecordType::DNSKEY | RecordType::ANY) {
                answer.answers.extend(self.dnssec.dnskey_records());
            }
            return answer;
        }

        if let Some(answer) = synth_answer(qname, qtype) {
            return answer;
        }

        let Some(label) = qname.iter().next_back() else {
            return RootAnswer::empty(ResponseCode::FormErr, false);
        };
        let Ok(tld) = str::from_utf8(label) else {
            return RootAnswer::empty(ResponseCode::Refused, false);
        };
        let tld = tld.to_ascii_lowercase();
        if !verify_name(&tld) {
            return RootAnswer::empty(ResponseCode::Refused, false);
        }

        let response = match self.source.resource(&tld).await {
            Ok(response) => response,
            Err(error) => {
                warn!(%error, %qname, "hsrd DNS resource lookup failed");
                return RootAnswer::servfail();
            }
        };
        if self.require_synchronized && !response.context.synchronized {
            debug!(
                %qname,
                active_height = ?response.context.active_height,
                best_header_height = ?response.context.best_header_height,
                "refusing DNS answer while hsrd active state is not synchronized"
            );
            return RootAnswer::servfail();
        }
        let resource = if is_hns_icann_collision(&tld) {
            None
        } else {
            response.resource
        };
        let Some(resource_hex) = resource else {
            if !is_hns_icann_collision(&tld) {
                if let Some(icann) = self
                    .icann
                    .as_ref()
                    .filter(|_| reserved_name(tld.as_bytes()).is_some_and(|reserved| reserved.root))
                {
                    let owner = match Name::from_ascii(format!("{tld}.")) {
                        Ok(owner) => owner,
                        Err(_) => return RootAnswer::servfail(),
                    };
                    return match icann.referral(&owner).await {
                        Ok(referral) => icann_answer(
                            qname,
                            qtype,
                            &owner,
                            referral,
                            response.context.active_height,
                        ),
                        Err(error) => {
                            warn!(%error, %qname, "validated ICANN root fallback failed");
                            RootAnswer::servfail()
                        }
                    };
                }
            }
            let mut answer = RootAnswer::empty(ResponseCode::NXDomain, true);
            answer.soa.push(root_soa(response.context.active_height));
            add_missing_name_proof(&mut answer, &tld);
            return answer;
        };
        let resource_bytes = match hex::decode(resource_hex) {
            Ok(bytes) => bytes,
            Err(error) => {
                warn!(%error, %qname, "hsrd returned invalid resource hex");
                return RootAnswer::servfail();
            }
        };
        let resource = match Resource::decode(&resource_bytes) {
            Ok(resource) => resource,
            Err(error) => {
                warn!(%error, %qname, "hsrd returned an invalid Handshake resource");
                return RootAnswer::servfail();
            }
        };
        match resource_answer(
            qname,
            qtype,
            &tld,
            resource.records(),
            response.context.active_height,
        ) {
            Ok(answer) => answer,
            Err(error) => {
                warn!(%error, %qname, "failed to project Handshake resource into DNS");
                RootAnswer::servfail()
            }
        }
    }

    pub async fn signed_answer(&self, qname: &Name, qtype: RecordType) -> RootAnswer {
        let mut answer = self.answer(qname, qtype).await;
        if answer.response_code != ResponseCode::ServFail {
            if let Err(error) = self.dnssec.sign_answer(&mut answer, qname.is_root()) {
                warn!(%error, %qname, ?qtype, "failed to sign Handshake root answer");
                return RootAnswer::servfail();
            }
        }
        answer
    }
}

#[async_trait]
impl RequestHandler for HandshakeRoot {
    async fn handle_request<R: ResponseHandler, T: Time>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let request_info = match request.request_info() {
            Ok(info) => info,
            Err(error) => {
                warn!(%error, "invalid internal root DNS request");
                let mut metadata = Metadata::response_from_request(&request.metadata);
                metadata.response_code = ResponseCode::FormErr;
                let response = MessageResponseBuilder::from_message_request(request)
                    .build_no_records(metadata);
                return response_handle
                    .send_response(response)
                    .await
                    .unwrap_or_else(|_| {
                        Header {
                            metadata,
                            counts: Default::default(),
                        }
                        .into()
                    });
            }
        };
        let qname = Name::from(request_info.query.name());
        let answer = self
            .signed_answer(&qname, request_info.query.query_type())
            .await;
        let mut metadata = Metadata::response_from_request(&request.metadata);
        metadata.authoritative = answer.authoritative;
        metadata.recursion_available = false;
        metadata.response_code = answer.response_code;
        let response = MessageResponseBuilder::from_message_request(request).build(
            metadata,
            answer.answers.iter(),
            answer.authorities.iter(),
            answer.soa.iter(),
            answer.additionals.iter(),
        );
        response_handle
            .send_response(response)
            .await
            .unwrap_or_else(|error| {
                warn!(%error, "failed to send internal root DNS response");
                Header {
                    metadata,
                    counts: Default::default(),
                }
                .into()
            })
    }
}

#[derive(Debug, thiserror::Error)]
enum ProjectionError {
    #[error("invalid DNS name in Handshake resource: {0}")]
    Name(#[from] hickory_server::proto::ProtoError),
}

fn resource_answer(
    qname: &Name,
    qtype: RecordType,
    tld: &str,
    records: &[ResourceRecord],
    height: Option<u32>,
) -> Result<RootAnswer, ProjectionError> {
    let owner = Name::from_ascii(format!("{tld}."))?;
    let has_ns = records.iter().any(|record| {
        matches!(
            record,
            ResourceRecord::Ns { .. }
                | ResourceRecord::Glue4 { .. }
                | ResourceRecord::Glue6 { .. }
                | ResourceRecord::Synth4 { .. }
                | ResourceRecord::Synth6 { .. }
        )
    });
    let mut ns_records = Vec::new();
    let mut ds_records = Vec::new();
    let mut txt_records = Vec::new();
    let mut glue_records = Vec::new();
    let mut seen_ns = HashSet::new();

    for record in records {
        match record {
            ResourceRecord::Ds {
                key_tag,
                algorithm,
                digest_type,
                digest,
            } => ds_records.push(Record::from_rdata(
                owner.clone(),
                DEFAULT_RESOURCE_TTL,
                RData::DNSSEC(DNSSECRData::DS(DS::new(
                    *key_tag,
                    Algorithm::from_u8(*algorithm),
                    DigestType::from(*digest_type),
                    digest.clone(),
                ))),
            )),
            ResourceRecord::Ns { name_server } => {
                let ns = projected_name(name_server)?;
                push_ns(&owner, ns, &mut seen_ns, &mut ns_records);
            }
            ResourceRecord::Glue4 {
                name_server,
                address,
            } => {
                let ns = projected_name(name_server)?;
                push_ns(&owner, ns.clone(), &mut seen_ns, &mut ns_records);
                if owner.zone_of(&ns) {
                    glue_records.push(Record::from_rdata(
                        ns,
                        DEFAULT_RESOURCE_TTL,
                        RData::A(A(Ipv4Addr::from(*address))),
                    ));
                }
            }
            ResourceRecord::Glue6 {
                name_server,
                address,
            } => {
                let ns = projected_name(name_server)?;
                push_ns(&owner, ns.clone(), &mut seen_ns, &mut ns_records);
                if owner.zone_of(&ns) {
                    glue_records.push(Record::from_rdata(
                        ns,
                        DEFAULT_RESOURCE_TTL,
                        RData::AAAA(AAAA(Ipv6Addr::from(*address))),
                    ));
                }
            }
            ResourceRecord::Synth4 { address } => {
                let ns = synth_name(address);
                push_ns(&owner, ns.clone(), &mut seen_ns, &mut ns_records);
                glue_records.push(Record::from_rdata(
                    ns,
                    DEFAULT_RESOURCE_TTL,
                    RData::A(A(Ipv4Addr::from(*address))),
                ));
            }
            ResourceRecord::Synth6 { address } => {
                let ns = synth_name(address);
                push_ns(&owner, ns.clone(), &mut seen_ns, &mut ns_records);
                glue_records.push(Record::from_rdata(
                    ns,
                    DEFAULT_RESOURCE_TTL,
                    RData::AAAA(AAAA(Ipv6Addr::from(*address))),
                ));
            }
            ResourceRecord::Txt { strings } => txt_records.push(Record::from_rdata(
                owner.clone(),
                DEFAULT_RESOURCE_TTL,
                RData::TXT(TXT::from_bytes(strings.iter().map(Vec::as_slice).collect())),
            )),
        }
    }

    let apex = qname.num_labels() == 1;
    if apex && qtype == RecordType::TXT && !has_ns {
        let mut answer = RootAnswer::empty(ResponseCode::NoError, true);
        answer.answers = txt_records;
        if answer.answers.is_empty() {
            answer.soa.push(root_soa(height));
            answer.authorities.push(existing_name_nsec(
                &owner,
                &[RecordType::RRSIG, RecordType::NSEC],
            ));
        }
        return Ok(answer);
    }
    if apex && qtype == RecordType::DS {
        let mut answer = RootAnswer::empty(ResponseCode::NoError, true);
        answer.answers = ds_records;
        if answer.answers.is_empty() {
            answer.soa.push(root_soa(height));
            let types = if has_ns {
                &[RecordType::NS, RecordType::RRSIG, RecordType::NSEC][..]
            } else {
                &[RecordType::RRSIG, RecordType::NSEC][..]
            };
            answer.authorities.push(existing_name_nsec(&owner, types));
        }
        return Ok(answer);
    }
    if has_ns {
        let mut answer = RootAnswer::empty(ResponseCode::NoError, false);
        answer.authorities = ns_records;
        answer.authorities.extend(ds_records);
        if !answer
            .authorities
            .iter()
            .any(|record| record.record_type() == RecordType::DS)
        {
            answer.authorities.push(existing_name_nsec(
                &owner,
                &[RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
            ));
        }
        answer.additionals = glue_records;
        return Ok(answer);
    }

    let mut answer = RootAnswer::empty(ResponseCode::NoError, true);
    answer.soa.push(root_soa(height));
    answer.authorities.push(existing_name_nsec(
        &owner,
        &[RecordType::RRSIG, RecordType::NSEC],
    ));
    Ok(answer)
}

fn projected_name(name: &ResourceName) -> Result<Name, ProjectionError> {
    Name::from_labels(name.labels().iter().map(Vec::as_slice)).map_err(ProjectionError::from)
}

fn icann_answer(
    qname: &Name,
    qtype: RecordType,
    owner: &Name,
    mut referral: IcannReferral,
    height: Option<u32>,
) -> RootAnswer {
    for record in referral
        .name_servers
        .iter_mut()
        .chain(referral.delegation_signers.iter_mut())
        .chain(referral.glue.iter_mut())
    {
        record.ttl = record.ttl.min(DEFAULT_RESOURCE_TTL);
    }
    let apex = qname == owner;
    if apex && qtype == RecordType::DS {
        let mut answer = RootAnswer::empty(ResponseCode::NoError, true);
        answer.answers = referral.delegation_signers;
        if answer.answers.is_empty() {
            answer.soa.push(root_soa(height));
            answer.authorities.push(existing_name_nsec(
                owner,
                &[RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
            ));
        }
        return answer;
    }

    let mut answer = RootAnswer::empty(ResponseCode::NoError, false);
    answer.authorities = referral.name_servers;
    answer.authorities.extend(referral.delegation_signers);
    if !answer
        .authorities
        .iter()
        .any(|record| record.record_type() == RecordType::DS)
    {
        answer.authorities.push(existing_name_nsec(
            owner,
            &[RecordType::NS, RecordType::RRSIG, RecordType::NSEC],
        ));
    }
    answer.additionals = referral.glue;
    answer
}

fn existing_name_nsec(owner: &Name, types: &[RecordType]) -> Record {
    Record::from_rdata(
        owner.clone(),
        DEFAULT_RESOURCE_TTL,
        RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
            next_name(owner),
            types.iter().copied(),
        ))),
    )
}

fn add_missing_name_proof(answer: &mut RootAnswer, tld: &str) {
    let mut label = tld.as_bytes().to_vec();
    if let Some(last) = label.last_mut() {
        *last = last.saturating_sub(1);
    }
    if label.len() < 63 {
        label.push(0xff);
    }
    let Ok(previous) = Name::from_labels([label.as_slice()]) else {
        return;
    };
    let Ok(owner) = Name::from_ascii(format!("{tld}.")) else {
        return;
    };
    answer.authorities.push(Record::from_rdata(
        previous,
        DEFAULT_RESOURCE_TTL,
        RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
            next_name(&owner),
            [RecordType::RRSIG, RecordType::NSEC],
        ))),
    ));
    answer.authorities.push(Record::from_rdata(
        Name::from_labels([b"!".as_slice()]).expect("wildcard denial owner"),
        DEFAULT_RESOURCE_TTL,
        RData::DNSSEC(DNSSECRData::NSEC(NSEC::new(
            Name::from_labels([b"+".as_slice()]).expect("wildcard denial successor"),
            [RecordType::RRSIG, RecordType::NSEC],
        ))),
    ));
    // Hickory validates the closest encloser for a one-label query as the
    // root itself. Keep HSD's !. -> +. wildcard proof above and also publish
    // the real root RRset bitmap through its first synthetic successor.
    answer.authorities.push(existing_name_nsec(
        &Name::root(),
        &[
            RecordType::NS,
            RecordType::SOA,
            RecordType::RRSIG,
            RecordType::NSEC,
            RecordType::DNSKEY,
        ],
    ));
}

fn next_name(owner: &Name) -> Name {
    let Some(current) = owner.iter().next() else {
        return Name::from_labels([b"!".as_slice()]).expect("root successor");
    };
    let mut label = current.to_vec();
    if label.len() < 63 {
        label.push(0);
    } else if let Some(last) = label.last_mut() {
        *last = last.saturating_add(1);
    }
    Name::from_labels([label.as_slice()]).expect("derived NSEC successor is valid")
}

fn is_hns_icann_collision(tld: &str) -> bool {
    matches!(
        tld,
        "bit" | "eth" | "exit" | "gnu" | "i2p" | "onion" | "tor" | "zkey"
    )
}

fn push_ns(owner: &Name, ns: Name, seen: &mut HashSet<Name>, records: &mut Vec<Record>) {
    if seen.insert(ns.clone()) {
        records.push(Record::from_rdata(
            owner.clone(),
            DEFAULT_RESOURCE_TTL,
            RData::NS(NS(ns)),
        ));
    }
}

fn root_zone_answer(qtype: RecordType) -> RootAnswer {
    let root = Name::root();
    let root_ip = [127, 0, 0, 1];
    let ns = synth_name(&root_ip);
    let ns_record = Record::from_rdata(root.clone(), ROOT_NS_TTL, RData::NS(NS(ns.clone())));
    let glue = Record::from_rdata(ns, ROOT_NS_TTL, RData::A(A(Ipv4Addr::from(root_ip))));
    let mut answer = RootAnswer::empty(ResponseCode::NoError, true);
    match qtype {
        RecordType::ANY => {
            answer.answers.push(ns_record);
            answer.additionals.push(glue);
        }
        // This authority is an in-process bootstrap adapter, not the public
        // recursive listener. Hickory 0.25 otherwise rebuilds its configured
        // root pool from this RRset and silently replaces the exact ephemeral
        // transport port with port 53. NODATA makes it retain the bounded,
        // explicitly configured root transport. TLD referrals are unaffected.
        RecordType::NS => {
            answer.soa.push(root_soa(None));
            answer.authorities.push(existing_name_nsec(
                &root,
                &[
                    RecordType::SOA,
                    RecordType::RRSIG,
                    RecordType::NSEC,
                    RecordType::DNSKEY,
                ],
            ));
        }
        RecordType::SOA => {
            answer.answers.push(root_soa(None));
            answer.authorities.push(ns_record);
            answer.additionals.push(glue);
        }
        RecordType::DNSKEY => {}
        RecordType::NSEC => answer.answers.push(existing_name_nsec(
            &root,
            &[
                RecordType::NS,
                RecordType::SOA,
                RecordType::RRSIG,
                RecordType::NSEC,
                RecordType::DNSKEY,
            ],
        )),
        _ => {
            answer.soa.push(root_soa(None));
            answer.authorities.push(existing_name_nsec(
                &root,
                &[
                    RecordType::NS,
                    RecordType::SOA,
                    RecordType::RRSIG,
                    RecordType::NSEC,
                    RecordType::DNSKEY,
                ],
            ));
        }
    }
    answer
}

fn root_soa(height: Option<u32>) -> Record {
    Record::from_rdata(
        Name::root(),
        ROOT_SOA_TTL,
        RData::SOA(SOA::new(
            Name::root(),
            Name::root(),
            height.unwrap_or(1),
            1_800,
            900,
            604_800,
            DEFAULT_RESOURCE_TTL,
        )),
    )
}

fn synth_name(bytes: &[u8]) -> Name {
    let encoded = BASE32HEX_NOPAD.encode(bytes).to_ascii_lowercase();
    Name::from_str(&format!("_{encoded}._synth.")).expect("base32 synth name is valid")
}

fn synth_answer(qname: &Name, qtype: RecordType) -> Option<RootAnswer> {
    let labels = qname.iter().collect::<Vec<_>>();
    if labels.last().copied() != Some(b"_synth".as_slice()) {
        return None;
    }
    if labels.len() != 2 || !labels[0].starts_with(b"_") {
        let mut answer = RootAnswer::empty(ResponseCode::NoError, true);
        answer.soa.push(root_soa(None));
        answer.authorities.push(existing_name_nsec(
            qname,
            &[RecordType::RRSIG, RecordType::NSEC],
        ));
        return Some(answer);
    }
    let encoded = str::from_utf8(&labels[0][1..]).ok()?.to_ascii_uppercase();
    let address = BASE32HEX_NOPAD.decode(encoded.as_bytes()).ok()?;
    let mut answer = RootAnswer::empty(ResponseCode::NoError, true);
    match (address.as_slice(), qtype) {
        ([a, b, c, d], RecordType::A) => answer.answers.push(Record::from_rdata(
            qname.clone(),
            DEFAULT_RESOURCE_TTL,
            RData::A(A::new(*a, *b, *c, *d)),
        )),
        (bytes, RecordType::AAAA) if bytes.len() == 16 => {
            let mut raw = [0; 16];
            raw.copy_from_slice(bytes);
            answer.answers.push(Record::from_rdata(
                qname.clone(),
                DEFAULT_RESOURCE_TTL,
                RData::AAAA(AAAA(Ipv6Addr::from(raw))),
            ));
        }
        _ => {
            answer.soa.push(root_soa(None));
            answer.authorities.push(existing_name_nsec(
                qname,
                &[RecordType::RRSIG, RecordType::NSEC],
            ));
        }
    }
    Some(answer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_rpc::{RpcDnsContext, RpcDnsResource};
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::{BackendError, IcannError};

    struct MockSource {
        response: RpcDnsResource,
    }

    #[async_trait]
    impl NameResourceSource for MockSource {
        async fn resource(&self, _name: &str) -> Result<RpcDnsResource, BackendError> {
            Ok(self.response.clone())
        }
    }

    struct MockIcann {
        calls: AtomicUsize,
        referral: IcannReferral,
    }

    #[async_trait]
    impl IcannLookup for MockIcann {
        async fn referral(&self, _tld: &Name) -> Result<IcannReferral, IcannError> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(self.referral.clone())
        }
    }

    fn icann() -> Arc<MockIcann> {
        let owner = Name::from_ascii("com.").expect("owner");
        let ns = Name::from_ascii("a.gtld-servers.net.").expect("name server");
        Arc::new(MockIcann {
            calls: AtomicUsize::new(0),
            referral: IcannReferral {
                name_servers: vec![Record::from_rdata(
                    owner,
                    DEFAULT_RESOURCE_TTL,
                    RData::NS(NS(ns.clone())),
                )],
                delegation_signers: Vec::new(),
                glue: vec![Record::from_rdata(
                    ns,
                    DEFAULT_RESOURCE_TTL,
                    RData::A(A::new(192, 5, 6, 30)),
                )],
            },
        })
    }

    fn source(resource: Option<&[u8]>, synchronized: bool) -> Arc<dyn NameResourceSource> {
        Arc::new(MockSource {
            response: RpcDnsResource {
                name: "handshake".to_owned(),
                resource: resource.map(hex::encode),
                context: RpcDnsContext {
                    network: "regtest".to_owned(),
                    active_height: Some(7),
                    best_header_height: Some(if synchronized { 7 } else { 8 }),
                    active_state_root: Some("11".repeat(32)),
                    chain_epoch: 9,
                    synchronized,
                },
            },
        })
    }

    #[tokio::test]
    async fn synth_resource_becomes_root_referral_and_glue() {
        let root = HandshakeRoot::new(source(Some(&[0, 4, 127, 0, 0, 1]), true), true);
        let answer = root
            .answer(
                &Name::from_ascii("www.handshake.").expect("query name"),
                RecordType::A,
            )
            .await;

        assert_eq!(answer.response_code, ResponseCode::NoError);
        assert!(!answer.authoritative);
        assert_eq!(
            answer
                .authorities
                .iter()
                .filter(|record| record.record_type() == RecordType::NS)
                .count(),
            1
        );
        assert_eq!(answer.additionals.len(), 1);
        assert_eq!(answer.additionals[0].record_type(), RecordType::A);
    }

    #[tokio::test]
    async fn unsynchronized_backend_fails_closed() {
        let root = HandshakeRoot::new(source(Some(&[0, 4, 127, 0, 0, 1]), false), true);
        let answer = root
            .answer(
                &Name::from_ascii("handshake.").expect("query name"),
                RecordType::NS,
            )
            .await;
        assert_eq!(answer.response_code, ResponseCode::ServFail);
        assert!(answer.answers.is_empty());
        assert!(answer.authorities.is_empty());
    }

    #[tokio::test]
    async fn standalone_txt_resource_answers_at_the_tld_apex() {
        let root = HandshakeRoot::new(source(Some(&[0, 6, 1, 3, b'f', b'o', b'o']), true), true);
        let answer = root
            .answer(
                &Name::from_ascii("handshake.").expect("query name"),
                RecordType::TXT,
            )
            .await;
        assert_eq!(answer.response_code, ResponseCode::NoError);
        assert!(answer.authoritative);
        assert_eq!(answer.answers.len(), 1);
        assert_eq!(answer.answers[0].record_type(), RecordType::TXT);
    }

    #[tokio::test]
    async fn missing_name_returns_authoritative_nxdomain() {
        let root = HandshakeRoot::new(source(None, true), true);
        let answer = root
            .answer(
                &Name::from_ascii("missing.").expect("query name"),
                RecordType::A,
            )
            .await;
        assert_eq!(answer.response_code, ResponseCode::NXDomain);
        assert!(answer.authoritative);
        assert_eq!(answer.soa.len(), 1);
        assert_eq!(
            answer
                .authorities
                .iter()
                .filter(|record| record.record_type() == RecordType::NSEC)
                .count(),
            3
        );
    }

    #[tokio::test]
    async fn apex_ds_without_ds_is_authoritative_nodata_not_a_referral() {
        let root = HandshakeRoot::new(source(Some(&[0, 4, 192, 0, 2, 1]), true), true);
        let answer = root
            .answer(
                &Name::from_ascii("handshake.").expect("query name"),
                RecordType::DS,
            )
            .await;

        assert_eq!(answer.response_code, ResponseCode::NoError);
        assert!(answer.authoritative);
        assert!(answer.answers.is_empty());
        assert_eq!(answer.authorities.len(), 1);
        assert_eq!(answer.authorities[0].record_type(), RecordType::NSEC);
        assert_eq!(answer.soa.len(), 1);
    }

    #[tokio::test]
    async fn out_of_bailiwick_glue_is_not_projected_as_additional_data() {
        let resource = [
            0, 2, 2, b'n', b's', 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 192, 0, 2, 1,
        ];
        let root = HandshakeRoot::new(source(Some(&resource), true), true);
        let answer = root
            .answer(
                &Name::from_ascii("www.handshake.").expect("query name"),
                RecordType::A,
            )
            .await;

        assert!(!answer.authoritative);
        assert_eq!(
            answer
                .authorities
                .iter()
                .filter(|record| record.record_type() == RecordType::NS)
                .count(),
            1
        );
        assert!(answer.additionals.is_empty());
    }

    #[tokio::test]
    async fn synthesized_name_round_trips_to_its_ipv4_address() {
        let root = HandshakeRoot::new(source(None, true), true);
        let answer = root
            .answer(
                &Name::from_ascii("_fs00008._synth.").expect("query name"),
                RecordType::A,
            )
            .await;

        assert!(answer.authoritative);
        assert_eq!(answer.answers.len(), 1);
        assert_eq!(answer.answers[0].data, RData::A(A::new(127, 0, 0, 1)));
    }

    #[test]
    fn internal_root_ns_nodata_preserves_configured_bootstrap_transport() {
        let answer = root_zone_answer(RecordType::NS);
        assert_eq!(answer.response_code, ResponseCode::NoError);
        assert!(answer.authoritative);
        assert!(answer.answers.is_empty());
        assert_eq!(answer.soa.len(), 1);
    }

    #[tokio::test]
    async fn signed_root_dnskey_rrset_uses_the_canonical_ksk() {
        let root = HandshakeRoot::new(source(None, true), true);
        let answer = root.signed_answer(&Name::root(), RecordType::DNSKEY).await;
        assert_eq!(
            answer
                .answers
                .iter()
                .filter(|record| record.record_type() == RecordType::DNSKEY)
                .count(),
            2
        );
        assert!(answer.answers.iter().any(|record| {
            matches!(
                &record.data,
                RData::DNSSEC(DNSSECRData::RRSIG(rrsig))
                    if rrsig.input().type_covered == RecordType::DNSKEY
                        && rrsig.input().key_tag == 35_215
            )
        }));
    }

    #[tokio::test]
    async fn eligible_missing_name_uses_signed_icann_referral() {
        let icann = icann();
        let lookup: Arc<dyn IcannLookup> = icann.clone();
        let root = HandshakeRoot::new(source(None, true), true).with_icann(lookup);
        let answer = root
            .signed_answer(&Name::from_ascii("www.com.").expect("query"), RecordType::A)
            .await;

        assert_eq!(icann.calls.load(Ordering::Relaxed), 1);
        assert!(!answer.authoritative);
        assert!(answer
            .authorities
            .iter()
            .any(|record| record.record_type() == RecordType::NS));
        assert!(answer.authorities.iter().any(|record| {
            matches!(
                &record.data,
                RData::DNSSEC(DNSSECRData::RRSIG(rrsig))
                    if rrsig.input().type_covered == RecordType::NSEC
            )
        }));
        assert!(!answer.authorities.iter().any(|record| {
            matches!(
                &record.data,
                RData::DNSSEC(DNSSECRData::RRSIG(rrsig))
                    if rrsig.input().type_covered == RecordType::NS
            )
        }));
    }

    #[tokio::test]
    async fn handshake_resource_takes_precedence_over_icann_fallback() {
        let icann = icann();
        let lookup: Arc<dyn IcannLookup> = icann.clone();
        let root =
            HandshakeRoot::new(source(Some(&[0, 4, 127, 0, 0, 1]), true), true).with_icann(lookup);
        let answer = root
            .answer(&Name::from_ascii("www.com.").expect("query"), RecordType::A)
            .await;

        assert_eq!(icann.calls.load(Ordering::Relaxed), 0);
        assert!(answer
            .additionals
            .iter()
            .any(|record| record.data == RData::A(A::new(127, 0, 0, 1))));
    }

    #[tokio::test]
    async fn decentralized_collision_blacklist_suppresses_chain_and_icann_data() {
        let icann = icann();
        let lookup: Arc<dyn IcannLookup> = icann.clone();
        let root =
            HandshakeRoot::new(source(Some(&[0, 4, 127, 0, 0, 1]), true), true).with_icann(lookup);
        let answer = root
            .answer(&Name::from_ascii("www.bit.").expect("query"), RecordType::A)
            .await;

        assert_eq!(answer.response_code, ResponseCode::NXDomain);
        assert_eq!(icann.calls.load(Ordering::Relaxed), 0);
    }
}
