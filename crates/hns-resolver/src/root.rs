use std::{
    collections::HashSet,
    net::{Ipv4Addr, Ipv6Addr},
    str::{self, FromStr},
    sync::Arc,
};

use async_trait::async_trait;
use data_encoding::BASE32HEX_NOPAD;
use hickory_server::{
    authority::MessageResponseBuilder,
    proto::{
        dnssec::{rdata::DNSSECRData, rdata::DS, Algorithm, DigestType},
        op::{Header, ResponseCode},
        rr::{
            rdata::{A, AAAA, NS, SOA, TXT},
            Name, RData, Record, RecordType,
        },
    },
    server::{Request, RequestHandler, ResponseHandler, ResponseInfo},
};
use hns_primitives::{verify_name, DecodedResourceRecord, Resource};
use tracing::{debug, warn};

use crate::NameResourceSource;

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
}

impl HandshakeRoot {
    pub fn new(source: Arc<dyn NameResourceSource>, require_synchronized: bool) -> Self {
        Self {
            source,
            require_synchronized,
        }
    }

    pub async fn answer(&self, qname: &Name, qtype: RecordType) -> RootAnswer {
        if qname.is_root() {
            return root_zone_answer(qtype);
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
        let Some(resource_hex) = response.resource else {
            let mut answer = RootAnswer::empty(ResponseCode::NXDomain, true);
            answer.soa.push(root_soa(response.context.active_height));
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
        let records = match resource.decoded_records() {
            Ok(records) => records,
            Err(error) => {
                warn!(%error, %qname, "failed to decode typed Handshake resource records");
                return RootAnswer::servfail();
            }
        };
        match resource_answer(qname, qtype, &tld, &records, response.context.active_height) {
            Ok(answer) => answer,
            Err(error) => {
                warn!(%error, %qname, "failed to project Handshake resource into DNS");
                RootAnswer::servfail()
            }
        }
    }
}

#[async_trait]
impl RequestHandler for HandshakeRoot {
    async fn handle_request<R: ResponseHandler>(
        &self,
        request: &Request,
        mut response_handle: R,
    ) -> ResponseInfo {
        let request_info = match request.request_info() {
            Ok(info) => info,
            Err(error) => {
                warn!(%error, "invalid internal root DNS request");
                let mut header = Header::response_from_request(request.header());
                header.set_response_code(ResponseCode::FormErr);
                let response =
                    MessageResponseBuilder::from_message_request(request).build_no_records(header);
                return response_handle
                    .send_response(response)
                    .await
                    .unwrap_or_else(|_| header.into());
            }
        };
        let qname = Name::from(request_info.query.name());
        let answer = self.answer(&qname, request_info.query.query_type()).await;
        let mut header = Header::response_from_request(request.header());
        header.set_authoritative(answer.authoritative);
        header.set_recursion_available(false);
        header.set_response_code(answer.response_code);
        let response = MessageResponseBuilder::from_message_request(request).build(
            header,
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
                header.into()
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
    records: &[DecodedResourceRecord],
    height: Option<u32>,
) -> Result<RootAnswer, ProjectionError> {
    let owner = Name::from_ascii(format!("{tld}."))?;
    let has_ns = records.iter().any(|record| {
        matches!(
            record,
            DecodedResourceRecord::Ns { .. }
                | DecodedResourceRecord::Glue4 { .. }
                | DecodedResourceRecord::Glue6 { .. }
                | DecodedResourceRecord::Synth4 { .. }
                | DecodedResourceRecord::Synth6 { .. }
        )
    });
    let mut ns_records = Vec::new();
    let mut ds_records = Vec::new();
    let mut txt_records = Vec::new();
    let mut glue_records = Vec::new();
    let mut seen_ns = HashSet::new();

    for record in records {
        match record {
            DecodedResourceRecord::Ds {
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
            DecodedResourceRecord::Ns { ns } => {
                let ns = Name::from_ascii(ns)?;
                push_ns(&owner, ns, &mut seen_ns, &mut ns_records);
            }
            DecodedResourceRecord::Glue4 { ns, address } => {
                let ns = Name::from_ascii(ns)?;
                push_ns(&owner, ns.clone(), &mut seen_ns, &mut ns_records);
                if owner.zone_of(&ns) {
                    glue_records.push(Record::from_rdata(
                        ns,
                        DEFAULT_RESOURCE_TTL,
                        RData::A(A(Ipv4Addr::from(*address))),
                    ));
                }
            }
            DecodedResourceRecord::Glue6 { ns, address } => {
                let ns = Name::from_ascii(ns)?;
                push_ns(&owner, ns.clone(), &mut seen_ns, &mut ns_records);
                if owner.zone_of(&ns) {
                    glue_records.push(Record::from_rdata(
                        ns,
                        DEFAULT_RESOURCE_TTL,
                        RData::AAAA(AAAA(Ipv6Addr::from(*address))),
                    ));
                }
            }
            DecodedResourceRecord::Synth4 { address } => {
                let ns = synth_name(address);
                push_ns(&owner, ns.clone(), &mut seen_ns, &mut ns_records);
                glue_records.push(Record::from_rdata(
                    ns,
                    DEFAULT_RESOURCE_TTL,
                    RData::A(A(Ipv4Addr::from(*address))),
                ));
            }
            DecodedResourceRecord::Synth6 { address } => {
                let ns = synth_name(address);
                push_ns(&owner, ns.clone(), &mut seen_ns, &mut ns_records);
                glue_records.push(Record::from_rdata(
                    ns,
                    DEFAULT_RESOURCE_TTL,
                    RData::AAAA(AAAA(Ipv6Addr::from(*address))),
                ));
            }
            DecodedResourceRecord::Txt { txt } => txt_records.push(Record::from_rdata(
                owner.clone(),
                DEFAULT_RESOURCE_TTL,
                RData::TXT(TXT::from_bytes(txt.iter().map(Vec::as_slice).collect())),
            )),
            DecodedResourceRecord::Unknown { .. } => {}
        }
    }

    let apex = qname.num_labels() == 1;
    if apex && qtype == RecordType::TXT && !has_ns {
        let mut answer = RootAnswer::empty(ResponseCode::NoError, true);
        answer.answers = txt_records;
        if answer.answers.is_empty() {
            answer.soa.push(root_soa(height));
        }
        return Ok(answer);
    }
    if apex && qtype == RecordType::DS {
        let mut answer = RootAnswer::empty(ResponseCode::NoError, true);
        answer.answers = ds_records;
        if answer.answers.is_empty() {
            answer.soa.push(root_soa(height));
        }
        return Ok(answer);
    }
    if has_ns {
        let mut answer = RootAnswer::empty(ResponseCode::NoError, false);
        answer.authorities = ns_records;
        answer.authorities.extend(ds_records);
        answer.additionals = glue_records;
        return Ok(answer);
    }

    let mut answer = RootAnswer::empty(ResponseCode::NoError, true);
    answer.soa.push(root_soa(height));
    Ok(answer)
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
        RecordType::NS => answer.soa.push(root_soa(None)),
        RecordType::SOA => {
            answer.answers.push(root_soa(None));
            answer.authorities.push(ns_record);
            answer.additionals.push(glue);
        }
        _ => answer.soa.push(root_soa(None)),
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
        _ => answer.soa.push(root_soa(None)),
    }
    Some(answer)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hns_rpc::{RpcDnsContext, RpcDnsResource};

    use crate::BackendError;

    struct MockSource {
        response: RpcDnsResource,
    }

    #[async_trait]
    impl NameResourceSource for MockSource {
        async fn resource(&self, _name: &str) -> Result<RpcDnsResource, BackendError> {
            Ok(self.response.clone())
        }
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
        assert_eq!(answer.authorities.len(), 1);
        assert_eq!(answer.authorities[0].record_type(), RecordType::NS);
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
        assert!(answer.authorities.is_empty());
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
        assert_eq!(answer.authorities.len(), 1);
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
        assert_eq!(answer.answers[0].data(), &RData::A(A::new(127, 0, 0, 1)));
    }

    #[test]
    fn internal_root_ns_nodata_preserves_configured_bootstrap_transport() {
        let answer = root_zone_answer(RecordType::NS);
        assert_eq!(answer.response_code, ResponseCode::NoError);
        assert!(answer.authoritative);
        assert!(answer.answers.is_empty());
        assert_eq!(answer.soa.len(), 1);
    }
}
