use std::{collections::HashSet, sync::Arc, time::Duration};

use hickory_server::proto::{
    dnssec::{
        crypto::signing_key_from_der, rdata::DNSSECRData, rdata::DNSKEY, rdata::RRSIG, Algorithm,
        PublicKeyBuf, SigSigner, TrustAnchors, TBS,
    },
    rr::{DNSClass, Name, RData, Record, RecordSet, RecordType},
};
use rustls_pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
use time::OffsetDateTime;

use crate::RootAnswer;

const DNSKEY_TTL: u32 = 10_800;
const SIGNATURE_VALIDITY: Duration = Duration::from_secs(2 * 60 * 60);
const SIGNATURE_INCEPTION_SKEW_SECONDS: i64 = 5 * 60;

// These are the canonical Handshake root KSK/ZSK from hsd. They are NIST
// P-256 PKCS#8 keys, not Handshake transaction secp256k1 keys. Keeping the
// public key bytes separately makes the configured trust anchor auditable.
const KSK_DER: &[u8] = &hex_literal::hex!(
    "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420
     1c74c825c5b0f08cf6be846bfc93c423f03e3e1f6202fb2d96474b1520bbafad
     a14403420004
     4fd714449d8cfcccfdaba52c64d63e3aca72be3f94bfeb60aeb5a42ed3d0c205
     3f5eee58934974d929f9b9adb10107c4608cd13babf9880f817a331e13034fe1"
);
const ZSK_DER: &[u8] = &hex_literal::hex!(
    "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b0201010420
     54276ff8604a3494c5c76d6651f14b289c7253ba636be4bfd7969308f48da47d
     a14403420004
     2399cfb3a72515ad609f09fd22954319d24b7c438dce00f535c7ee13010856e2
     281dd64682f55b96c2cd6d13beb295b79d060783ddacbe1cb51ce8d3885048b1"
);
pub(crate) const KSK_PUBLIC_KEY: &[u8] = &hex_literal::hex!(
    "4fd714449d8cfcccfdaba52c64d63e3aca72be3f94bfeb60aeb5a42ed3d0c205
     3f5eee58934974d929f9b9adb10107c4608cd13babf9880f817a331e13034fe1"
);
const ZSK_PUBLIC_KEY: &[u8] = &hex_literal::hex!(
    "2399cfb3a72515ad609f09fd22954319d24b7c438dce00f535c7ee13010856e2
     281dd64682f55b96c2cd6d13beb295b79d060783ddacbe1cb51ce8d3885048b1"
);

pub(crate) struct RootDnssec {
    ksk: SigSigner,
    zsk: SigSigner,
    ksk_dnskey: DNSKEY,
    zsk_dnskey: DNSKEY,
}

impl RootDnssec {
    pub(crate) fn new() -> anyhow::Result<Self> {
        let algorithm = Algorithm::ECDSAP256SHA256;
        let ksk_dnskey =
            DNSKEY::with_flags(257, PublicKeyBuf::new(KSK_PUBLIC_KEY.to_vec(), algorithm));
        let zsk_dnskey =
            DNSKEY::with_flags(256, PublicKeyBuf::new(ZSK_PUBLIC_KEY.to_vec(), algorithm));
        let ksk_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(KSK_DER.to_vec()));
        let zsk_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ZSK_DER.to_vec()));
        let ksk_key = signing_key_from_der(&ksk_der, algorithm)
            .map_err(|error| anyhow::anyhow!("invalid embedded Handshake KSK: {error}"))?;
        let zsk_key = signing_key_from_der(&zsk_der, algorithm)
            .map_err(|error| anyhow::anyhow!("invalid embedded Handshake ZSK: {error}"))?;
        let root = Name::root();
        Ok(Self {
            ksk: SigSigner::dnssec(
                ksk_dnskey.clone(),
                ksk_key,
                root.clone(),
                SIGNATURE_VALIDITY,
            ),
            zsk: SigSigner::dnssec(zsk_dnskey.clone(), zsk_key, root, SIGNATURE_VALIDITY),
            ksk_dnskey,
            zsk_dnskey,
        })
    }

    pub(crate) fn trust_anchors() -> Arc<TrustAnchors> {
        let mut anchors = TrustAnchors::empty();
        anchors.insert(&PublicKeyBuf::new(
            KSK_PUBLIC_KEY.to_vec(),
            Algorithm::ECDSAP256SHA256,
        ));
        Arc::new(anchors)
    }

    pub(crate) fn dnskey_records(&self) -> [Record; 2] {
        let root = Name::root();
        [
            Record::from_rdata(
                root.clone(),
                DNSKEY_TTL,
                RData::DNSSEC(DNSSECRData::DNSKEY(self.ksk_dnskey.clone())),
            ),
            Record::from_rdata(
                root,
                DNSKEY_TTL,
                RData::DNSSEC(DNSSECRData::DNSKEY(self.zsk_dnskey.clone())),
            ),
        ]
    }

    pub(crate) fn sign_answer(
        &self,
        answer: &mut RootAnswer,
        root_query: bool,
    ) -> anyhow::Result<()> {
        let authoritative = answer.authoritative;
        sign_section(&self.ksk, &self.zsk, &mut answer.answers, |_| true)?;
        sign_section(
            &self.ksk,
            &self.zsk,
            &mut answer.authorities,
            |record_type| {
                root_query
                    || authoritative
                    || matches!(
                        record_type,
                        RecordType::DS | RecordType::NSEC | RecordType::SOA
                    )
            },
        )?;
        sign_section(&self.ksk, &self.zsk, &mut answer.soa, |_| true)?;
        if root_query {
            sign_section(&self.ksk, &self.zsk, &mut answer.additionals, |_| true)?;
        }
        Ok(())
    }
}

fn sign_section(
    ksk: &SigSigner,
    zsk: &SigSigner,
    records: &mut Vec<Record>,
    eligible: impl Fn(RecordType) -> bool,
) -> anyhow::Result<()> {
    let mut rrsets = HashSet::new();
    for record in records.iter() {
        let record_type = record.record_type();
        if record_type != RecordType::RRSIG && eligible(record_type) {
            rrsets.insert((record.name().clone(), record_type));
        }
    }

    let inception =
        OffsetDateTime::now_utc() - time::Duration::seconds(SIGNATURE_INCEPTION_SKEW_SECONDS);
    let expiration = inception + time::Duration::seconds(SIGNATURE_VALIDITY.as_secs() as i64);
    let mut signatures = Vec::with_capacity(rrsets.len());
    for (name, record_type) in rrsets {
        let mut rrset = RecordSet::with_ttl(
            name.clone(),
            record_type,
            records
                .iter()
                .find(|record| record.name() == &name && record.record_type() == record_type)
                .map_or(0, Record::ttl),
        );
        for record in records
            .iter()
            .filter(|record| record.name() == &name && record.record_type() == record_type)
        {
            rrset.insert(record.clone(), 0);
        }
        let signer = if record_type == RecordType::DNSKEY {
            ksk
        } else {
            zsk
        };
        let tbs = TBS::from_rrset(&rrset, DNSClass::IN, inception, expiration, signer)?;
        let signature = signer.sign(&tbs)?;
        signatures.push(Record::from_rdata(
            name,
            rrset.ttl(),
            RData::DNSSEC(DNSSECRData::RRSIG(RRSIG::new(
                record_type,
                signer.key().algorithm(),
                rrset.name().num_labels(),
                rrset.ttl(),
                expiration.unix_timestamp() as u32,
                inception.unix_timestamp() as u32,
                signer.calculate_key_tag()?,
                signer.signer_name().clone(),
                signature,
            ))),
        ));
    }
    records.extend(signatures);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_server::proto::{dnssec::Verifier, op::ResponseCode, rr::rdata::A};

    #[test]
    fn canonical_handshake_ksk_has_expected_key_tag() {
        let dnssec = RootDnssec::new().expect("embedded keys");
        assert_eq!(dnssec.ksk.calculate_key_tag().expect("key tag"), 35_215);
        assert_eq!(RootDnssec::trust_anchors().len(), 1);
    }

    #[test]
    fn signature_validation_rejects_tampered_root_data() {
        let dnssec = RootDnssec::new().expect("embedded keys");
        let owner = Name::from_ascii("example.").expect("owner");
        let mut answer = RootAnswer {
            response_code: ResponseCode::NoError,
            authoritative: true,
            answers: vec![Record::from_rdata(
                owner.clone(),
                300,
                RData::A(A::new(192, 0, 2, 1)),
            )],
            authorities: Vec::new(),
            soa: Vec::new(),
            additionals: Vec::new(),
        };
        dnssec.sign_answer(&mut answer, false).expect("sign answer");
        let zsk = dnssec
            .dnskey_records()
            .into_iter()
            .find_map(|record| match record.into_data() {
                RData::DNSSEC(DNSSECRData::DNSKEY(key)) if key.flags() == 256 => Some(key),
                _ => None,
            })
            .expect("ZSK");
        let rrsig = answer
            .answers
            .iter()
            .find_map(|record| match record.data() {
                RData::DNSSEC(DNSSECRData::RRSIG(rrsig))
                    if rrsig.type_covered() == RecordType::A =>
                {
                    Some(rrsig.clone())
                }
                _ => None,
            })
            .expect("A signature");
        let original = answer
            .answers
            .iter()
            .filter(|record| record.record_type() == RecordType::A);
        zsk.verify_rrsig(&owner, DNSClass::IN, &rrsig, original)
            .expect("original signature");

        let tampered = Record::from_rdata(owner.clone(), 300, RData::A(A::new(192, 0, 2, 2)));
        assert!(zsk
            .verify_rrsig(&owner, DNSClass::IN, &rrsig, std::iter::once(&tampered))
            .is_err());
    }
}
