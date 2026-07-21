use crate::{
    ClaimError, OwnershipClaimData, PrimitiveError, Reader, Writer, MAX_OWNERSHIP_PROOF_SIZE,
};

pub const DNS_CLASS_IN: u16 = 1;
pub const DNS_TYPE_TXT: u16 = 16;
pub const DNS_TYPE_DS: u16 = 43;
pub const DNS_TYPE_RRSIG: u16 = 46;
pub const DNS_TYPE_DNSKEY: u16 = 48;

const DNSKEY_REVOKE: u16 = 1 << 7;
const DNSSEC_ALG_RSASHA1: u8 = 5;
const DNSSEC_ALG_RSASHA1_NSEC3: u8 = 7;
const DNSSEC_ALG_RSASHA256: u8 = 8;
const DNSSEC_ALG_RSASHA512: u8 = 10;
const DNSSEC_ALG_ECDSA_P256_SHA256: u8 = 13;
const DNSSEC_ALG_ECDSA_P384_SHA384: u8 = 14;
const DNSSEC_ALG_ED25519: u8 = 15;
const DNSSEC_ALG_ED448: u8 = 16;
const DNSSEC_DIGEST_SHA1: u8 = 1;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct DnsName {
    pub labels: Vec<Vec<u8>>,
}

impl DnsName {
    fn read(reader: &mut Reader<'_>) -> Result<Self, OwnershipProofError> {
        let start = reader.position();
        let mut labels = Vec::new();
        loop {
            if labels.len() >= 127 {
                return Err(OwnershipProofError::DnsName);
            }
            let size = reader.read_u8()?;
            if size & 0xc0 != 0 {
                return Err(OwnershipProofError::DnsCompression);
            }
            if size == 0 {
                break;
            }
            if size > 63 {
                return Err(OwnershipProofError::DnsName);
            }
            labels.push(reader.read_vec(usize::from(size))?);
            if reader.position().saturating_sub(start) > 255 {
                return Err(OwnershipProofError::DnsName);
            }
        }
        if reader.position().saturating_sub(start) > 255 {
            return Err(OwnershipProofError::DnsName);
        }
        Ok(Self { labels })
    }

    fn write(&self, writer: &mut Writer, canonical: bool) -> Result<(), OwnershipProofError> {
        let mut size = 1usize;
        for label in &self.labels {
            if label.is_empty() || label.len() > 63 {
                return Err(OwnershipProofError::DnsName);
            }
            size = size
                .checked_add(1 + label.len())
                .ok_or(OwnershipProofError::DnsName)?;
            if size > 255 {
                return Err(OwnershipProofError::DnsName);
            }
            writer.write_u8(label.len() as u8);
            if canonical {
                writer.write_bytes(&label.iter().map(u8::to_ascii_lowercase).collect::<Vec<_>>());
            } else {
                writer.write_bytes(label);
            }
        }
        writer.write_u8(0);
        Ok(())
    }

    pub fn canonical_wire(&self) -> Result<Vec<u8>, OwnershipProofError> {
        let mut writer = Writer::new();
        self.write(&mut writer, true)?;
        Ok(writer.finish())
    }

    pub fn label_count(&self) -> usize {
        self.labels.len()
    }

    pub fn first_label(&self) -> Option<&[u8]> {
        self.labels.first().map(Vec::as_slice)
    }

    pub fn to_ascii_fqdn(&self) -> Option<String> {
        if self.labels.is_empty() {
            return Some(".".to_owned());
        }
        let mut output = String::new();
        for label in &self.labels {
            if !label.is_ascii() {
                return None;
            }
            if !output.is_empty() {
                output.push('.');
            }
            for byte in label {
                output.push(char::from(byte.to_ascii_lowercase()));
            }
        }
        output.push('.');
        Some(output)
    }

    fn eq_dns(&self, other: &Self) -> bool {
        self.labels.len() == other.labels.len()
            && self.labels.iter().zip(&other.labels).all(|(left, right)| {
                left.len() == right.len()
                    && left
                        .iter()
                        .zip(right)
                        .all(|(left, right)| left.eq_ignore_ascii_case(right))
            })
    }

    fn is_child_of(&self, parent: Option<&Self>) -> bool {
        match parent {
            None => self.labels.is_empty(),
            Some(parent) => {
                self.labels.len() == parent.labels.len() + 1
                    && self.labels[1..]
                        .iter()
                        .zip(&parent.labels)
                        .all(|(left, right)| {
                            left.len() == right.len()
                                && left
                                    .iter()
                                    .zip(right)
                                    .all(|(left, right)| left.eq_ignore_ascii_case(right))
                        })
            }
        }
    }

    fn wildcard_for_labels(&self, labels: usize) -> Option<Self> {
        if self.labels.len() < labels {
            return None;
        }
        if self.labels.len() == labels {
            return Some(self.clone());
        }
        let mut wildcard = Vec::with_capacity(labels + 1);
        wildcard.push(vec![b'*']);
        wildcard.extend_from_slice(&self.labels[self.labels.len() - labels..]);
        Some(Self { labels: wildcard })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsDnskey {
    pub flags: u16,
    pub protocol: u8,
    pub algorithm: u8,
    pub public_key: Vec<u8>,
}

impl DnsDnskey {
    pub fn key_tag(&self) -> u16 {
        let raw = self.encode();
        let mut tag = 0u32;
        for (index, byte) in raw.iter().copied().enumerate() {
            tag = tag.wrapping_add(if index & 1 == 0 {
                u32::from(byte) << 8
            } else {
                u32::from(byte)
            });
        }
        tag = tag.wrapping_add((tag >> 16) & 0xffff);
        tag as u16
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(4 + self.public_key.len());
        writer.write_u16_be(self.flags);
        writer.write_u8(self.protocol);
        writer.write_u8(self.algorithm);
        writer.write_bytes(&self.public_key);
        writer.finish()
    }

    pub fn rsa_bits(&self) -> usize {
        if !is_rsa_algorithm(self.algorithm) {
            return 0;
        }
        let Some(first) = self.public_key.first().copied() else {
            return 0;
        };
        let (exponent_size, offset) = if first == 0 {
            if self.public_key.len() < 3 {
                return 0;
            }
            (
                usize::from(u16::from_be_bytes([self.public_key[1], self.public_key[2]])),
                3usize,
            )
        } else {
            (usize::from(first), 1usize)
        };
        let Some(modulus) = self.public_key.get(offset.saturating_add(exponent_size)..) else {
            return 0;
        };
        let Some(first_nonzero) = modulus.iter().position(|byte| *byte != 0) else {
            return 0;
        };
        let significant = &modulus[first_nonzero..];
        significant.len() * 8 - significant[0].leading_zeros() as usize
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsDs {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRrsig {
    pub type_covered: u16,
    pub algorithm: u8,
    pub labels: u8,
    pub original_ttl: u32,
    pub expiration: u32,
    pub inception: u32,
    pub key_tag: u16,
    pub signer_name: DnsName,
    pub signature: Vec<u8>,
}

impl DnsRrsig {
    fn tbs(&self) -> Result<Vec<u8>, OwnershipProofError> {
        let mut writer = Writer::new();
        writer.write_u16_be(self.type_covered);
        writer.write_u8(self.algorithm);
        writer.write_u8(self.labels);
        writer.write_u32_be(self.original_ttl);
        writer.write_u32_be(self.expiration);
        writer.write_u32_be(self.inception);
        writer.write_u16_be(self.key_tag);
        self.signer_name.write(&mut writer, true)?;
        Ok(writer.finish())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DnsRecordData {
    Dnskey(DnsDnskey),
    Ds(DnsDs),
    Rrsig(DnsRrsig),
    Txt(Vec<Vec<u8>>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnsRecord {
    pub name: DnsName,
    pub record_type: u16,
    pub class: u16,
    pub ttl: u32,
    pub data: DnsRecordData,
}

impl DnsRecord {
    fn read_expected(reader: &mut Reader<'_>, expected: u16) -> Result<Self, OwnershipProofError> {
        let name = DnsName::read(reader)?;
        let record_type = reader.read_u16_be()?;
        if record_type != expected && record_type != DNS_TYPE_RRSIG {
            return Err(OwnershipProofError::UnexpectedRecordType {
                expected,
                actual: record_type,
            });
        }
        let class = reader.read_u16_be()?;
        let ttl = reader.read_u32_be()?;
        let size = usize::from(reader.read_u16_be()?);
        let raw = reader.read_vec(size)?;
        let mut data_reader = Reader::new(&raw, u16::MAX as usize)?;
        let data = match record_type {
            DNS_TYPE_DNSKEY => {
                let flags = data_reader.read_u16_be()?;
                let protocol = data_reader.read_u8()?;
                let algorithm = data_reader.read_u8()?;
                let public_key = data_reader.read_vec(data_reader.remaining())?;
                DnsRecordData::Dnskey(DnsDnskey {
                    flags,
                    protocol,
                    algorithm,
                    public_key,
                })
            }
            DNS_TYPE_DS => {
                let key_tag = data_reader.read_u16_be()?;
                let algorithm = data_reader.read_u8()?;
                let digest_type = data_reader.read_u8()?;
                let digest = data_reader.read_vec(data_reader.remaining())?;
                DnsRecordData::Ds(DnsDs {
                    key_tag,
                    algorithm,
                    digest_type,
                    digest,
                })
            }
            DNS_TYPE_RRSIG => {
                let type_covered = data_reader.read_u16_be()?;
                let algorithm = data_reader.read_u8()?;
                let labels = data_reader.read_u8()?;
                let original_ttl = data_reader.read_u32_be()?;
                let expiration = data_reader.read_u32_be()?;
                let inception = data_reader.read_u32_be()?;
                let key_tag = data_reader.read_u16_be()?;
                let signer_name = DnsName::read(&mut data_reader)?;
                let signature = data_reader.read_vec(data_reader.remaining())?;
                DnsRecordData::Rrsig(DnsRrsig {
                    type_covered,
                    algorithm,
                    labels,
                    original_ttl,
                    expiration,
                    inception,
                    key_tag,
                    signer_name,
                    signature,
                })
            }
            DNS_TYPE_TXT => {
                let mut items = Vec::new();
                while data_reader.remaining() != 0 {
                    let size = usize::from(data_reader.read_u8()?);
                    items.push(data_reader.read_vec(size)?);
                }
                DnsRecordData::Txt(items)
            }
            _ => unreachable!(),
        };
        data_reader.ensure_finished()?;
        Ok(Self {
            name,
            record_type,
            class,
            ttl,
            data,
        })
    }

    fn encode_rdata(&self, canonical: bool) -> Result<Vec<u8>, OwnershipProofError> {
        let mut writer = Writer::new();
        match &self.data {
            DnsRecordData::Dnskey(key) => writer.write_bytes(&key.encode()),
            DnsRecordData::Ds(ds) => {
                writer.write_u16_be(ds.key_tag);
                writer.write_u8(ds.algorithm);
                writer.write_u8(ds.digest_type);
                writer.write_bytes(&ds.digest);
            }
            DnsRecordData::Rrsig(signature) => {
                writer.write_u16_be(signature.type_covered);
                writer.write_u8(signature.algorithm);
                writer.write_u8(signature.labels);
                writer.write_u32_be(signature.original_ttl);
                writer.write_u32_be(signature.expiration);
                writer.write_u32_be(signature.inception);
                writer.write_u16_be(signature.key_tag);
                signature.signer_name.write(&mut writer, canonical)?;
                writer.write_bytes(&signature.signature);
            }
            DnsRecordData::Txt(items) => {
                for item in items {
                    let size =
                        u8::try_from(item.len()).map_err(|_| OwnershipProofError::TxtItem)?;
                    writer.write_u8(size);
                    writer.write_bytes(item);
                }
            }
        }
        Ok(writer.finish())
    }

    fn write(
        &self,
        writer: &mut Writer,
        canonical: bool,
        ttl: u32,
        owner: Option<&DnsName>,
    ) -> Result<(), OwnershipProofError> {
        owner.unwrap_or(&self.name).write(writer, canonical)?;
        writer.write_u16_be(self.record_type);
        writer.write_u16_be(self.class);
        writer.write_u32_be(ttl);
        let data = self.encode_rdata(canonical)?;
        let size = u16::try_from(data.len()).map_err(|_| OwnershipProofError::RecordData)?;
        writer.write_u16_be(size);
        writer.write_bytes(&data);
        Ok(())
    }

    pub fn encode(&self) -> Result<Vec<u8>, OwnershipProofError> {
        let mut writer = Writer::new();
        self.write(&mut writer, false, self.ttl, None)?;
        Ok(writer.finish())
    }

    pub fn dnskey(&self) -> Option<&DnsDnskey> {
        match &self.data {
            DnsRecordData::Dnskey(key) => Some(key),
            _ => None,
        }
    }

    pub fn ds(&self) -> Option<&DnsDs> {
        match &self.data {
            DnsRecordData::Ds(ds) => Some(ds),
            _ => None,
        }
    }

    pub fn rrsig(&self) -> Option<&DnsRrsig> {
        match &self.data {
            DnsRecordData::Rrsig(signature) => Some(signature),
            _ => None,
        }
    }

    pub fn txt(&self) -> Option<&[Vec<u8>]> {
        match &self.data {
            DnsRecordData::Txt(items) => Some(items),
            _ => None,
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OwnershipZone {
    pub keys: Vec<DnsRecord>,
    pub referral: Vec<DnsRecord>,
    pub claim: Vec<DnsRecord>,
}

impl OwnershipZone {
    fn read(reader: &mut Reader<'_>) -> Result<Self, OwnershipProofError> {
        let keys = read_records(reader, DNS_TYPE_DNSKEY)?;
        let referral = read_records(reader, DNS_TYPE_DS)?;
        let claim = read_records(reader, DNS_TYPE_TXT)?;
        Ok(Self {
            keys,
            referral,
            claim,
        })
    }

    fn write(&self, writer: &mut Writer) -> Result<(), OwnershipProofError> {
        write_records(writer, &self.keys)?;
        write_records(writer, &self.referral)?;
        write_records(writer, &self.claim)?;
        Ok(())
    }

    fn body(&self) -> &[DnsRecord] {
        if self.referral.is_empty() {
            &self.claim
        } else {
            &self.referral
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OwnershipProof {
    pub zones: Vec<OwnershipZone>,
}

impl OwnershipProof {
    pub fn decode(raw: &[u8]) -> Result<Self, OwnershipProofError> {
        if raw.len() > MAX_OWNERSHIP_PROOF_SIZE {
            return Err(OwnershipProofError::TooLarge(raw.len()));
        }
        let mut reader = Reader::new(raw, MAX_OWNERSHIP_PROOF_SIZE)?;
        let count = usize::from(reader.read_u8()?);
        let mut zones = Vec::with_capacity(count);
        for _ in 0..count {
            zones.push(OwnershipZone::read(&mut reader)?);
        }
        reader.ensure_finished()?;
        Ok(Self { zones })
    }

    pub fn encode(&self) -> Result<Vec<u8>, OwnershipProofError> {
        let count = u8::try_from(self.zones.len()).map_err(|_| OwnershipProofError::ZoneCount)?;
        let mut writer = Writer::new();
        writer.write_u8(count);
        for zone in &self.zones {
            zone.write(&mut writer)?;
        }
        let raw = writer.finish();
        if raw.len() > MAX_OWNERSHIP_PROOF_SIZE {
            return Err(OwnershipProofError::TooLarge(raw.len()));
        }
        Ok(raw)
    }

    pub fn target(&self) -> Option<&DnsName> {
        self.zones.last()?.claim.first().map(|record| &record.name)
    }

    pub fn name(&self) -> Option<&[u8]> {
        self.target()?.first_label()
    }

    pub fn window(&self) -> (u32, u32) {
        let mut inception = None;
        let mut expiration = None;
        for zone in &self.zones {
            for record in zone.keys.iter().chain(&zone.referral).chain(&zone.claim) {
                let Some(signature) = record.rrsig() else {
                    continue;
                };
                inception = Some(inception.map_or(signature.inception, |current: u32| {
                    current.max(signature.inception)
                }));
                expiration = Some(expiration.map_or(signature.expiration, |current: u32| {
                    current.min(signature.expiration)
                }));
            }
        }
        match (inception, expiration) {
            (Some(start), Some(end)) if start <= end => (start, end),
            _ => (0, 0),
        }
    }

    pub fn verify_time(&self, time: u64) -> bool {
        let (start, end) = self.window();
        time >= u64::from(start) && time <= u64::from(end)
    }

    pub fn is_sane(&self) -> bool {
        if self.zones.len() < 2 {
            return false;
        }
        let mut parent: Option<&DnsName> = None;
        for (index, zone) in self.zones.iter().enumerate() {
            let last = index + 1 == self.zones.len();
            let Some(zone_name) = zone.keys.first().map(|record| &record.name) else {
                return false;
            };
            if !zone_name.is_child_of(parent) {
                return false;
            }
            if last {
                if !zone.referral.is_empty() || zone.claim.is_empty() {
                    return false;
                }
            } else if zone.referral.is_empty() || !zone.claim.is_empty() {
                return false;
            }
            if !sane_set(&zone.keys, zone_name, DNS_TYPE_DNSKEY, zone_name)
                || (!zone.claim.is_empty()
                    && !sane_set(&zone.claim, zone_name, DNS_TYPE_TXT, zone_name))
            {
                return false;
            }
            if !zone.referral.is_empty() {
                let referral_name = &zone.referral[0].name;
                if !referral_name.is_child_of(Some(zone_name))
                    || !sane_set(&zone.referral, referral_name, DNS_TYPE_DS, zone_name)
                {
                    return false;
                }
            }
            parent = Some(zone_name);
        }
        true
    }

    pub fn is_weak(&self) -> bool {
        if self.zones.len() < 2 {
            return false;
        }
        for zone in &self.zones {
            for records in [&zone.keys[..], zone.body()] {
                let Some(key) = signing_key(records, &zone.keys) else {
                    continue;
                };
                if is_rsa_algorithm(key.algorithm) && key.rsa_bits() < 2041 {
                    return true;
                }
            }
        }
        false
    }

    pub fn claim_data(&self, prefix: &str) -> Result<Option<OwnershipClaimData>, ClaimError> {
        let Some(zone) = self.zones.last() else {
            return Ok(None);
        };
        for record in &zone.claim {
            let Some(items) = record.txt() else {
                continue;
            };
            let Some(first) = items.first() else {
                continue;
            };
            let Ok(txt) = std::str::from_utf8(first) else {
                continue;
            };
            if !txt.starts_with(prefix) {
                continue;
            }
            return OwnershipClaimData::decode_txt(txt, prefix).map(Some);
        }
        Ok(None)
    }

    pub fn verify_signatures(&self, verifier: &dyn DnssecVerifier) -> bool {
        self.verify_signatures_with_anchors(verifier, &[icann_root_anchor_2017()])
    }

    pub fn verify_signatures_with_anchors(
        &self,
        verifier: &dyn DnssecVerifier,
        anchors: &[DnssecAnchor],
    ) -> bool {
        if self.zones.len() < 2 {
            return false;
        }
        let mut current = anchors.to_vec();
        for zone in &self.zones[..self.zones.len() - 1] {
            if !verify_keys(&zone.keys, &current, verifier)
                || !verify_records(&zone.referral, &zone.keys, verifier)
            {
                return false;
            }
            current = zone
                .referral
                .iter()
                .filter_map(DnsRecord::ds)
                .map(DnssecAnchor::from)
                .collect();
        }
        let Some(zone) = self.zones.last() else {
            return false;
        };
        verify_keys(&zone.keys, &current, verifier)
            && verify_records(&zone.claim, &zone.keys, verifier)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DnssecAnchor {
    pub key_tag: u16,
    pub algorithm: u8,
    pub digest_type: u8,
    pub digest: Vec<u8>,
}

impl From<&DnsDs> for DnssecAnchor {
    fn from(ds: &DnsDs) -> Self {
        Self {
            key_tag: ds.key_tag,
            algorithm: ds.algorithm,
            digest_type: ds.digest_type,
            digest: ds.digest.clone(),
        }
    }
}

pub fn icann_root_anchor_2017() -> DnssecAnchor {
    DnssecAnchor {
        key_tag: 20_326,
        algorithm: DNSSEC_ALG_RSASHA256,
        digest_type: 2,
        digest: [
            0xe0, 0x6d, 0x44, 0xb8, 0x0b, 0x8f, 0x1d, 0x39, 0xa9, 0x5c, 0x0b, 0x0d, 0x7c, 0x65,
            0xd0, 0x84, 0x58, 0xe8, 0x80, 0x40, 0x9b, 0xbc, 0x68, 0x34, 0x57, 0x10, 0x42, 0x37,
            0xc7, 0xf8, 0xec, 0x8d,
        ]
        .to_vec(),
    }
}

pub trait DnssecVerifier: Send + Sync {
    fn digest(&self, digest_type: u8, data: &[u8]) -> Option<Vec<u8>>;

    fn verify(&self, algorithm: u8, public_key: &[u8], data: &[u8], signature: &[u8]) -> bool;
}

fn read_records(
    reader: &mut Reader<'_>,
    expected: u16,
) -> Result<Vec<DnsRecord>, OwnershipProofError> {
    let count = usize::from(reader.read_u8()?);
    let mut records = Vec::with_capacity(count);
    for _ in 0..count {
        records.push(DnsRecord::read_expected(reader, expected)?);
    }
    Ok(records)
}

fn write_records(writer: &mut Writer, records: &[DnsRecord]) -> Result<(), OwnershipProofError> {
    let count = u8::try_from(records.len()).map_err(|_| OwnershipProofError::RecordCount)?;
    writer.write_u8(count);
    for record in records {
        record.write(writer, false, record.ttl, None)?;
    }
    Ok(())
}

fn sane_set(records: &[DnsRecord], name: &DnsName, expected: u16, signer: &DnsName) -> bool {
    let mut saw_signature = false;
    for record in records {
        if !record.name.eq_dns(name) {
            return false;
        }
        match &record.data {
            DnsRecordData::Rrsig(signature) => {
                if signature.type_covered != expected
                    || !is_valid_algorithm(signature.algorithm)
                    || usize::from(signature.labels) != name.label_count()
                    || !signature.signer_name.eq_dns(signer)
                    || saw_signature
                {
                    return false;
                }
                saw_signature = true;
            }
            DnsRecordData::Dnskey(_) if expected == DNS_TYPE_DNSKEY => {}
            DnsRecordData::Ds(_) if expected == DNS_TYPE_DS => {}
            DnsRecordData::Txt(_) if expected == DNS_TYPE_TXT => {}
            _ => return false,
        }
    }
    saw_signature
}

fn is_valid_algorithm(algorithm: u8) -> bool {
    matches!(
        algorithm,
        DNSSEC_ALG_RSASHA1
            | DNSSEC_ALG_RSASHA1_NSEC3
            | DNSSEC_ALG_RSASHA256
            | DNSSEC_ALG_RSASHA512
            | DNSSEC_ALG_ECDSA_P256_SHA256
            | DNSSEC_ALG_ECDSA_P384_SHA384
            | DNSSEC_ALG_ED25519
            | DNSSEC_ALG_ED448
    )
}

fn is_rsa_algorithm(algorithm: u8) -> bool {
    matches!(
        algorithm,
        DNSSEC_ALG_RSASHA1 | DNSSEC_ALG_RSASHA1_NSEC3 | DNSSEC_ALG_RSASHA256 | DNSSEC_ALG_RSASHA512
    )
}

fn first_signature(records: &[DnsRecord]) -> Option<&DnsRrsig> {
    records.iter().find_map(DnsRecord::rrsig)
}

fn find_key(records: &[DnsRecord], key_tag: u16) -> Option<&DnsDnskey> {
    find_key_record(records, key_tag).and_then(DnsRecord::dnskey)
}

fn find_key_record(records: &[DnsRecord], key_tag: u16) -> Option<&DnsRecord> {
    records.iter().find(|record| {
        let Some(key) = record.dnskey() else {
            return false;
        };
        key.key_tag() == key_tag && key.flags & DNSKEY_REVOKE == 0
    })
}

fn signing_key<'a>(records: &[DnsRecord], keys: &'a [DnsRecord]) -> Option<&'a DnsDnskey> {
    find_key(keys, first_signature(records)?.key_tag)
}

fn candidate_key(record: &DnsRecord, key_tag: u16) -> Option<&DnsDnskey> {
    let key = record.dnskey()?;
    (key.key_tag() == key_tag && key.flags & DNSKEY_REVOKE == 0).then_some(key)
}

fn split_set(records: &[DnsRecord]) -> (Option<&DnsRecord>, Vec<&DnsRecord>) {
    let mut signature = None;
    let mut rrset = Vec::new();
    for record in records {
        if record.record_type == DNS_TYPE_RRSIG {
            signature = Some(record);
        } else {
            rrset.push(record);
        }
    }
    if rrset.is_empty() {
        (None, rrset)
    } else {
        (signature, rrset)
    }
}

fn verify_keys(
    records: &[DnsRecord],
    anchors: &[DnssecAnchor],
    verifier: &dyn DnssecVerifier,
) -> bool {
    let Some(signature) = first_signature(records) else {
        return false;
    };
    let Some(ksk_record) = find_key_record(records, signature.key_tag) else {
        return false;
    };
    let Some(ksk) = ksk_record.dnskey() else {
        return false;
    };
    let mut candidates = vec![ksk_record];
    if matches!(ksk.algorithm, DNSSEC_ALG_RSASHA256 | DNSSEC_ALG_RSASHA512) {
        for record in records {
            let Some(key) = record.dnskey() else {
                continue;
            };
            if matches!(key.algorithm, DNSSEC_ALG_RSASHA1 | DNSSEC_ALG_RSASHA1_NSEC3)
                && key.flags & DNSKEY_REVOKE == 0
                && key.public_key == ksk.public_key
                && !candidates.iter().any(|candidate| {
                    candidate
                        .dnskey()
                        .is_some_and(|candidate| candidate.key_tag() == key.key_tag())
                })
            {
                candidates.push(record);
            }
        }
    }

    let Some(owner) = records.first().map(|record| &record.name) else {
        return false;
    };
    let trusted = anchors.iter().any(|anchor| {
        if anchor.digest_type == DNSSEC_DIGEST_SHA1 {
            return false;
        }
        let Some(key) = candidates
            .iter()
            .copied()
            .find_map(|record| candidate_key(record, anchor.key_tag))
        else {
            return false;
        };
        let mut data = match owner.canonical_wire() {
            Ok(data) => data,
            Err(_) => return false,
        };
        data.extend_from_slice(&key.encode());
        verifier
            .digest(anchor.digest_type, &data)
            .is_some_and(|digest| digest == anchor.digest && key.algorithm == anchor.algorithm)
    });
    if !trusted {
        return false;
    }

    let (signature, rrset) = split_set(records);
    signature.is_some_and(|signature| verify_signature(signature, ksk_record, &rrset, verifier))
}

fn verify_records(
    records: &[DnsRecord],
    keys: &[DnsRecord],
    verifier: &dyn DnssecVerifier,
) -> bool {
    let (signature, rrset) = split_set(records);
    let Some(signature) = signature else {
        return false;
    };
    let Some(data) = signature.rrsig() else {
        return false;
    };
    let Some(key) = find_key_record(keys, data.key_tag) else {
        return false;
    };
    verify_signature(signature, key, &rrset, verifier)
}

fn verify_signature(
    signature_record: &DnsRecord,
    key_record: &DnsRecord,
    rrset: &[&DnsRecord],
    verifier: &dyn DnssecVerifier,
) -> bool {
    let Some(signature) = signature_record.rrsig() else {
        return false;
    };
    let Some(key) = key_record.dnskey() else {
        return false;
    };
    if rrset.is_empty()
        || key.key_tag() != signature.key_tag
        || signature_record.class != key_record.class
        || signature.algorithm != key.algorithm
        || key.protocol != 3
        || rrset[0].class != signature_record.class
        || rrset[0].record_type != signature.type_covered
        || !signature.signer_name.eq_dns(&key_record.name)
        || !rrset.iter().all(|record| {
            record.name.eq_dns(&rrset[0].name)
                && record.class == rrset[0].class
                && record.record_type == rrset[0].record_type
        })
        || !verify_key(key)
    {
        return false;
    }
    let Some(data) = signature_data(signature, rrset) else {
        return false;
    };
    verifier.verify(
        signature.algorithm,
        &key.public_key,
        &data,
        &signature.signature,
    )
}

fn verify_key(key: &DnsDnskey) -> bool {
    if !is_valid_algorithm(key.algorithm)
        || matches!(key.algorithm, DNSSEC_ALG_RSASHA1 | DNSSEC_ALG_RSASHA1_NSEC3)
    {
        return false;
    }
    if is_rsa_algorithm(key.algorithm) {
        return (1017..=4096).contains(&key.rsa_bits());
    }
    true
}

fn signature_data(signature: &DnsRrsig, rrset: &[&DnsRecord]) -> Option<Vec<u8>> {
    let mut records = Vec::with_capacity(rrset.len());
    for record in rrset {
        let owner = record
            .name
            .wildcard_for_labels(usize::from(signature.labels))?;
        let mut writer = Writer::new();
        record
            .write(&mut writer, true, signature.original_ttl, Some(&owner))
            .ok()?;
        records.push(writer.finish());
    }
    records.sort();
    records.dedup();
    let mut data = signature.tbs().ok()?;
    for record in records {
        data.extend_from_slice(&record);
    }
    Some(data)
}

#[derive(Debug, thiserror::Error)]
pub enum OwnershipProofError {
    #[error("ownership proof codec failed: {0}")]
    Codec(#[from] PrimitiveError),
    #[error("ownership proof exceeds {MAX_OWNERSHIP_PROOF_SIZE} bytes: {0}")]
    TooLarge(usize),
    #[error("compressed DNS names are forbidden in ownership proofs")]
    DnsCompression,
    #[error("invalid DNS name in ownership proof")]
    DnsName,
    #[error("expected DNS record type {expected}, got {actual}")]
    UnexpectedRecordType { expected: u16, actual: u16 },
    #[error("DNS TXT item exceeds 255 bytes")]
    TxtItem,
    #[error("DNS record data exceeds 65535 bytes")]
    RecordData,
    #[error("ownership proof contains more than 255 zones")]
    ZoneCount,
    #[error("ownership proof record set contains more than 255 records")]
    RecordCount,
}

#[cfg(test)]
mod tests {
    use serde::Deserialize;

    use super::*;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Fixture {
        proof: ProofFixture,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ProofFixture {
        raw: String,
        size: usize,
        zones: usize,
        target: String,
        name: String,
        sane: bool,
        weak: bool,
        inception: u32,
        expiration: u32,
    }

    fn fixture() -> Fixture {
        serde_json::from_str(include_str!("../../../fixtures/hsd/claims/codec-v1.json"))
            .expect("HSD ownership proof fixture")
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        value
            .as_bytes()
            .chunks_exact(2)
            .map(|pair| (nibble(pair[0]) << 4) | nibble(pair[1]))
            .collect()
    }

    fn nibble(value: u8) -> u8 {
        match value {
            b'0'..=b'9' => value - b'0',
            b'a'..=b'f' => value - b'a' + 10,
            _ => panic!("invalid fixture hex"),
        }
    }

    #[test]
    fn ownership_proof_codec_sanity_window_and_weakness_match_hsd() {
        let expected = fixture().proof;
        let raw = decode_hex(&expected.raw);
        assert_eq!(raw.len(), expected.size);
        let proof = OwnershipProof::decode(&raw).expect("HSD ownership proof");
        assert_eq!(proof.encode().expect("proof encode"), raw);
        assert_eq!(proof.zones.len(), expected.zones);
        assert_eq!(
            proof.target().and_then(DnsName::to_ascii_fqdn),
            Some(expected.target)
        );
        assert_eq!(proof.name(), Some(expected.name.as_bytes()));
        assert_eq!(proof.is_sane(), expected.sane);
        assert_eq!(proof.is_weak(), expected.weak);
        assert_eq!(proof.window(), (expected.inception, expected.expiration));
        assert!(proof.verify_time(u64::from(expected.inception)));
        assert!(proof.verify_time(u64::from(expected.expiration)));
        assert!(!proof.verify_time(u64::from(expected.inception) - 1));
        assert!(!proof.verify_time(u64::from(expected.expiration) + 1));
    }

    #[test]
    fn ownership_proof_rejects_compression_trailing_and_wrong_record_type() {
        let raw = decode_hex(&fixture().proof.raw);
        let mut trailing = raw.clone();
        trailing.push(0);
        assert!(OwnershipProof::decode(&trailing).is_err());

        let mut compressed_root = raw.clone();
        compressed_root[2] = 0xc0;
        assert!(matches!(
            OwnershipProof::decode(&compressed_root),
            Err(OwnershipProofError::DnsCompression)
        ));

        let proof = OwnershipProof::decode(&raw).expect("HSD ownership proof");
        let mut wrong = proof.clone();
        wrong.zones[0].keys[0].record_type = DNS_TYPE_TXT;
        let encoded = wrong.encode().expect("structurally encodable proof");
        assert!(matches!(
            OwnershipProof::decode(&encoded),
            Err(OwnershipProofError::UnexpectedRecordType { .. })
        ));
    }
}
