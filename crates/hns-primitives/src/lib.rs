#![forbid(unsafe_code)]

use blake2::{
    digest::{Update, VariableOutput},
    Blake2b512, Blake2bVar, Digest,
};
use serde::{Deserialize, Serialize};
use sha3::{Keccak256, Sha3_256};
use std::fmt;

pub const HEADER_SIZE: usize = 236;
pub const NONCE_SIZE: usize = 24;
pub const MAX_BLOCK_WEIGHT: usize = 4_000_000;
pub const MAX_TX_SIZE: usize = 1_000_000;
pub const MAX_RESOURCE_SIZE: usize = 512;
pub const MAX_SCRIPT_STACK: usize = 1_000;
pub const MAX_ADDRESS_HASH_SIZE: usize = 40;
pub const MIN_ADDRESS_HASH_SIZE: usize = 2;
pub const MAX_NAME_SIZE: usize = 63;

pub type Amount = u64;
pub type Height = u32;

#[derive(
    Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize,
)]
pub struct Uint256([u8; 32]);

impl Uint256 {
    pub const ZERO: Self = Self([0; 32]);
    pub const ONE: Self = Self::from_u64(1);

    pub const fn from_be_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn to_be_bytes(self) -> [u8; 32] {
        self.0
    }

    pub const fn as_be_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn from_u64(value: u64) -> Self {
        let mut bytes = [0; 32];
        let value = value.to_be_bytes();
        let mut index = 0;
        while index < 8 {
            bytes[24 + index] = value[index];
            index += 1;
        }
        Self(bytes)
    }

    pub const fn from_u128(value: u128) -> Self {
        let mut bytes = [0; 32];
        let value = value.to_be_bytes();
        let mut index = 0;
        while index < 16 {
            bytes[16 + index] = value[index];
            index += 1;
        }
        Self(bytes)
    }

    pub fn checked_add(self, other: Self) -> Option<Self> {
        let mut output = [0; 32];
        let mut carry = 0u16;
        for index in (0..32).rev() {
            let sum = u16::from(self.0[index]) + u16::from(other.0[index]) + carry;
            output[index] = sum as u8;
            carry = sum >> 8;
        }
        (carry == 0).then_some(Self(output))
    }

    pub fn checked_sub(self, other: Self) -> Option<Self> {
        (self >= other).then(|| self.wrapping_sub(other))
    }

    pub fn checked_mul_u64(self, multiplier: u64) -> Option<Self> {
        let mut output = [0; 32];
        let mut carry = 0u128;
        for index in (0..32).rev() {
            let product = u128::from(self.0[index]) * u128::from(multiplier) + carry;
            output[index] = product as u8;
            carry = product >> 8;
        }
        (carry == 0).then_some(Self(output))
    }

    pub fn div_u64(self, divisor: u64) -> Option<Self> {
        if divisor == 0 {
            return None;
        }
        let mut output = [0; 32];
        let mut remainder = 0u128;
        for (index, byte) in self.0.into_iter().enumerate() {
            let dividend = (remainder << 8) | u128::from(byte);
            output[index] = (dividend / u128::from(divisor)) as u8;
            remainder = dividend % u128::from(divisor);
        }
        Some(Self(output))
    }

    pub fn work_for_target(target: Self) -> Option<Self> {
        if target == Self::ZERO {
            return None;
        }

        let Some(divisor) = target.checked_add(Self::ONE) else {
            return Some(Self::ONE);
        };
        Self::divide_two_to_256(divisor)
    }

    pub fn target_for_work(work: Self) -> Option<Self> {
        if work == Self::ZERO {
            return None;
        }
        if work == Self::ONE {
            return Some(Self([0xff; 32]));
        }
        Self::divide_two_to_256(work)?.checked_sub(Self::ONE)
    }

    pub fn to_fixed_hex(self) -> String {
        hex_encode(&self.0)
    }

    fn shift_left_one(&mut self) -> bool {
        let high = (self.0[0] & 0x80) != 0;
        let mut carry = 0;
        for byte in self.0.iter_mut().rev() {
            let next_carry = *byte >> 7;
            *byte = (*byte << 1) | carry;
            carry = next_carry;
        }
        high
    }

    fn wrapping_sub(self, other: Self) -> Self {
        let mut output = [0; 32];
        let mut borrow = 0i16;
        for index in (0..32).rev() {
            let difference = i16::from(self.0[index]) - i16::from(other.0[index]) - borrow;
            if difference < 0 {
                output[index] = (difference + 256) as u8;
                borrow = 1;
            } else {
                output[index] = difference as u8;
                borrow = 0;
            }
        }
        Self(output)
    }

    fn set_bit(&mut self, bit: usize) {
        debug_assert!(bit < 256);
        self.0[31 - bit / 8] |= 1 << (bit % 8);
    }

    fn divide_two_to_256(divisor: Self) -> Option<Self> {
        if divisor == Self::ZERO || divisor == Self::ONE {
            return None;
        }
        let mut remainder = Self::ZERO;
        let mut quotient = Self::ZERO;

        for bit in (0..=256).rev() {
            let high = remainder.shift_left_one();
            if bit == 256 {
                remainder.0[31] |= 1;
            }

            if high || remainder >= divisor {
                remainder = remainder.wrapping_sub(divisor);
                if bit < 256 {
                    quotient.set_bit(bit);
                }
            }
        }

        Some(quotient)
    }
}

impl From<u64> for Uint256 {
    fn from(value: u64) -> Self {
        Self::from_u64(value)
    }
}

impl From<u128> for Uint256 {
    fn from(value: u128) -> Self {
        Self::from_u128(value)
    }
}

impl fmt::LowerHex for Uint256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Some(first) = self.0.iter().position(|byte| *byte != 0) else {
            return formatter.write_str("0");
        };
        write!(formatter, "{:x}", self.0[first])?;
        for byte in &self.0[first + 1..] {
            write!(formatter, "{byte:02x}")?;
        }
        Ok(())
    }
}

macro_rules! hash_type {
    ($name:ident) => {
        #[derive(
            Clone,
            Copy,
            Debug,
            Default,
            Eq,
            Hash,
            Ord,
            PartialEq,
            PartialOrd,
            Serialize,
            Deserialize,
        )]
        pub struct $name([u8; 32]);

        impl $name {
            pub const ZERO: Self = Self([0; 32]);

            pub const fn new(bytes: [u8; 32]) -> Self {
                Self(bytes)
            }

            pub fn as_bytes(&self) -> &[u8; 32] {
                &self.0
            }

            pub const fn into_inner(self) -> [u8; 32] {
                self.0
            }

            pub fn to_hex(self) -> String {
                hex_encode(&self.0)
            }
        }
    };
}

hash_type!(BlockHash);
hash_type!(Txid);
hash_type!(NameHash);

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Header {
    pub nonce: u32,
    pub time: u64,
    pub prev_block: BlockHash,
    pub tree_root: [u8; 32],
    pub extra_nonce: [u8; NONCE_SIZE],
    pub reserved_root: [u8; 32],
    pub witness_root: [u8; 32],
    pub merkle_root: [u8; 32],
    pub version: u32,
    pub bits: u32,
    pub mask: [u8; 32],
}

impl Default for Header {
    fn default() -> Self {
        Self {
            nonce: 0,
            time: 0,
            prev_block: BlockHash::ZERO,
            tree_root: [0; 32],
            extra_nonce: [0; NONCE_SIZE],
            reserved_root: [0; 32],
            witness_root: [0; 32],
            merkle_root: [0; 32],
            version: 0,
            bits: 0,
            mask: [0; 32],
        }
    }
}

impl Header {
    pub fn from_raw(raw: Vec<u8>) -> Result<Self, PrimitiveError> {
        Self::decode(&raw)
    }

    pub fn decode(raw: &[u8]) -> Result<Self, PrimitiveError> {
        if raw.len() != HEADER_SIZE {
            return Err(PrimitiveError::InvalidLength {
                context: "header",
                expected: HEADER_SIZE,
                actual: raw.len(),
            });
        }

        let mut reader = Reader::new(raw, HEADER_SIZE)?;
        let header = Self::read_from(&mut reader)?;
        reader.ensure_finished()?;
        Ok(header)
    }

    pub fn read_from(reader: &mut Reader<'_>) -> Result<Self, PrimitiveError> {
        Ok(Self {
            nonce: reader.read_u32()?,
            time: reader.read_u64()?,
            prev_block: BlockHash::new(reader.read_hash()?),
            tree_root: reader.read_hash()?,
            extra_nonce: reader.read_nonce()?,
            reserved_root: reader.read_hash()?,
            witness_root: reader.read_hash()?,
            merkle_root: reader.read_hash()?,
            version: reader.read_u32()?,
            bits: reader.read_u32()?,
            mask: reader.read_hash()?,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::with_capacity(HEADER_SIZE);
        self.write_to(&mut writer);
        writer.finish()
    }

    pub fn hash(&self) -> BlockHash {
        BlockHash::new(self.pow_hash())
    }

    pub fn subheader(&self) -> [u8; 128] {
        let mut writer = Writer::with_capacity(128);
        writer.write_bytes(&self.extra_nonce);
        writer.write_bytes(&self.reserved_root);
        writer.write_bytes(&self.witness_root);
        writer.write_bytes(&self.merkle_root);
        writer.write_u32(self.version);
        writer.write_u32(self.bits);
        fixed_128(writer.finish())
    }

    pub fn sub_hash(&self) -> [u8; 32] {
        blake2b_256(&self.subheader())
    }

    pub fn mask_hash(&self) -> [u8; 32] {
        blake2b_256_many([self.prev_block.as_bytes().as_slice(), self.mask.as_slice()])
    }

    pub fn commit_hash(&self) -> [u8; 32] {
        let sub_hash = self.sub_hash();
        let mask_hash = self.mask_hash();
        blake2b_256_many([sub_hash.as_slice(), mask_hash.as_slice()])
    }

    pub fn preheader(&self) -> [u8; 128] {
        let commit_hash = self.commit_hash();
        let mut writer = Writer::with_capacity(128);
        writer.write_u32(self.nonce);
        writer.write_u64(self.time);
        writer.write_bytes(&self.padding(20));
        writer.write_bytes(self.prev_block.as_bytes());
        writer.write_bytes(&self.tree_root);
        writer.write_bytes(&commit_hash);
        fixed_128(writer.finish())
    }

    pub fn share_hash(&self) -> [u8; 32] {
        let preheader = self.preheader();
        let left = blake2b_512(&preheader);
        let padding32 = self.padding(32);
        let padding8 = self.padding(8);
        let right = sha3_256_many([preheader.as_slice(), padding8.as_slice()]);
        blake2b_256_many([left.as_slice(), padding32.as_slice(), right.as_slice()])
    }

    pub fn pow_hash(&self) -> [u8; 32] {
        let mut hash = self.share_hash();

        for (byte, mask) in hash.iter_mut().zip(self.mask) {
            *byte ^= mask;
        }

        hash
    }

    pub fn verify_pow(&self) -> bool {
        CompactTarget::from_bits(self.bits).is_met_by(&self.pow_hash())
    }

    pub fn padding(&self, size: usize) -> Vec<u8> {
        (0..size)
            .map(|index| self.prev_block.as_bytes()[index % 32] ^ self.tree_root[index % 32])
            .collect()
    }

    pub fn write_to(&self, writer: &mut Writer) {
        writer.write_u32(self.nonce);
        writer.write_u64(self.time);
        writer.write_bytes(self.prev_block.as_bytes());
        writer.write_bytes(&self.tree_root);
        writer.write_bytes(&self.extra_nonce);
        writer.write_bytes(&self.reserved_root);
        writer.write_bytes(&self.witness_root);
        writer.write_bytes(&self.merkle_root);
        writer.write_u32(self.version);
        writer.write_u32(self.bits);
        writer.write_bytes(&self.mask);
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<Input>,
    pub outputs: Vec<Output>,
    pub locktime: u32,
}

impl Transaction {
    pub fn from_raw(raw: Vec<u8>) -> Result<Self, PrimitiveError> {
        Self::decode(&raw)
    }

    pub fn decode(raw: &[u8]) -> Result<Self, PrimitiveError> {
        let mut reader = Reader::new(raw, MAX_TX_SIZE)?;
        let transaction = Self::read_from(&mut reader)?;
        reader.ensure_finished()?;
        Ok(transaction)
    }

    pub fn read_from(reader: &mut Reader<'_>) -> Result<Self, PrimitiveError> {
        let version = reader.read_u32()?;
        let input_count = reader.read_varint_usize("transaction inputs")?;
        let mut inputs = Vec::with_capacity(input_count);

        for _ in 0..input_count {
            inputs.push(Input::read_from(reader)?);
        }

        let output_count = reader.read_varint_usize("transaction outputs")?;
        let mut outputs = Vec::with_capacity(output_count);

        for _ in 0..output_count {
            outputs.push(Output::read_from(reader)?);
        }

        let locktime = reader.read_u32()?;

        for input in &mut inputs {
            input.witness = Witness::read_from(reader)?;
        }

        Ok(Self {
            version,
            inputs,
            outputs,
            locktime,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        self.write_to(&mut writer);
        writer.finish()
    }

    pub fn base_encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        self.write_base_to(&mut writer);
        writer.finish()
    }

    pub fn witness_encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();

        for input in &self.inputs {
            input.witness.write_to(&mut writer);
        }

        writer.finish()
    }

    pub fn base_size(&self) -> usize {
        self.base_encode().len()
    }

    pub fn witness_size(&self) -> usize {
        self.witness_encode().len()
    }

    pub fn txid(&self) -> Txid {
        Txid::new(blake2b_256(&self.base_encode()))
    }

    pub fn witness_data_hash(&self) -> [u8; 32] {
        blake2b_256(&self.witness_encode())
    }

    pub fn witness_hash(&self) -> [u8; 32] {
        let txid = self.txid();
        let witness_data_hash = self.witness_data_hash();
        blake2b_256_many([txid.as_bytes().as_slice(), witness_data_hash.as_slice()])
    }

    pub fn write_to(&self, writer: &mut Writer) {
        self.write_base_to(writer);

        for input in &self.inputs {
            input.witness.write_to(writer);
        }
    }

    pub fn write_base_to(&self, writer: &mut Writer) {
        writer.write_u32(self.version);
        writer.write_varint(self.inputs.len() as u64);

        for input in &self.inputs {
            input.write_to(writer);
        }

        writer.write_varint(self.outputs.len() as u64);

        for output in &self.outputs {
            output.write_to(writer);
        }

        writer.write_u32(self.locktime);
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Input {
    pub previous_output: Outpoint,
    pub sequence: u32,
    pub witness: Witness,
}

impl Input {
    pub fn read_from(reader: &mut Reader<'_>) -> Result<Self, PrimitiveError> {
        Ok(Self {
            previous_output: Outpoint::read_from(reader)?,
            sequence: reader.read_u32()?,
            witness: Witness::default(),
        })
    }

    pub fn write_to(&self, writer: &mut Writer) {
        self.previous_output.write_to(writer);
        writer.write_u32(self.sequence);
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Witness {
    pub items: Vec<Vec<u8>>,
}

impl Witness {
    pub fn read_from(reader: &mut Reader<'_>) -> Result<Self, PrimitiveError> {
        let count = reader.read_varint_usize("witness items")?;

        if count > MAX_SCRIPT_STACK {
            return Err(PrimitiveError::LimitExceeded {
                context: "witness items",
                limit: MAX_SCRIPT_STACK,
                actual: count,
            });
        }

        let mut items = Vec::with_capacity(count);

        for _ in 0..count {
            items.push(reader.read_varbytes(MAX_TX_SIZE, "witness item")?);
        }

        Ok(Self { items })
    }

    pub fn write_to(&self, writer: &mut Writer) {
        writer.write_varint(self.items.len() as u64);

        for item in &self.items {
            writer.write_varbytes(item);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Output {
    pub value: Amount,
    pub address: Address,
    pub covenant: Covenant,
}

impl Output {
    pub fn decode(raw: &[u8]) -> Result<Self, PrimitiveError> {
        let mut reader = Reader::new(raw, MAX_TX_SIZE)?;
        let output = Self::read_from(&mut reader)?;
        reader.ensure_finished()?;
        Ok(output)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        self.write_to(&mut writer);
        writer.finish()
    }

    pub fn read_from(reader: &mut Reader<'_>) -> Result<Self, PrimitiveError> {
        Ok(Self {
            value: reader.read_u64()?,
            address: Address::read_from(reader)?,
            covenant: Covenant::read_from(reader)?,
        })
    }

    pub fn write_to(&self, writer: &mut Writer) {
        writer.write_u64(self.value);
        self.address.write_to(writer);
        self.covenant.write_to(writer);
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Address {
    pub version: u8,
    pub hash: Vec<u8>,
}

impl Address {
    pub fn new(version: u8, hash: Vec<u8>) -> Result<Self, PrimitiveError> {
        let address = Self { version, hash };
        address.validate()?;
        Ok(address)
    }

    pub fn read_from(reader: &mut Reader<'_>) -> Result<Self, PrimitiveError> {
        let version = reader.read_u8()?;
        let size = usize::from(reader.read_u8()?);
        let hash = reader.read_vec(size)?;
        Self::new(version, hash)
    }

    pub fn write_to(&self, writer: &mut Writer) {
        writer.write_u8(self.version);
        writer.write_u8(self.hash.len() as u8);
        writer.write_bytes(&self.hash);
    }

    pub fn validate(&self) -> Result<(), PrimitiveError> {
        if self.version > 31 {
            return Err(PrimitiveError::InvalidAddress("version exceeds 31"));
        }

        if !(MIN_ADDRESS_HASH_SIZE..=MAX_ADDRESS_HASH_SIZE).contains(&self.hash.len()) {
            return Err(PrimitiveError::InvalidAddress(
                "hash length is outside 2..=40",
            ));
        }

        if self.version == 0 && self.hash.len() != 20 && self.hash.len() != 32 {
            return Err(PrimitiveError::InvalidAddress(
                "version 0 witness program must be 20 or 32 bytes",
            ));
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Block {
    pub header: Header,
    pub transactions: Vec<Transaction>,
}

impl Block {
    pub fn from_raw(raw: Vec<u8>) -> Result<Self, PrimitiveError> {
        Self::decode(&raw)
    }

    pub fn decode(raw: &[u8]) -> Result<Self, PrimitiveError> {
        let mut reader = Reader::new(raw, MAX_BLOCK_WEIGHT)?;
        let block = Self::read_from(&mut reader)?;
        reader.ensure_finished()?;
        Ok(block)
    }

    pub fn read_from(reader: &mut Reader<'_>) -> Result<Self, PrimitiveError> {
        let header = Header::read_from(reader)?;
        let transaction_count = reader.read_varint_usize("block transactions")?;
        let mut transactions = Vec::with_capacity(transaction_count);

        for _ in 0..transaction_count {
            transactions.push(Transaction::read_from(reader)?);
        }

        Ok(Self {
            header,
            transactions,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        self.write_to(&mut writer);
        writer.finish()
    }

    pub fn hash(&self) -> BlockHash {
        self.header.hash()
    }

    pub fn write_to(&self, writer: &mut Writer) {
        self.header.write_to(writer);
        writer.write_varint(self.transactions.len() as u64);

        for transaction in &self.transactions {
            transaction.write_to(writer);
        }
    }
}

#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub struct Outpoint {
    pub txid: Txid,
    pub index: u32,
}

impl Outpoint {
    pub fn read_from(reader: &mut Reader<'_>) -> Result<Self, PrimitiveError> {
        Ok(Self {
            txid: Txid::new(reader.read_hash()?),
            index: reader.read_u32()?,
        })
    }

    pub fn write_to(&self, writer: &mut Writer) {
        writer.write_bytes(self.txid.as_bytes());
        writer.write_u32(self.index);
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Coin {
    pub outpoint: Outpoint,
    pub value: Amount,
    pub height: Height,
    pub coinbase: bool,
    pub address: Address,
    pub covenant: Covenant,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Script {
    pub raw: Vec<u8>,
}

impl Script {
    pub fn new(raw: Vec<u8>) -> Result<Self, PrimitiveError> {
        if raw.len() > MAX_TX_SIZE {
            return Err(PrimitiveError::LimitExceeded {
                context: "script",
                limit: MAX_TX_SIZE,
                actual: raw.len(),
            });
        }

        Ok(Self { raw })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Covenant {
    pub kind: CovenantKind,
    pub items: Vec<Vec<u8>>,
}

impl Covenant {
    pub fn item(&self, index: usize) -> Option<&[u8]> {
        self.items.get(index).map(Vec::as_slice)
    }

    pub fn item_u8(&self, index: usize) -> Option<u8> {
        let item = self.item(index)?;
        (item.len() == 1).then_some(item[0])
    }

    pub fn item_u32(&self, index: usize) -> Option<u32> {
        let item: [u8; 4] = self.item(index)?.try_into().ok()?;
        Some(u32::from_le_bytes(item))
    }

    pub fn item_hash(&self, index: usize) -> Option<[u8; 32]> {
        self.item(index)?.try_into().ok()
    }

    pub fn decode(raw: &[u8]) -> Result<Self, PrimitiveError> {
        let mut reader = Reader::new(raw, MAX_TX_SIZE)?;
        let covenant = Self::read_from(&mut reader)?;
        reader.ensure_finished()?;
        Ok(covenant)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut writer = Writer::new();
        self.write_to(&mut writer);
        writer.finish()
    }

    pub fn read_from(reader: &mut Reader<'_>) -> Result<Self, PrimitiveError> {
        let kind = CovenantKind::from_u8(reader.read_u8()?);
        let item_count = reader.read_varint_usize("covenant items")?;

        if item_count > MAX_SCRIPT_STACK {
            return Err(PrimitiveError::LimitExceeded {
                context: "covenant items",
                limit: MAX_SCRIPT_STACK,
                actual: item_count,
            });
        }

        let mut items = Vec::with_capacity(item_count);

        for _ in 0..item_count {
            items.push(reader.read_varbytes(MAX_TX_SIZE, "covenant item")?);
        }

        Ok(Self { kind, items })
    }

    pub fn write_to(&self, writer: &mut Writer) {
        writer.write_u8(self.kind.as_u8());
        writer.write_varint(self.items.len() as u64);

        for item in &self.items {
            writer.write_varbytes(item);
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Resource {
    pub raw: Vec<u8>,
    pub records: Vec<ResourceRecord>,
}

impl Resource {
    pub fn decode(raw: &[u8]) -> Result<Self, PrimitiveError> {
        let mut reader = Reader::new(raw, MAX_RESOURCE_SIZE)?;
        let version = reader.read_u8()?;

        if version != 0 {
            return Err(PrimitiveError::InvalidResource("unknown resource version"));
        }

        let mut records = Vec::new();

        while reader.remaining() > 0 {
            let kind = ResourceRecordKind::from_u8(reader.read_u8()?);
            let payload_start = reader.position();

            match kind {
                ResourceRecordKind::Ds => {
                    reader.read_u16_be()?;
                    reader.read_u8()?;
                    reader.read_u8()?;
                    let digest_len = usize::from(reader.read_u8()?);
                    reader.read_vec(digest_len)?;
                }
                ResourceRecordKind::Ns => {
                    read_dns_name_payload(&mut reader)?;
                }
                ResourceRecordKind::Glue4 => {
                    read_dns_name_payload(&mut reader)?;
                    reader.read_vec(4)?;
                }
                ResourceRecordKind::Glue6 => {
                    read_dns_name_payload(&mut reader)?;
                    reader.read_vec(16)?;
                }
                ResourceRecordKind::Synth4 => {
                    reader.read_vec(4)?;
                }
                ResourceRecordKind::Synth6 => {
                    reader.read_vec(16)?;
                }
                ResourceRecordKind::Txt => {
                    let count = usize::from(reader.read_u8()?);

                    for _ in 0..count {
                        let len = usize::from(reader.read_u8()?);
                        reader.read_vec(len)?;
                    }
                }
                ResourceRecordKind::Unknown(_) => {
                    reader.read_vec(reader.remaining())?;
                }
            }

            let payload_end = reader.position();
            records.push(ResourceRecord {
                kind,
                payload: raw[payload_start..payload_end].to_vec(),
            });
        }

        Ok(Self {
            raw: raw.to_vec(),
            records,
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        self.raw.clone()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ResourceRecord {
    pub kind: ResourceRecordKind,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum ResourceRecordKind {
    Ds,
    Ns,
    Glue4,
    Glue6,
    Synth4,
    Synth6,
    Txt,
    Unknown(u8),
}

impl ResourceRecordKind {
    pub const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Ds,
            1 => Self::Ns,
            2 => Self::Glue4,
            3 => Self::Glue6,
            4 => Self::Synth4,
            5 => Self::Synth6,
            6 => Self::Txt,
            other => Self::Unknown(other),
        }
    }

    pub const fn as_u8(self) -> u8 {
        match self {
            Self::Ds => 0,
            Self::Ns => 1,
            Self::Glue4 => 2,
            Self::Glue6 => 3,
            Self::Synth4 => 4,
            Self::Synth6 => 5,
            Self::Txt => 6,
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum CovenantKind {
    None,
    Claim,
    Open,
    Bid,
    Reveal,
    Redeem,
    Register,
    Update,
    Renew,
    Transfer,
    Finalize,
    Revoke,
    Unknown(u8),
}

impl CovenantKind {
    pub const fn is_name(self) -> bool {
        matches!(
            self,
            Self::Claim
                | Self::Open
                | Self::Bid
                | Self::Reveal
                | Self::Redeem
                | Self::Register
                | Self::Update
                | Self::Renew
                | Self::Transfer
                | Self::Finalize
                | Self::Revoke
        )
    }

    pub const fn is_linked(self) -> bool {
        matches!(
            self,
            Self::Reveal
                | Self::Redeem
                | Self::Register
                | Self::Update
                | Self::Renew
                | Self::Transfer
                | Self::Finalize
                | Self::Revoke
        )
    }

    pub const fn is_unspendable(self) -> bool {
        matches!(self, Self::Revoke)
    }

    pub const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::None,
            1 => Self::Claim,
            2 => Self::Open,
            3 => Self::Bid,
            4 => Self::Reveal,
            5 => Self::Redeem,
            6 => Self::Register,
            7 => Self::Update,
            8 => Self::Renew,
            9 => Self::Transfer,
            10 => Self::Finalize,
            11 => Self::Revoke,
            other => Self::Unknown(other),
        }
    }

    pub const fn as_u8(self) -> u8 {
        match self {
            Self::None => 0,
            Self::Claim => 1,
            Self::Open => 2,
            Self::Bid => 3,
            Self::Reveal => 4,
            Self::Redeem => 5,
            Self::Register => 6,
            Self::Update => 7,
            Self::Renew => 8,
            Self::Transfer => 9,
            Self::Finalize => 10,
            Self::Revoke => 11,
            Self::Unknown(value) => value,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NameState {
    pub name_hash: NameHash,
    pub name: Option<String>,
    pub height: Height,
    pub state: NameLifecycleState,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
pub enum NameLifecycleState {
    Available,
    Opening,
    Bidding,
    Reveal,
    Redeem,
    Registered,
    Updating,
    Renewing,
    Transferring,
    Finalizing,
    Revoked,
    Expired,
    Reserved,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompactTarget {
    bytes: [u8; 32],
    negative: bool,
    overflow: bool,
}

impl CompactTarget {
    pub fn from_bits(bits: u32) -> Self {
        if bits == 0 {
            return Self {
                bytes: [0; 32],
                negative: false,
                overflow: false,
            };
        }

        let exponent = (bits >> 24) as usize;
        let negative = ((bits >> 23) & 1) != 0;
        let mantissa = bits & 0x007f_ffff;
        let mut bytes = [0u8; 32];
        let mut overflow = false;

        if exponent <= 3 {
            let value = mantissa >> (8 * (3 - exponent));
            let value_bytes = value.to_be_bytes();
            bytes[29..32].copy_from_slice(&value_bytes[1..4]);
        } else {
            let mantissa_bytes = [
                ((mantissa >> 16) & 0xff) as u8,
                ((mantissa >> 8) & 0xff) as u8,
                (mantissa & 0xff) as u8,
            ];
            for (offset, byte) in mantissa_bytes.into_iter().enumerate() {
                let position = 32isize - exponent as isize + offset as isize;
                if !(0..32).contains(&position) {
                    overflow |= byte != 0;
                } else {
                    bytes[position as usize] = byte;
                }
            }
        }

        Self {
            bytes,
            negative,
            overflow,
        }
    }

    pub fn bytes(&self) -> &[u8; 32] {
        &self.bytes
    }

    pub fn is_zero(&self) -> bool {
        self.bytes.iter().all(|byte| *byte == 0)
    }

    pub fn is_valid(&self) -> bool {
        !self.negative && !self.overflow && !self.is_zero()
    }

    pub fn is_met_by(&self, hash: &[u8; 32]) -> bool {
        self.is_valid() && hash <= &self.bytes
    }

    pub fn proof(&self) -> Option<Uint256> {
        self.is_valid()
            .then(|| Uint256::from_be_bytes(self.bytes))
            .and_then(Uint256::work_for_target)
    }

    pub fn from_target(target: Uint256) -> u32 {
        let bytes = target.as_be_bytes();
        let Some(first) = bytes.iter().position(|byte| *byte != 0) else {
            return 0;
        };
        let mut exponent = 32 - first;
        let mut mantissa = if exponent <= 3 {
            let mut value = 0u32;
            for byte in &bytes[first..] {
                value = (value << 8) | u32::from(*byte);
            }
            value << (8 * (3 - exponent))
        } else {
            (u32::from(bytes[first]) << 16)
                | (u32::from(bytes[first + 1]) << 8)
                | u32::from(bytes[first + 2])
        };

        if mantissa & 0x0080_0000 != 0 {
            mantissa >>= 8;
            exponent += 1;
        }

        ((exponent as u32) << 24) | mantissa
    }
}

pub fn verify_name(name: &str) -> bool {
    if name.is_empty() || name.len() > MAX_NAME_SIZE {
        return false;
    }

    if matches!(name, "example" | "invalid" | "local" | "localhost" | "test") {
        return false;
    }

    let bytes = name.as_bytes();

    for (index, byte) in bytes.iter().copied().enumerate() {
        let valid = match byte {
            b'0'..=b'9' | b'a'..=b'z' => true,
            b'-' | b'_' => index != 0 && index + 1 != bytes.len(),
            _ => false,
        };

        if !valid {
            return false;
        }
    }

    true
}

pub fn hash_name(name: &str) -> Result<NameHash, PrimitiveError> {
    if !verify_name(name) {
        return Err(PrimitiveError::InvalidName);
    }

    Ok(NameHash::new(sha3_256(name.as_bytes())))
}

pub fn blake2b_160(bytes: &[u8]) -> [u8; 20] {
    let mut hasher = Blake2bVar::new(20).expect("valid blake2b output size");
    hasher.update(bytes);
    let mut output = [0; 20];
    hasher
        .finalize_variable(&mut output)
        .expect("valid blake2b output buffer");
    output
}

pub fn blake2b_256(bytes: &[u8]) -> [u8; 32] {
    blake2b_256_many([bytes])
}

pub fn blake2b_256_many<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> [u8; 32] {
    let mut hasher = Blake2bVar::new(32).expect("valid blake2b output size");

    for part in parts {
        hasher.update(part);
    }

    let mut output = [0; 32];
    hasher
        .finalize_variable(&mut output)
        .expect("valid blake2b output buffer");
    output
}

pub fn blake2b_512(bytes: &[u8]) -> [u8; 64] {
    let mut hasher = Blake2b512::new();
    Digest::update(&mut hasher, bytes);
    hasher.finalize().into()
}

pub fn sha3_256(bytes: &[u8]) -> [u8; 32] {
    sha3_256_many([bytes])
}

pub fn sha3_256_many<'a>(parts: impl IntoIterator<Item = &'a [u8]>) -> [u8; 32] {
    let mut hasher = Sha3_256::new();

    for part in parts {
        Digest::update(&mut hasher, part);
    }

    hasher.finalize().into()
}

pub fn keccak_256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    Digest::update(&mut hasher, bytes);
    hasher.finalize().into()
}

pub fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn fixed_128(bytes: Vec<u8>) -> [u8; 128] {
    debug_assert_eq!(bytes.len(), 128);
    let mut output = [0; 128];
    output.copy_from_slice(&bytes);
    output
}

#[derive(Clone, Debug)]
pub struct Reader<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8], max_len: usize) -> Result<Self, PrimitiveError> {
        if bytes.len() > max_len {
            return Err(PrimitiveError::LimitExceeded {
                context: "reader length",
                limit: max_len,
                actual: bytes.len(),
            });
        }

        Ok(Self { bytes, offset: 0 })
    }

    pub fn position(&self) -> usize {
        self.offset
    }

    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.offset)
    }

    pub fn ensure_finished(&self) -> Result<(), PrimitiveError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(PrimitiveError::TrailingBytes {
                remaining: self.remaining(),
            })
        }
    }

    pub fn read_u8(&mut self) -> Result<u8, PrimitiveError> {
        let bytes = self.read_exact(1)?;
        Ok(bytes[0])
    }

    pub fn read_u16(&mut self) -> Result<u16, PrimitiveError> {
        let bytes = self.read_array::<2>()?;
        Ok(u16::from_le_bytes(bytes))
    }

    pub fn read_u16_be(&mut self) -> Result<u16, PrimitiveError> {
        let bytes = self.read_array::<2>()?;
        Ok(u16::from_be_bytes(bytes))
    }

    pub fn read_u32(&mut self) -> Result<u32, PrimitiveError> {
        let bytes = self.read_array::<4>()?;
        Ok(u32::from_le_bytes(bytes))
    }

    pub fn read_u64(&mut self) -> Result<u64, PrimitiveError> {
        let bytes = self.read_array::<8>()?;
        Ok(u64::from_le_bytes(bytes))
    }

    pub fn read_hash(&mut self) -> Result<[u8; 32], PrimitiveError> {
        self.read_array::<32>()
    }

    pub fn read_nonce(&mut self) -> Result<[u8; NONCE_SIZE], PrimitiveError> {
        self.read_array::<NONCE_SIZE>()
    }

    pub fn read_vec(&mut self, len: usize) -> Result<Vec<u8>, PrimitiveError> {
        self.read_exact(len).map(ToOwned::to_owned)
    }

    pub fn read_varint(&mut self) -> Result<u64, PrimitiveError> {
        let prefix = self.read_u8()?;

        match prefix {
            0x00..=0xfc => Ok(u64::from(prefix)),
            0xfd => {
                let value = u64::from(self.read_u16()?);
                if value < 0xfd {
                    return Err(PrimitiveError::NonCanonicalVarint);
                }
                Ok(value)
            }
            0xfe => {
                let value = u64::from(self.read_u32()?);
                if value <= 0xffff {
                    return Err(PrimitiveError::NonCanonicalVarint);
                }
                Ok(value)
            }
            0xff => {
                let value = self.read_u64()?;
                if value <= 0xffff_ffff {
                    return Err(PrimitiveError::NonCanonicalVarint);
                }
                Ok(value)
            }
        }
    }

    pub fn read_varint_usize(&mut self, context: &'static str) -> Result<usize, PrimitiveError> {
        let value = self.read_varint()?;
        usize::try_from(value).map_err(|_| PrimitiveError::LimitExceeded {
            context,
            limit: usize::MAX,
            actual: usize::MAX,
        })
    }

    pub fn read_varbytes(
        &mut self,
        max_len: usize,
        context: &'static str,
    ) -> Result<Vec<u8>, PrimitiveError> {
        let len = self.read_varint_usize(context)?;

        if len > max_len {
            return Err(PrimitiveError::LimitExceeded {
                context,
                limit: max_len,
                actual: len,
            });
        }

        self.read_vec(len)
    }

    fn read_array<const N: usize>(&mut self) -> Result<[u8; N], PrimitiveError> {
        let bytes = self.read_exact(N)?;
        let mut array = [0; N];
        array.copy_from_slice(bytes);
        Ok(array)
    }

    fn read_exact(&mut self, len: usize) -> Result<&'a [u8], PrimitiveError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(PrimitiveError::IntegerOverflow)?;

        let bytes = self
            .bytes
            .get(self.offset..end)
            .ok_or(PrimitiveError::UnexpectedEof {
                needed: len,
                remaining: self.remaining(),
            })?;

        self.offset = end;
        Ok(bytes)
    }
}

fn read_dns_name_payload(reader: &mut Reader<'_>) -> Result<(), PrimitiveError> {
    let mut labels = 0usize;

    loop {
        labels += 1;

        if labels > 128 {
            return Err(PrimitiveError::InvalidResource(
                "dns name has too many labels",
            ));
        }

        let len = reader.read_u8()?;

        if len & 0xc0 == 0xc0 {
            reader.read_u8()?;
            return Ok(());
        }

        if len & 0xc0 != 0 {
            return Err(PrimitiveError::InvalidResource("invalid dns label prefix"));
        }

        if len == 0 {
            return Ok(());
        }

        if len > 63 {
            return Err(PrimitiveError::InvalidResource(
                "dns label exceeds 63 bytes",
            ));
        }

        reader.read_vec(usize::from(len))?;
    }
}

#[derive(Clone, Debug, Default)]
pub struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(capacity),
        }
    }

    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }

    pub fn write_u8(&mut self, value: u8) {
        self.bytes.push(value);
    }

    pub fn write_u32(&mut self, value: u32) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_u64(&mut self, value: u64) {
        self.bytes.extend_from_slice(&value.to_le_bytes());
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) {
        self.bytes.extend_from_slice(bytes);
    }

    pub fn write_varint(&mut self, value: u64) {
        match value {
            0x00..=0xfc => self.write_u8(value as u8),
            0xfd..=0xffff => {
                self.write_u8(0xfd);
                self.bytes.extend_from_slice(&(value as u16).to_le_bytes());
            }
            0x1_0000..=0xffff_ffff => {
                self.write_u8(0xfe);
                self.write_u32(value as u32);
            }
            _ => {
                self.write_u8(0xff);
                self.write_u64(value);
            }
        }
    }

    pub fn write_varbytes(&mut self, bytes: &[u8]) {
        self.write_varint(bytes.len() as u64);
        self.write_bytes(bytes);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum PrimitiveError {
    #[error("{context} exceeds limit {limit}: {actual}")]
    LimitExceeded {
        context: &'static str,
        limit: usize,
        actual: usize,
    },
    #[error("{context} has invalid length: expected {expected}, got {actual}")]
    InvalidLength {
        context: &'static str,
        expected: usize,
        actual: usize,
    },
    #[error("unexpected end of input: needed {needed}, remaining {remaining}")]
    UnexpectedEof { needed: usize, remaining: usize },
    #[error("input has {remaining} trailing bytes")]
    TrailingBytes { remaining: usize },
    #[error("varint is not minimally encoded")]
    NonCanonicalVarint,
    #[error("integer overflow while parsing")]
    IntegerOverflow,
    #[error("invalid address: {0}")]
    InvalidAddress(&'static str),
    #[error("invalid resource value: {0}")]
    InvalidResource(&'static str),
    #[error("invalid handshake name")]
    InvalidName,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn uint256_round_trips_and_formats_without_losing_width() {
        let mut bytes = [0; 32];
        bytes[0] = 0x01;
        bytes[30] = 0xab;
        bytes[31] = 0xcd;
        let value = Uint256::from_be_bytes(bytes);

        assert_eq!(value.to_be_bytes(), bytes);
        assert_eq!(value.to_fixed_hex(), hex_encode(&bytes));
        assert_eq!(format!("{value:x}"), format!("1{}abcd", "00".repeat(29)));
        assert_eq!(format!("{:x}", Uint256::ZERO), "0");
    }

    #[test]
    fn uint256_checked_add_propagates_carry_and_detects_overflow() {
        let mut low_half_max = [0; 32];
        low_half_max[16..].fill(0xff);
        let sum = Uint256::from_be_bytes(low_half_max)
            .checked_add(Uint256::ONE)
            .expect("addition fits");
        let mut expected = [0; 32];
        expected[15] = 1;
        assert_eq!(sum.to_be_bytes(), expected);

        assert!(Uint256::from_be_bytes([0xff; 32])
            .checked_add(Uint256::ONE)
            .is_none());
    }

    #[test]
    fn uint256_target_work_matches_hsd_formula_boundaries() {
        let work = Uint256::work_for_target(Uint256::ONE).expect("nonzero target");
        let mut two_to_255 = [0; 32];
        two_to_255[0] = 0x80;
        assert_eq!(work, Uint256::from_be_bytes(two_to_255));

        assert_eq!(
            Uint256::work_for_target(Uint256::from(2u64)).expect("target two"),
            Uint256::from_be_bytes([0x55; 32])
        );
        assert_eq!(
            Uint256::work_for_target(Uint256::from_be_bytes([0xff; 32])),
            Some(Uint256::ONE)
        );
        assert_eq!(Uint256::work_for_target(Uint256::ZERO), None);
    }

    #[test]
    fn uint256_retarget_arithmetic_is_checked_and_exact() {
        assert_eq!(
            Uint256::from(1_000u64).checked_sub(Uint256::from(400u64)),
            Some(Uint256::from(600u64))
        );
        assert_eq!(
            Uint256::from(400u64).checked_sub(Uint256::from(1_000u64)),
            None
        );
        assert_eq!(
            Uint256::from(u64::MAX).checked_mul_u64(2),
            Some(Uint256::from(u128::from(u64::MAX) * 2))
        );
        assert_eq!(
            Uint256::from(1_000u64).div_u64(7),
            Some(Uint256::from(142u64))
        );
        assert_eq!(Uint256::ONE.div_u64(0), None);
        assert!(Uint256::from_be_bytes([0xff; 32])
            .checked_mul_u64(2)
            .is_none());
    }

    #[test]
    fn uint256_target_for_work_inverts_hsd_chainwork_formula() {
        assert_eq!(
            Uint256::target_for_work(Uint256::ONE),
            Some(Uint256::from_be_bytes([0xff; 32]))
        );
        let target = Uint256::from_be_bytes({
            let mut bytes = [0; 32];
            bytes[0] = 0x7f;
            bytes[1..].fill(0xff);
            bytes
        });
        assert_eq!(Uint256::target_for_work(Uint256::from(2u64)), Some(target));
        assert_eq!(Uint256::target_for_work(Uint256::ZERO), None);
    }

    #[test]
    fn compact_target_exposes_exact_hsd_chain_proof() {
        assert_eq!(
            CompactTarget::from_bits(0x207f_ffff).proof(),
            Some(Uint256::from(2u64))
        );
        assert_eq!(CompactTarget::from_bits(0).proof(), None);
    }

    #[test]
    fn target_to_compact_matches_hsd_canonical_encoding() {
        for bits in [
            0x0112_0000,
            0x0201_2300,
            0x0312_3456,
            0x0412_3456,
            0x1d00_ffff,
            0x207f_ffff,
        ] {
            let target = CompactTarget::from_bits(bits);
            assert!(target.is_valid());
            assert_eq!(
                CompactTarget::from_target(Uint256::from_be_bytes(*target.bytes())),
                bits
            );
        }
        assert_eq!(CompactTarget::from_target(Uint256::ZERO), 0);
    }

    #[test]
    fn header_round_trips_in_hsd_order() {
        let raw: Vec<u8> = (0..HEADER_SIZE).map(|index| index as u8).collect();
        let header = Header::decode(&raw).expect("header parses");

        assert_eq!(header.nonce, 0x0302_0100);
        assert_eq!(header.time, 0x0b0a_0908_0706_0504);
        assert_eq!(header.encode(), raw);
    }

    #[test]
    fn transaction_round_trips_with_witness() {
        let transaction = Transaction {
            version: 1,
            inputs: vec![Input {
                previous_output: Outpoint {
                    txid: Txid::new([7; 32]),
                    index: 2,
                },
                sequence: 0xffff_fffe,
                witness: Witness {
                    items: vec![vec![1, 2, 3], vec![4, 5]],
                },
            }],
            outputs: vec![Output {
                value: 42,
                address: Address::new(0, vec![9; 20]).expect("valid address"),
                covenant: Covenant {
                    kind: CovenantKind::Open,
                    items: vec![b"example".to_vec()],
                },
            }],
            locktime: 99,
        };

        let raw = transaction.encode();
        let decoded = Transaction::decode(&raw).expect("transaction parses");

        assert_eq!(decoded, transaction);
        assert_eq!(decoded.encode(), raw);
    }

    #[test]
    fn block_round_trips() {
        let block = Block {
            header: Header::default(),
            transactions: vec![Transaction {
                version: 1,
                inputs: Vec::new(),
                outputs: Vec::new(),
                locktime: 0,
            }],
        };

        let raw = block.encode();
        let decoded = Block::decode(&raw).expect("block parses");

        assert_eq!(decoded, block);
        assert_eq!(decoded.encode(), raw);
    }

    #[test]
    fn address_rejects_bad_version_zero_hash_size() {
        let error = Address::new(0, vec![1; 21]).expect_err("invalid version 0 size");
        assert!(matches!(error, PrimitiveError::InvalidAddress(_)));
    }

    #[test]
    fn reader_rejects_non_canonical_varint() {
        let mut reader = Reader::new(&[0xfd, 0xfc, 0x00], 3).expect("reader");
        let error = reader.read_varint().expect_err("non-canonical varint");

        assert!(matches!(error, PrimitiveError::NonCanonicalVarint));
    }

    #[test]
    fn compact_target_handles_hsd_256_bit_boundary() {
        let exponent_33_small = CompactTarget::from_bits(0x2100_0001);
        assert!(exponent_33_small.is_valid());
        let mut expected = [0; 32];
        expected[1] = 1;
        assert_eq!(exponent_33_small.bytes(), &expected);

        let exponent_34_small = CompactTarget::from_bits(0x2200_0001);
        assert!(exponent_34_small.is_valid());
        let mut expected = [0; 32];
        expected[0] = 1;
        assert_eq!(exponent_34_small.bytes(), &expected);

        assert!(!CompactTarget::from_bits(0x2300_0001).is_valid());
        assert!(!CompactTarget::from_bits(0x1d80_ffff).is_valid());
    }

    #[test]
    fn resource_value_scans_known_records() {
        let raw = [
            0, 5, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 1, 3, b't', b'x', b't',
        ];
        let resource = Resource::decode(&raw).expect("resource parses");

        assert_eq!(resource.records.len(), 2);
        assert_eq!(resource.records[0].kind, ResourceRecordKind::Synth6);
        assert_eq!(resource.records[1].kind, ResourceRecordKind::Txt);
        assert_eq!(resource.encode(), raw);
    }
}
