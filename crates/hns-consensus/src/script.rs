use hns_primitives::{
    blake2b_160, blake2b_256, hash160, hash256, keccak_256, ripemd160, sha1, sha256, sha3_256,
    Address, Coin, Transaction, Witness, MAX_SCRIPT_STACK,
};
use hns_secp256k1::{Secp256k1Verifier, SecpError};

use crate::{
    is_valid_signature_hash_type, signature_hash, verify_locktime_predicate,
    verify_sequence_predicate, ConsensusError, TransactionInputVerifier, MAX_MULTISIG_PUBKEYS,
    MAX_SCRIPT_OPS, MAX_SCRIPT_PUSH, MAX_SCRIPT_SIZE,
};

const OP_0: u8 = 0x00;
const OP_PUSHDATA1: u8 = 0x4c;
const OP_PUSHDATA2: u8 = 0x4d;
const OP_PUSHDATA4: u8 = 0x4e;
const OP_1NEGATE: u8 = 0x4f;
const OP_RESERVED: u8 = 0x50;
const OP_1: u8 = 0x51;
const OP_16: u8 = 0x60;
const OP_NOP: u8 = 0x61;
const OP_VER: u8 = 0x62;
const OP_IF: u8 = 0x63;
const OP_NOTIF: u8 = 0x64;
const OP_VERIF: u8 = 0x65;
const OP_VERNOTIF: u8 = 0x66;
const OP_ELSE: u8 = 0x67;
const OP_ENDIF: u8 = 0x68;
const OP_VERIFY: u8 = 0x69;
const OP_RETURN: u8 = 0x6a;
const OP_TOALTSTACK: u8 = 0x6b;
const OP_FROMALTSTACK: u8 = 0x6c;
const OP_2DROP: u8 = 0x6d;
const OP_2DUP: u8 = 0x6e;
const OP_3DUP: u8 = 0x6f;
const OP_2OVER: u8 = 0x70;
const OP_2ROT: u8 = 0x71;
const OP_2SWAP: u8 = 0x72;
const OP_IFDUP: u8 = 0x73;
const OP_DEPTH: u8 = 0x74;
const OP_DROP: u8 = 0x75;
const OP_DUP: u8 = 0x76;
const OP_NIP: u8 = 0x77;
const OP_OVER: u8 = 0x78;
const OP_PICK: u8 = 0x79;
const OP_ROLL: u8 = 0x7a;
const OP_ROT: u8 = 0x7b;
const OP_SWAP: u8 = 0x7c;
const OP_TUCK: u8 = 0x7d;
const OP_CAT: u8 = 0x7e;
const OP_SUBSTR: u8 = 0x7f;
const OP_LEFT: u8 = 0x80;
const OP_RIGHT: u8 = 0x81;
const OP_SIZE: u8 = 0x82;
const OP_INVERT: u8 = 0x83;
const OP_AND: u8 = 0x84;
const OP_OR: u8 = 0x85;
const OP_XOR: u8 = 0x86;
const OP_EQUAL: u8 = 0x87;
const OP_EQUALVERIFY: u8 = 0x88;
const OP_RESERVED1: u8 = 0x89;
const OP_RESERVED2: u8 = 0x8a;
const OP_1ADD: u8 = 0x8b;
const OP_1SUB: u8 = 0x8c;
const OP_2MUL: u8 = 0x8d;
const OP_2DIV: u8 = 0x8e;
const OP_NEGATE: u8 = 0x8f;
const OP_ABS: u8 = 0x90;
const OP_NOT: u8 = 0x91;
const OP_0NOTEQUAL: u8 = 0x92;
const OP_ADD: u8 = 0x93;
const OP_SUB: u8 = 0x94;
const OP_MUL: u8 = 0x95;
const OP_DIV: u8 = 0x96;
const OP_MOD: u8 = 0x97;
const OP_LSHIFT: u8 = 0x98;
const OP_RSHIFT: u8 = 0x99;
const OP_BOOLAND: u8 = 0x9a;
const OP_BOOLOR: u8 = 0x9b;
const OP_NUMEQUAL: u8 = 0x9c;
const OP_NUMEQUALVERIFY: u8 = 0x9d;
const OP_NUMNOTEQUAL: u8 = 0x9e;
const OP_LESSTHAN: u8 = 0x9f;
const OP_GREATERTHAN: u8 = 0xa0;
const OP_LESSTHANOREQUAL: u8 = 0xa1;
const OP_GREATERTHANOREQUAL: u8 = 0xa2;
const OP_MIN: u8 = 0xa3;
const OP_MAX: u8 = 0xa4;
const OP_WITHIN: u8 = 0xa5;
const OP_RIPEMD160: u8 = 0xa6;
const OP_SHA1: u8 = 0xa7;
const OP_SHA256: u8 = 0xa8;
const OP_HASH160: u8 = 0xa9;
const OP_HASH256: u8 = 0xaa;
const OP_CODESEPARATOR: u8 = 0xab;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKSIGVERIFY: u8 = 0xad;
const OP_CHECKMULTISIG: u8 = 0xae;
const OP_CHECKMULTISIGVERIFY: u8 = 0xaf;
const OP_NOP1: u8 = 0xb0;
const OP_CHECKLOCKTIMEVERIFY: u8 = 0xb1;
const OP_CHECKSEQUENCEVERIFY: u8 = 0xb2;
const OP_NOP4: u8 = 0xb3;
const OP_NOP10: u8 = 0xb9;
const OP_BLAKE160: u8 = 0xc0;
const OP_BLAKE256: u8 = 0xc1;
const OP_SHA3: u8 = 0xc2;
const OP_KECCAK: u8 = 0xc3;
const OP_TYPE: u8 = 0xd0;
const OP_INVALIDOPCODE: u8 = 0xff;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ScriptFlags(u32);

impl ScriptFlags {
    pub const NONE: Self = Self(0);
    pub const VERIFY_MINIMAL_DATA: Self = Self(1 << 1);
    pub const VERIFY_DISCOURAGE_UPGRADABLE_NOPS: Self = Self(1 << 2);
    pub const VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: Self = Self(1 << 3);
    pub const VERIFY_MINIMAL_IF: Self = Self(1 << 4);
    pub const VERIFY_NULLFAIL: Self = Self(1 << 5);
    pub const MANDATORY: Self =
        Self(Self::VERIFY_MINIMAL_DATA.0 | Self::VERIFY_MINIMAL_IF.0 | Self::VERIFY_NULLFAIL.0);
    pub const STANDARD: Self = Self(
        Self::MANDATORY.0
            | Self::VERIFY_DISCOURAGE_UPGRADABLE_NOPS.0
            | Self::VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM.0,
    );

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }

    pub const fn bits(self) -> u32 {
        self.0
    }

    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }
}

/// Count HSD witness sigops without executing the script. Malformed trailing
/// pushes terminate the scan after the valid prefix, matching
/// `Script#getSigops`: the block-level limit is a cheap contextual bound and
/// script execution remains responsible for rejecting the malformed program.
pub fn count_script_sigops(script: &[u8]) -> u32 {
    let mut total = 0u32;
    let mut offset = 0usize;
    let mut last_opcode = None;

    while offset < script.len() {
        let opcode = script[offset];
        offset += 1;
        let data_length = match opcode {
            0x01..=0x4b => Some(usize::from(opcode)),
            OP_PUSHDATA1 => {
                let Some(length) = script.get(offset).copied() else {
                    break;
                };
                offset += 1;
                Some(usize::from(length))
            }
            OP_PUSHDATA2 => {
                let Some(bytes) = script.get(offset..offset.saturating_add(2)) else {
                    break;
                };
                let Ok(bytes) = <[u8; 2]>::try_from(bytes) else {
                    break;
                };
                offset += 2;
                Some(usize::from(u16::from_le_bytes(bytes)))
            }
            OP_PUSHDATA4 => {
                let Some(bytes) = script.get(offset..offset.saturating_add(4)) else {
                    break;
                };
                let Ok(bytes) = <[u8; 4]>::try_from(bytes) else {
                    break;
                };
                offset += 4;
                let Ok(length) = usize::try_from(u32::from_le_bytes(bytes)) else {
                    break;
                };
                Some(length)
            }
            _ => None,
        };
        if let Some(data_length) = data_length {
            let Some(end) = offset.checked_add(data_length) else {
                break;
            };
            if end > script.len() {
                break;
            }
            offset = end;
        }

        match opcode {
            OP_CHECKSIG | OP_CHECKSIGVERIFY => total = total.saturating_add(1),
            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                let sigops = match last_opcode {
                    Some(opcode @ OP_1..=OP_16) => u32::from(opcode - 0x50),
                    _ => MAX_MULTISIG_PUBKEYS as u32,
                };
                total = total.saturating_add(sigops);
            }
            _ => {}
        }
        last_opcode = Some(opcode);
    }

    total
}

pub fn witness_program_sigops(address: &Address, witness: &Witness) -> u32 {
    if address.version != 0 {
        return 0;
    }
    match address.hash.len() {
        20 => 1,
        32 => witness
            .items
            .last()
            .map_or(0, |script| count_script_sigops(script)),
        _ => 0,
    }
}

pub fn transaction_sigops(
    transaction: &Transaction,
    input_coins: &[Coin],
) -> Result<u32, ConsensusError> {
    if crate::is_coinbase(transaction) {
        return Ok(0);
    }
    if transaction.inputs.len() != input_coins.len() {
        return Err(ConsensusError::InvalidTransaction(
            "resolved input count does not match transaction inputs",
        ));
    }

    transaction
        .inputs
        .iter()
        .zip(input_coins)
        .try_fold(0u32, |total, (input, coin)| {
            if input.previous_output != coin.outpoint {
                return Err(ConsensusError::InvalidTransaction(
                    "resolved input coin does not match transaction outpoint",
                ));
            }
            Ok(total.saturating_add(witness_program_sigops(&coin.address, &input.witness)))
        })
}

pub trait SignatureVerifier: Send + Sync {
    /// Validate the compact signature's scalar encoding, including hsd's low-S
    /// requirement. Empty signatures are handled by the script engine and are
    /// never passed to this method.
    fn validate_compact_signature(&self, signature: &[u8; 64]) -> Result<(), ScriptError>;

    fn verify(
        &self,
        message: &[u8; 32],
        signature: &[u8; 64],
        public_key: &[u8; 33],
    ) -> Result<bool, ScriptError>;
}

#[derive(Clone, Copy, Debug, Default)]
pub struct UnavailableSignatureVerifier;

impl SignatureVerifier for UnavailableSignatureVerifier {
    fn validate_compact_signature(&self, _signature: &[u8; 64]) -> Result<(), ScriptError> {
        Err(ScriptError::SignatureBackendUnavailable)
    }

    fn verify(
        &self,
        _message: &[u8; 32],
        _signature: &[u8; 64],
        _public_key: &[u8; 33],
    ) -> Result<bool, ScriptError> {
        Err(ScriptError::SignatureBackendUnavailable)
    }
}

/// Production verification backend backed by the exact libsecp256k1 source
/// pinned by the repository's HSD oracle. The wrapper itself is stateless;
/// verification contexts are owned lazily per thread by `hns-secp256k1`.
#[derive(Clone, Copy, Debug, Default)]
pub struct NativeSignatureVerifier {
    verifier: Secp256k1Verifier,
}

impl NativeSignatureVerifier {
    /// Eagerly create the current thread's verification context. Startup code
    /// should call this before advertising script-verification readiness.
    pub fn new() -> Result<Self, ScriptError> {
        let verifier = Secp256k1Verifier::new().map_err(map_secp_error)?;
        Ok(Self { verifier })
    }
}

impl SignatureVerifier for NativeSignatureVerifier {
    fn validate_compact_signature(&self, signature: &[u8; 64]) -> Result<(), ScriptError> {
        self.verifier
            .validate_compact_signature(signature)
            .map_err(map_secp_error)
    }

    fn verify(
        &self,
        message: &[u8; 32],
        signature: &[u8; 64],
        public_key: &[u8; 33],
    ) -> Result<bool, ScriptError> {
        self.verifier
            .verify(message, signature, public_key)
            .map_err(map_secp_error)
    }
}

fn map_secp_error(error: SecpError) -> ScriptError {
    match error {
        SecpError::ContextCreation => ScriptError::SignatureBackendUnavailable,
        SecpError::InvalidCompactSignature | SecpError::HighS => ScriptError::SignatureEncoding,
        SecpError::InvalidPublicKey => ScriptError::PublicKeyEncoding,
    }
}

#[derive(Clone, Debug)]
pub struct WitnessProgramVerifier<V> {
    signatures: V,
    flags: ScriptFlags,
}

impl<V> WitnessProgramVerifier<V> {
    pub const fn new(signatures: V, flags: ScriptFlags) -> Self {
        Self { signatures, flags }
    }

    pub const fn mandatory(signatures: V) -> Self {
        Self::new(signatures, ScriptFlags::MANDATORY)
    }
}

impl<V: SignatureVerifier> TransactionInputVerifier for WitnessProgramVerifier<V> {
    fn verify_input(
        &self,
        transaction: &Transaction,
        input_index: usize,
        coin: &Coin,
    ) -> Result<(), ConsensusError> {
        verify_witness_program(transaction, input_index, coin, self.flags, &self.signatures)
            .map_err(|error| ConsensusError::Authorization(error.to_string()))
    }
}

pub fn verify_witness_program(
    transaction: &Transaction,
    input_index: usize,
    coin: &Coin,
    flags: ScriptFlags,
    signatures: &dyn SignatureVerifier,
) -> Result<(), ScriptError> {
    let input = transaction
        .inputs
        .get(input_index)
        .ok_or(ScriptError::InputIndexOutOfRange)?;
    let address = &coin.address;

    if address.version == 31 {
        return Err(ScriptError::OpReturn);
    }
    if input.witness.items.len() > MAX_SCRIPT_STACK {
        return Err(ScriptError::StackSize);
    }

    let mut stack = input.witness.items.clone();
    let redeem = if address.version == 0 {
        match address.hash.len() {
            32 => {
                let witness_script = stack.pop().ok_or(ScriptError::WitnessProgramWitnessEmpty)?;
                if witness_script.len() > MAX_SCRIPT_SIZE {
                    return Err(ScriptError::ScriptSize);
                }
                if sha3_256(&witness_script).as_slice() != address.hash.as_slice() {
                    return Err(ScriptError::WitnessProgramMismatch);
                }
                witness_script
            }
            20 => {
                if stack.len() != 2 {
                    return Err(ScriptError::WitnessProgramMismatch);
                }
                pubkey_hash_script(&address.hash)
            }
            _ => return Err(ScriptError::WitnessProgramWrongLength),
        }
    } else {
        if flags.contains(ScriptFlags::VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM) {
            return Err(ScriptError::DiscourageUpgradableWitnessProgram);
        }
        return Ok(());
    };

    if stack.iter().any(|item| item.len() > MAX_SCRIPT_PUSH) {
        return Err(ScriptError::PushSize);
    }

    execute_script(
        &redeem,
        &mut stack,
        transaction,
        input_index,
        coin.value,
        flags,
        signatures,
    )?;

    if stack.len() != 1 || !cast_to_bool(&stack[0]) {
        return Err(ScriptError::EvalFalse);
    }
    Ok(())
}

fn pubkey_hash_script(hash: &[u8]) -> Vec<u8> {
    let mut script = Vec::with_capacity(25);
    script.extend_from_slice(&[OP_DUP, OP_BLAKE160, 20]);
    script.extend_from_slice(hash);
    script.extend_from_slice(&[OP_EQUALVERIFY, OP_CHECKSIG]);
    script
}

fn execute_script(
    script: &[u8],
    stack: &mut Vec<Vec<u8>>,
    transaction: &Transaction,
    input_index: usize,
    previous_value: u64,
    flags: ScriptFlags,
    signatures: &dyn SignatureVerifier,
) -> Result<(), ScriptError> {
    if script.len() > MAX_SCRIPT_SIZE {
        return Err(ScriptError::ScriptSize);
    }

    let instructions = parse_script(script)?;
    let mut alt_stack = Vec::<Vec<u8>>::new();
    let mut conditions = Vec::<bool>::new();
    let mut operation_count = 0usize;
    let mut last_separator = 0usize;

    for instruction in instructions {
        if instruction
            .data
            .as_ref()
            .is_some_and(|data| data.len() > MAX_SCRIPT_PUSH)
        {
            return Err(ScriptError::PushSize);
        }
        if instruction.opcode > OP_16 {
            operation_count = operation_count
                .checked_add(1)
                .ok_or(ScriptError::OperationCount)?;
            if operation_count > MAX_SCRIPT_OPS {
                return Err(ScriptError::OperationCount);
            }
        }
        if is_disabled_opcode(instruction.opcode) {
            return Err(ScriptError::DisabledOpcode(instruction.opcode));
        }

        let executing = conditions.iter().all(|condition| *condition);
        let is_branch = (OP_IF..=OP_ENDIF).contains(&instruction.opcode);
        if !executing && !is_branch {
            enforce_stack_limit(stack, &alt_stack)?;
            continue;
        }

        if let Some(data) = instruction.data {
            if flags.contains(ScriptFlags::VERIFY_MINIMAL_DATA)
                && !is_minimal_push(instruction.opcode, &data)
            {
                return Err(ScriptError::MinimalData);
            }
            stack.push(data);
            enforce_stack_limit(stack, &alt_stack)?;
            continue;
        }

        match instruction.opcode {
            OP_0 => stack.push(Vec::new()),
            OP_1NEGATE => stack.push(encode_script_number(-1)),
            OP_1..=OP_16 => {
                stack.push(encode_script_number(i64::from(
                    instruction.opcode - OP_1 + 1,
                )));
            }
            OP_NOP => {}
            OP_TYPE => {
                let covenant_type = transaction
                    .outputs
                    .get(input_index)
                    .map(|output| i64::from(output.covenant.kind.as_u8()))
                    .unwrap_or(0);
                stack.push(encode_script_number(covenant_type));
            }
            OP_CHECKLOCKTIMEVERIFY => {
                let value = decode_top_number(stack, flags, 5)?;
                if value < 0 {
                    return Err(ScriptError::NegativeLocktime);
                }
                let predicate =
                    u32::try_from(value).map_err(|_| ScriptError::UnsatisfiedLocktime)?;
                if !verify_locktime_predicate(transaction, input_index, predicate) {
                    return Err(ScriptError::UnsatisfiedLocktime);
                }
            }
            OP_CHECKSEQUENCEVERIFY => {
                let value = decode_top_number(stack, flags, 5)?;
                if value < 0 {
                    return Err(ScriptError::NegativeLocktime);
                }
                let predicate =
                    u32::try_from(value).map_err(|_| ScriptError::UnsatisfiedLocktime)?;
                if !verify_sequence_predicate(transaction, input_index, predicate) {
                    return Err(ScriptError::UnsatisfiedLocktime);
                }
            }
            opcode if opcode == OP_NOP1 || (OP_NOP4..=OP_NOP10).contains(&opcode) => {
                if flags.contains(ScriptFlags::VERIFY_DISCOURAGE_UPGRADABLE_NOPS) {
                    return Err(ScriptError::DiscourageUpgradableNops);
                }
            }
            OP_IF | OP_NOTIF => {
                let parent_executing = conditions.iter().all(|condition| *condition);
                let mut value = false;
                if parent_executing {
                    let item = pop(stack)?;
                    if flags.contains(ScriptFlags::VERIFY_MINIMAL_IF)
                        && !(item.is_empty() || item.as_slice() == [1u8])
                    {
                        return Err(ScriptError::MinimalIf);
                    }
                    value = cast_to_bool(&item);
                    if instruction.opcode == OP_NOTIF {
                        value = !value;
                    }
                }
                conditions.push(value);
            }
            OP_ELSE => {
                let Some(condition) = conditions.last_mut() else {
                    return Err(ScriptError::UnbalancedConditional);
                };
                *condition = !*condition;
            }
            OP_ENDIF => {
                conditions.pop().ok_or(ScriptError::UnbalancedConditional)?;
            }
            OP_VERIFY => {
                if !cast_to_bool(&pop(stack)?) {
                    return Err(ScriptError::Verify);
                }
            }
            OP_RETURN => return Err(ScriptError::OpReturn),
            OP_TOALTSTACK => alt_stack.push(pop(stack)?),
            OP_FROMALTSTACK => {
                let item = alt_stack
                    .pop()
                    .ok_or(ScriptError::InvalidAltStackOperation)?;
                stack.push(item);
            }
            OP_2DROP => {
                require_stack(stack, 2)?;
                stack.truncate(stack.len() - 2);
            }
            OP_2DUP => duplicate_tail(stack, 2)?,
            OP_3DUP => duplicate_tail(stack, 3)?,
            OP_2OVER => {
                require_stack(stack, 4)?;
                let len = stack.len();
                let values = stack[len - 4..len - 2].to_vec();
                stack.extend(values);
            }
            OP_2ROT => {
                require_stack(stack, 6)?;
                let len = stack.len();
                let first = stack.remove(len - 6);
                let second = stack.remove(len - 6);
                stack.push(first);
                stack.push(second);
            }
            OP_2SWAP => {
                require_stack(stack, 4)?;
                let len = stack.len();
                stack.swap(len - 4, len - 2);
                stack.swap(len - 3, len - 1);
            }
            OP_IFDUP => {
                let value = stack.last().ok_or(ScriptError::InvalidStackOperation)?;
                if cast_to_bool(value) {
                    stack.push(value.clone());
                }
            }
            OP_DEPTH => stack.push(encode_script_number(stack.len() as i64)),
            OP_DROP => {
                pop(stack)?;
            }
            OP_DUP => duplicate_tail(stack, 1)?,
            OP_NIP => {
                require_stack(stack, 2)?;
                let len = stack.len();
                stack.remove(len - 2);
            }
            OP_OVER => {
                require_stack(stack, 2)?;
                let len = stack.len();
                stack.push(stack[len - 2].clone());
            }
            OP_PICK | OP_ROLL => {
                let depth = decode_script_number(&pop(stack)?, minimal_numbers(flags), 4)?;
                let depth =
                    usize::try_from(depth).map_err(|_| ScriptError::InvalidStackOperation)?;
                if depth >= stack.len() {
                    return Err(ScriptError::InvalidStackOperation);
                }
                let index = stack.len() - 1 - depth;
                let item = if instruction.opcode == OP_ROLL {
                    stack.remove(index)
                } else {
                    stack[index].clone()
                };
                stack.push(item);
            }
            OP_ROT => {
                require_stack(stack, 3)?;
                let len = stack.len();
                let item = stack.remove(len - 3);
                stack.push(item);
            }
            OP_SWAP => {
                require_stack(stack, 2)?;
                let len = stack.len();
                stack.swap(len - 2, len - 1);
            }
            OP_TUCK => {
                require_stack(stack, 2)?;
                let len = stack.len();
                let item = stack[len - 1].clone();
                stack.insert(len - 2, item);
            }
            OP_SIZE => {
                let size = stack
                    .last()
                    .ok_or(ScriptError::InvalidStackOperation)?
                    .len();
                stack.push(encode_script_number(size as i64));
            }
            OP_EQUAL | OP_EQUALVERIFY => {
                require_stack(stack, 2)?;
                let right = pop(stack)?;
                let left = pop(stack)?;
                let equal = left == right;
                if instruction.opcode == OP_EQUALVERIFY {
                    if !equal {
                        return Err(ScriptError::EqualVerify);
                    }
                } else {
                    push_bool(stack, equal);
                }
            }
            OP_1ADD | OP_1SUB | OP_NEGATE | OP_ABS | OP_NOT | OP_0NOTEQUAL => {
                let value = decode_script_number(&pop(stack)?, minimal_numbers(flags), 4)?;
                let result = match instruction.opcode {
                    OP_1ADD => value.checked_add(1),
                    OP_1SUB => value.checked_sub(1),
                    OP_NEGATE => value.checked_neg(),
                    OP_ABS => value.checked_abs(),
                    OP_NOT => Some(i64::from(value == 0)),
                    OP_0NOTEQUAL => Some(i64::from(value != 0)),
                    _ => None,
                }
                .ok_or(ScriptError::NumericOverflow)?;
                stack.push(encode_script_number(result));
            }
            OP_ADD
            | OP_SUB
            | OP_BOOLAND
            | OP_BOOLOR
            | OP_NUMEQUAL
            | OP_NUMEQUALVERIFY
            | OP_NUMNOTEQUAL
            | OP_LESSTHAN
            | OP_GREATERTHAN
            | OP_LESSTHANOREQUAL
            | OP_GREATERTHANOREQUAL
            | OP_MIN
            | OP_MAX => {
                require_stack(stack, 2)?;
                let right = decode_script_number(&pop(stack)?, minimal_numbers(flags), 4)?;
                let left = decode_script_number(&pop(stack)?, minimal_numbers(flags), 4)?;
                let result = match instruction.opcode {
                    OP_ADD => left
                        .checked_add(right)
                        .ok_or(ScriptError::NumericOverflow)?,
                    OP_SUB => left
                        .checked_sub(right)
                        .ok_or(ScriptError::NumericOverflow)?,
                    OP_BOOLAND => i64::from(left != 0 && right != 0),
                    OP_BOOLOR => i64::from(left != 0 || right != 0),
                    OP_NUMEQUAL | OP_NUMEQUALVERIFY => i64::from(left == right),
                    OP_NUMNOTEQUAL => i64::from(left != right),
                    OP_LESSTHAN => i64::from(left < right),
                    OP_GREATERTHAN => i64::from(left > right),
                    OP_LESSTHANOREQUAL => i64::from(left <= right),
                    OP_GREATERTHANOREQUAL => i64::from(left >= right),
                    OP_MIN => left.min(right),
                    OP_MAX => left.max(right),
                    _ => unreachable!(),
                };
                if instruction.opcode == OP_NUMEQUALVERIFY {
                    if result == 0 {
                        return Err(ScriptError::NumEqualVerify);
                    }
                } else {
                    stack.push(encode_script_number(result));
                }
            }
            OP_WITHIN => {
                require_stack(stack, 3)?;
                let maximum = decode_script_number(&pop(stack)?, minimal_numbers(flags), 4)?;
                let minimum = decode_script_number(&pop(stack)?, minimal_numbers(flags), 4)?;
                let value = decode_script_number(&pop(stack)?, minimal_numbers(flags), 4)?;
                push_bool(stack, minimum <= value && value < maximum);
            }
            OP_BLAKE160 | OP_BLAKE256 | OP_SHA3 | OP_KECCAK => {
                let item = pop(stack)?;
                let digest = match instruction.opcode {
                    OP_BLAKE160 => blake2b_160(&item).to_vec(),
                    OP_BLAKE256 => blake2b_256(&item).to_vec(),
                    OP_SHA3 => sha3_256(&item).to_vec(),
                    OP_KECCAK => keccak_256(&item).to_vec(),
                    _ => unreachable!(),
                };
                stack.push(digest);
            }
            OP_RIPEMD160 | OP_SHA1 | OP_SHA256 | OP_HASH160 | OP_HASH256 => {
                let item = pop(stack)?;
                let digest = match instruction.opcode {
                    OP_RIPEMD160 => ripemd160(&item).to_vec(),
                    OP_SHA1 => sha1(&item).to_vec(),
                    OP_SHA256 => sha256(&item).to_vec(),
                    OP_HASH160 => hash160(&item).to_vec(),
                    OP_HASH256 => hash256(&item).to_vec(),
                    _ => unreachable!(),
                };
                stack.push(digest);
            }
            OP_CODESEPARATOR => last_separator = instruction.end,
            OP_CHECKSIG | OP_CHECKSIGVERIFY => {
                require_stack(stack, 2)?;
                let public_key = pop(stack)?;
                let signature = pop(stack)?;
                let subscript = &script[last_separator..];
                let valid = check_signature(
                    transaction,
                    input_index,
                    previous_value,
                    subscript,
                    &signature,
                    &public_key,
                    signatures,
                )?;
                if !valid && flags.contains(ScriptFlags::VERIFY_NULLFAIL) && !signature.is_empty() {
                    return Err(ScriptError::NullFail);
                }
                if instruction.opcode == OP_CHECKSIGVERIFY {
                    if !valid {
                        return Err(ScriptError::CheckSigVerify);
                    }
                } else {
                    push_bool(stack, valid);
                }
            }
            OP_CHECKMULTISIG | OP_CHECKMULTISIGVERIFY => {
                let valid = check_multisig(
                    stack,
                    transaction,
                    input_index,
                    previous_value,
                    &script[last_separator..],
                    flags,
                    signatures,
                    &mut operation_count,
                )?;
                if instruction.opcode == OP_CHECKMULTISIGVERIFY {
                    if !valid {
                        return Err(ScriptError::CheckMultiSigVerify);
                    }
                } else {
                    push_bool(stack, valid);
                }
            }
            OP_RESERVED | OP_VER | OP_VERIF | OP_VERNOTIF | OP_RESERVED1 | OP_RESERVED2
            | OP_INVALIDOPCODE => return Err(ScriptError::BadOpcode(instruction.opcode)),
            opcode => return Err(ScriptError::UnsupportedOpcode(opcode)),
        }

        enforce_stack_limit(stack, &alt_stack)?;
    }

    if !conditions.is_empty() {
        return Err(ScriptError::UnbalancedConditional);
    }
    Ok(())
}

fn check_signature(
    transaction: &Transaction,
    input_index: usize,
    previous_value: u64,
    subscript: &[u8],
    signature: &[u8],
    public_key: &[u8],
    signatures: &dyn SignatureVerifier,
) -> Result<bool, ScriptError> {
    let compact = if signature.is_empty() {
        None
    } else {
        if signature.len() != 65 || !is_valid_signature_hash_type(signature[64]) {
            return Err(ScriptError::SignatureEncoding);
        }
        let compact: &[u8; 64] = signature[..64]
            .try_into()
            .map_err(|_| ScriptError::SignatureEncoding)?;
        signatures.validate_compact_signature(compact)?;
        Some(compact)
    };
    let public_key: &[u8; 33] = public_key
        .try_into()
        .map_err(|_| ScriptError::PublicKeyEncoding)?;
    if !matches!(public_key[0], 0x02 | 0x03) {
        return Err(ScriptError::PublicKeyEncoding);
    }
    let Some(compact) = compact else {
        return Ok(false);
    };
    let message = signature_hash(
        transaction,
        input_index,
        subscript,
        previous_value,
        u32::from(signature[64]),
    )
    .map_err(|error| ScriptError::Sighash(error.to_string()))?;
    signatures.verify(&message, compact, public_key)
}

#[allow(clippy::too_many_arguments)]
fn check_multisig(
    stack: &mut Vec<Vec<u8>>,
    transaction: &Transaction,
    input_index: usize,
    previous_value: u64,
    subscript: &[u8],
    flags: ScriptFlags,
    signatures: &dyn SignatureVerifier,
    operation_count: &mut usize,
) -> Result<bool, ScriptError> {
    let key_count = decode_script_number(&pop(stack)?, minimal_numbers(flags), 4)?;
    let key_count = usize::try_from(key_count).map_err(|_| ScriptError::PublicKeyCount)?;
    if key_count > MAX_MULTISIG_PUBKEYS {
        return Err(ScriptError::PublicKeyCount);
    }
    *operation_count = (*operation_count)
        .checked_add(key_count)
        .ok_or(ScriptError::OperationCount)?;
    if *operation_count > MAX_SCRIPT_OPS {
        return Err(ScriptError::OperationCount);
    }
    require_stack(stack, key_count.saturating_add(1))?;
    let keys_start = stack.len() - key_count;
    let keys = stack.split_off(keys_start);
    let signature_count = decode_script_number(&pop(stack)?, minimal_numbers(flags), 4)?;
    let signature_count =
        usize::try_from(signature_count).map_err(|_| ScriptError::SignatureCount)?;
    if signature_count > key_count {
        return Err(ScriptError::SignatureCount);
    }
    require_stack(stack, signature_count.saturating_add(1))?;
    let signatures_start = stack.len() - signature_count;
    let candidate_signatures = stack.split_off(signatures_start);
    let dummy = pop(stack)?;

    // HSD consumes both lists from the top of the stack. Besides preserving
    // ordered multisignature matching, this determines which malformed
    // signature or key is observed before an impossible remainder exits.
    let mut remaining_signatures = candidate_signatures.len();
    let mut remaining_keys = keys.len();
    let mut valid = true;
    while remaining_signatures > 0 {
        if remaining_signatures > remaining_keys {
            valid = false;
            break;
        }
        let signature = &candidate_signatures[remaining_signatures - 1];
        let key = &keys[remaining_keys - 1];
        if check_signature(
            transaction,
            input_index,
            previous_value,
            subscript,
            signature,
            key,
            signatures,
        )? {
            remaining_signatures -= 1;
        }
        remaining_keys -= 1;
    }
    valid &= remaining_signatures == 0;

    if !valid
        && flags.contains(ScriptFlags::VERIFY_NULLFAIL)
        && candidate_signatures
            .iter()
            .any(|signature| !signature.is_empty())
    {
        return Err(ScriptError::NullFail);
    }
    if !dummy.is_empty() {
        return Err(ScriptError::SignatureNullDummy);
    }
    Ok(valid)
}

#[derive(Clone, Debug)]
struct Instruction {
    opcode: u8,
    data: Option<Vec<u8>>,
    end: usize,
}

fn parse_script(script: &[u8]) -> Result<Vec<Instruction>, ScriptError> {
    let mut instructions = Vec::new();
    let mut offset = 0usize;

    while offset < script.len() {
        let opcode = script[offset];
        offset += 1;
        let data_len = match opcode {
            0x01..=0x4b => Some(usize::from(opcode)),
            OP_PUSHDATA1 => Some(usize::from(read_u8(script, &mut offset)?)),
            OP_PUSHDATA2 => Some(usize::from(read_u16(script, &mut offset)?)),
            OP_PUSHDATA4 => Some(
                usize::try_from(read_u32(script, &mut offset)?)
                    .map_err(|_| ScriptError::BadOpcode(opcode))?,
            ),
            _ => None,
        };
        let data = if let Some(data_len) = data_len {
            let end = offset
                .checked_add(data_len)
                .filter(|end| *end <= script.len())
                .ok_or(ScriptError::BadOpcode(opcode))?;
            let data = script[offset..end].to_vec();
            offset = end;
            Some(data)
        } else {
            None
        };
        instructions.push(Instruction {
            opcode,
            data,
            end: offset,
        });
    }

    Ok(instructions)
}

fn read_u8(script: &[u8], offset: &mut usize) -> Result<u8, ScriptError> {
    let value = *script
        .get(*offset)
        .ok_or(ScriptError::BadOpcode(OP_PUSHDATA1))?;
    *offset += 1;
    Ok(value)
}

fn read_u16(script: &[u8], offset: &mut usize) -> Result<u16, ScriptError> {
    let end = offset
        .checked_add(2)
        .filter(|end| *end <= script.len())
        .ok_or(ScriptError::BadOpcode(OP_PUSHDATA2))?;
    let bytes: [u8; 2] = script[*offset..end]
        .try_into()
        .map_err(|_| ScriptError::BadOpcode(OP_PUSHDATA2))?;
    *offset = end;
    Ok(u16::from_le_bytes(bytes))
}

fn read_u32(script: &[u8], offset: &mut usize) -> Result<u32, ScriptError> {
    let end = offset
        .checked_add(4)
        .filter(|end| *end <= script.len())
        .ok_or(ScriptError::BadOpcode(OP_PUSHDATA4))?;
    let bytes: [u8; 4] = script[*offset..end]
        .try_into()
        .map_err(|_| ScriptError::BadOpcode(OP_PUSHDATA4))?;
    *offset = end;
    Ok(u32::from_le_bytes(bytes))
}

fn is_minimal_push(opcode: u8, data: &[u8]) -> bool {
    if data.is_empty() {
        return opcode == OP_0;
    }
    if data.len() == 1 && (1..=16).contains(&data[0]) {
        return opcode == OP_1 + data[0] - 1;
    }
    if data == [0x81] {
        return opcode == OP_1NEGATE;
    }
    match data.len() {
        1..=75 => opcode == data.len() as u8,
        76..=255 => opcode == OP_PUSHDATA1,
        256..=65_535 => opcode == OP_PUSHDATA2,
        _ => opcode == OP_PUSHDATA4,
    }
}

fn is_disabled_opcode(opcode: u8) -> bool {
    matches!(
        opcode,
        OP_CAT
            | OP_SUBSTR
            | OP_LEFT
            | OP_RIGHT
            | OP_INVERT
            | OP_AND
            | OP_OR
            | OP_XOR
            | OP_2MUL
            | OP_2DIV
            | OP_MUL
            | OP_DIV
            | OP_MOD
            | OP_LSHIFT
            | OP_RSHIFT
    )
}

fn minimal_numbers(flags: ScriptFlags) -> bool {
    flags.contains(ScriptFlags::VERIFY_MINIMAL_DATA)
}

fn decode_top_number(
    stack: &[Vec<u8>],
    flags: ScriptFlags,
    maximum_size: usize,
) -> Result<i64, ScriptError> {
    let item = stack.last().ok_or(ScriptError::InvalidStackOperation)?;
    decode_script_number(item, minimal_numbers(flags), maximum_size)
}

fn decode_script_number(
    bytes: &[u8],
    require_minimal: bool,
    maximum_size: usize,
) -> Result<i64, ScriptError> {
    if bytes.len() > maximum_size {
        return Err(ScriptError::NumericOverflow);
    }
    if require_minimal && !is_minimal_script_number(bytes) {
        return Err(ScriptError::NonMinimalNumber);
    }
    if bytes.is_empty() {
        return Ok(0);
    }

    let mut magnitude = 0u64;
    for (index, byte) in bytes.iter().copied().enumerate() {
        magnitude |= u64::from(byte) << (8 * index);
    }
    let sign_bit = 1u64 << (bytes.len() * 8 - 1);
    let negative = magnitude & sign_bit != 0;
    magnitude &= !sign_bit;
    let magnitude = i64::try_from(magnitude).map_err(|_| ScriptError::NumericOverflow)?;
    Ok(if negative { -magnitude } else { magnitude })
}

fn encode_script_number(value: i64) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }

    let negative = value < 0;
    let mut magnitude = value.unsigned_abs();
    let mut bytes = Vec::new();
    while magnitude != 0 {
        bytes.push(magnitude as u8);
        magnitude >>= 8;
    }
    if bytes.last().is_some_and(|byte| byte & 0x80 != 0) {
        bytes.push(if negative { 0x80 } else { 0x00 });
    } else if negative {
        if let Some(last) = bytes.last_mut() {
            *last |= 0x80;
        }
    }
    bytes
}

fn is_minimal_script_number(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }
    if bytes.last().is_some_and(|byte| byte & 0x7f == 0) {
        if bytes.len() == 1 {
            return false;
        }
        if bytes[bytes.len() - 2] & 0x80 == 0 {
            return false;
        }
    }
    true
}

fn cast_to_bool(bytes: &[u8]) -> bool {
    for (index, byte) in bytes.iter().copied().enumerate() {
        if byte == 0 {
            continue;
        }
        if index == bytes.len() - 1 && byte == 0x80 {
            return false;
        }
        return true;
    }
    false
}

fn push_bool(stack: &mut Vec<Vec<u8>>, value: bool) {
    stack.push(if value { vec![1] } else { Vec::new() });
}

fn pop(stack: &mut Vec<Vec<u8>>) -> Result<Vec<u8>, ScriptError> {
    stack.pop().ok_or(ScriptError::InvalidStackOperation)
}

fn require_stack(stack: &[Vec<u8>], count: usize) -> Result<(), ScriptError> {
    if stack.len() < count {
        Err(ScriptError::InvalidStackOperation)
    } else {
        Ok(())
    }
}

fn duplicate_tail(stack: &mut Vec<Vec<u8>>, count: usize) -> Result<(), ScriptError> {
    require_stack(stack, count)?;
    let start = stack.len() - count;
    let values = stack[start..].to_vec();
    stack.extend(values);
    Ok(())
}

fn enforce_stack_limit(stack: &[Vec<u8>], alt_stack: &[Vec<u8>]) -> Result<(), ScriptError> {
    if stack.len().saturating_add(alt_stack.len()) > MAX_SCRIPT_STACK {
        Err(ScriptError::StackSize)
    } else {
        Ok(())
    }
}

#[derive(Debug, thiserror::Error, Eq, PartialEq)]
pub enum ScriptError {
    #[error("input index is outside the transaction")]
    InputIndexOutOfRange,
    #[error("OP_RETURN")]
    OpReturn,
    #[error("script exceeds the consensus size limit")]
    ScriptSize,
    #[error("script stack exceeds the consensus item limit")]
    StackSize,
    #[error("script push exceeds the consensus item-size limit")]
    PushSize,
    #[error("witness program has an empty witness")]
    WitnessProgramWitnessEmpty,
    #[error("witness program does not match the committed hash or shape")]
    WitnessProgramMismatch,
    #[error("version-zero witness program has the wrong length")]
    WitnessProgramWrongLength,
    #[error("upgradable witness program is discouraged by policy")]
    DiscourageUpgradableWitnessProgram,
    #[error("upgradable NOP is discouraged by policy")]
    DiscourageUpgradableNops,
    #[error("script evaluated to false")]
    EvalFalse,
    #[error("script contains malformed or invalid opcode 0x{0:02x}")]
    BadOpcode(u8),
    #[error("script contains disabled opcode 0x{0:02x}")]
    DisabledOpcode(u8),
    #[error("script opcode 0x{0:02x} is not yet implemented")]
    UnsupportedOpcode(u8),
    #[error("script operation count exceeds the consensus limit")]
    OperationCount,
    #[error("script push is not minimally encoded")]
    MinimalData,
    #[error("script number is not minimally encoded")]
    NonMinimalNumber,
    #[error("conditional argument is not minimally encoded")]
    MinimalIf,
    #[error("script conditional is unbalanced")]
    UnbalancedConditional,
    #[error("invalid main-stack operation")]
    InvalidStackOperation,
    #[error("invalid alt-stack operation")]
    InvalidAltStackOperation,
    #[error("VERIFY failed")]
    Verify,
    #[error("EQUALVERIFY failed")]
    EqualVerify,
    #[error("NUMEQUALVERIFY failed")]
    NumEqualVerify,
    #[error("negative locktime")]
    NegativeLocktime,
    #[error("locktime predicate is not satisfied")]
    UnsatisfiedLocktime,
    #[error("script number overflow")]
    NumericOverflow,
    #[error("public key count is invalid")]
    PublicKeyCount,
    #[error("signature count is invalid")]
    SignatureCount,
    #[error("public key encoding is invalid")]
    PublicKeyEncoding,
    #[error("signature encoding is invalid")]
    SignatureEncoding,
    #[error("multisig dummy argument is not empty")]
    SignatureNullDummy,
    #[error("NULLFAIL")]
    NullFail,
    #[error("CHECKSIGVERIFY failed")]
    CheckSigVerify,
    #[error("CHECKMULTISIGVERIFY failed")]
    CheckMultiSigVerify,
    #[error("secp256k1 signature backend is unavailable")]
    SignatureBackendUnavailable,
    #[error("signature hash failed: {0}")]
    Sighash(String),
}

impl ScriptError {
    /// Return the rejection code used by the pinned HSD script engine for the
    /// same failure class. This is diagnostic parity only; consensus callers
    /// must continue to treat every error as rejection.
    pub const fn hsd_code(&self) -> &'static str {
        match self {
            Self::InputIndexOutOfRange
            | Self::NumericOverflow
            | Self::NonMinimalNumber
            | Self::SignatureBackendUnavailable
            | Self::Sighash(_) => "UNKNOWN_ERROR",
            Self::OpReturn => "OP_RETURN",
            Self::ScriptSize => "SCRIPT_SIZE",
            Self::StackSize => "STACK_SIZE",
            Self::PushSize => "PUSH_SIZE",
            Self::WitnessProgramWitnessEmpty => "WITNESS_PROGRAM_WITNESS_EMPTY",
            Self::WitnessProgramMismatch => "WITNESS_PROGRAM_MISMATCH",
            Self::WitnessProgramWrongLength => "WITNESS_PROGRAM_WRONG_LENGTH",
            Self::DiscourageUpgradableWitnessProgram => "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM",
            Self::DiscourageUpgradableNops => "DISCOURAGE_UPGRADABLE_NOPS",
            Self::EvalFalse => "EVAL_FALSE",
            Self::BadOpcode(_) | Self::UnsupportedOpcode(_) => "BAD_OPCODE",
            Self::DisabledOpcode(_) => "DISABLED_OPCODE",
            Self::OperationCount => "OP_COUNT",
            Self::MinimalData => "MINIMALDATA",
            Self::MinimalIf => "MINIMALIF",
            Self::UnbalancedConditional => "UNBALANCED_CONDITIONAL",
            Self::InvalidStackOperation => "INVALID_STACK_OPERATION",
            Self::InvalidAltStackOperation => "INVALID_ALTSTACK_OPERATION",
            Self::Verify => "VERIFY",
            Self::EqualVerify => "EQUALVERIFY",
            Self::NumEqualVerify => "NUMEQUALVERIFY",
            Self::NegativeLocktime => "NEGATIVE_LOCKTIME",
            Self::UnsatisfiedLocktime => "UNSATISFIED_LOCKTIME",
            Self::PublicKeyCount => "PUBKEY_COUNT",
            Self::SignatureCount => "SIG_COUNT",
            Self::PublicKeyEncoding => "PUBKEY_ENCODING",
            Self::SignatureEncoding => "SIG_ENCODING",
            Self::SignatureNullDummy => "SIG_NULLDUMMY",
            Self::NullFail => "NULLFAIL",
            Self::CheckSigVerify => "CHECKSIGVERIFY",
            Self::CheckMultiSigVerify => "CHECKMULTISIGVERIFY",
        }
    }
}

#[cfg(test)]
mod tests {
    use hns_primitives::{
        Address, Covenant, CovenantKind, Input, Outpoint, Output, Transaction, Txid, Witness,
    };
    use serde::Deserialize;

    use super::*;

    #[derive(Clone, Copy)]
    struct AcceptingSignatures;

    impl SignatureVerifier for AcceptingSignatures {
        fn validate_compact_signature(&self, _signature: &[u8; 64]) -> Result<(), ScriptError> {
            Ok(())
        }

        fn verify(
            &self,
            _message: &[u8; 32],
            _signature: &[u8; 64],
            _public_key: &[u8; 33],
        ) -> Result<bool, ScriptError> {
            Ok(true)
        }
    }

    fn transaction(witness: Witness, output: Output) -> (Transaction, Coin) {
        let outpoint = Outpoint {
            txid: Txid::new([7; 32]),
            index: 1,
        };
        let coin = Coin {
            outpoint: outpoint.clone(),
            value: 50,
            height: 1,
            coinbase: false,
            address: output.address.clone(),
            covenant: Covenant {
                kind: CovenantKind::None,
                items: Vec::new(),
            },
        };
        (
            Transaction {
                version: 1,
                inputs: vec![Input {
                    previous_output: outpoint,
                    sequence: u32::MAX,
                    witness,
                }],
                outputs: vec![output],
                locktime: 0,
            },
            coin,
        )
    }

    fn output(address: Address) -> Output {
        Output {
            value: 49,
            address,
            covenant: Covenant {
                kind: CovenantKind::None,
                items: Vec::new(),
            },
        }
    }

    #[test]
    fn version_zero_script_hash_executes_basic_program() {
        let script = vec![OP_1];
        let address = Address::new(0, sha3_256(&script).to_vec()).expect("address");
        let witness = Witness {
            items: vec![script],
        };
        let (transaction, coin) = transaction(witness, output(address));
        verify_witness_program(
            &transaction,
            0,
            &coin,
            ScriptFlags::MANDATORY,
            &AcceptingSignatures,
        )
        .expect("valid program");
    }

    #[test]
    fn version_zero_script_hash_rejects_a_mismatched_program() {
        let address = Address::new(0, vec![1; 32]).expect("address");
        let witness = Witness {
            items: vec![vec![OP_1]],
        };
        let (transaction, coin) = transaction(witness, output(address));
        assert_eq!(
            verify_witness_program(
                &transaction,
                0,
                &coin,
                ScriptFlags::MANDATORY,
                &AcceptingSignatures,
            ),
            Err(ScriptError::WitnessProgramMismatch)
        );
    }

    #[test]
    fn pubkey_hash_program_reaches_the_signature_backend() {
        let public_key = [
            0x02, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
            23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let mut signature = vec![0x01; 65];
        signature[64] = 1;
        let address = Address::new(0, blake2b_160(&public_key).to_vec()).expect("address");
        let witness = Witness {
            items: vec![signature, public_key.to_vec()],
        };
        let (transaction, coin) = transaction(witness, output(address));
        verify_witness_program(
            &transaction,
            0,
            &coin,
            ScriptFlags::MANDATORY,
            &AcceptingSignatures,
        )
        .expect("valid P2WPKH shape");
    }

    #[test]
    fn missing_signature_backend_fails_closed() {
        let public_key = [
            0x02, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22,
            23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
        ];
        let mut signature = vec![0x01; 65];
        signature[64] = 1;
        let address = Address::new(0, blake2b_160(&public_key).to_vec()).expect("address");
        let witness = Witness {
            items: vec![signature, public_key.to_vec()],
        };
        let (transaction, coin) = transaction(witness, output(address));
        assert_eq!(
            verify_witness_program(
                &transaction,
                0,
                &coin,
                ScriptFlags::MANDATORY,
                &UnavailableSignatureVerifier,
            ),
            Err(ScriptError::SignatureBackendUnavailable)
        );
    }

    #[test]
    fn sigop_count_matches_hsd_witness_program_rules() {
        let pubkey_hash = Address::new(0, vec![0x11; 20]).expect("pubkey-hash address");
        assert_eq!(witness_program_sigops(&pubkey_hash, &Witness::default()), 1);

        let script_hash = Address::new(0, vec![0x22; 32]).expect("script-hash address");
        let witness = Witness {
            items: vec![vec![OP_1 + 1, OP_CHECKMULTISIG, OP_CHECKSIG]],
        };
        assert_eq!(witness_program_sigops(&script_hash, &witness), 3);
        assert_eq!(
            count_script_sigops(&[OP_CHECKSIG, OP_PUSHDATA1]),
            1,
            "a malformed trailing push retains the valid-prefix count"
        );

        let future_program = Address::new(1, vec![0x33; 32]).expect("future witness address");
        assert_eq!(witness_program_sigops(&future_program, &witness), 0);
    }

    #[test]
    fn script_number_encoding_handles_negative_zero_rules() {
        for value in [-2, -1, 0, 1, 2, 127, 128, 255, 256] {
            let encoded = encode_script_number(value);
            assert!(is_minimal_script_number(&encoded));
            assert_eq!(decode_script_number(&encoded, true, 8).unwrap(), value);
        }
        assert!(!cast_to_bool(&[0x80]));
        assert!(cast_to_bool(&[0x81]));
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ScriptExecutionFixture {
        schema: u32,
        vectors: Vec<ScriptExecutionVector>,
    }

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct ScriptExecutionVector {
        id: String,
        script_raw: String,
        witness: Vec<String>,
        transaction_raw: String,
        previous_value: u64,
        address_version: u8,
        address_hash: String,
        sigops: u32,
        flags: Vec<String>,
        result: String,
    }

    #[test]
    fn script_execution_matches_hsd_fixture() {
        let fixture: ScriptExecutionFixture = serde_json::from_slice(include_bytes!(
            "../../../fixtures/hsd/scripts/execution-v1.json"
        ))
        .expect("script execution fixture");
        assert_eq!(fixture.schema, 2);
        let signatures = NativeSignatureVerifier::new().expect("native signature verifier");

        for vector in fixture.vectors {
            let transaction = Transaction::decode(&decode_hex(&vector.transaction_raw))
                .unwrap_or_else(|error| panic!("{} transaction: {error}", vector.id));
            let input = transaction
                .inputs
                .first()
                .unwrap_or_else(|| panic!("{} input", vector.id));
            let expected_witness = vector
                .witness
                .iter()
                .map(|item| decode_hex(item))
                .chain(std::iter::once(decode_hex(&vector.script_raw)))
                .collect::<Vec<_>>();
            assert_eq!(
                input.witness.items, expected_witness,
                "{} witness",
                vector.id
            );
            let coin = Coin {
                outpoint: input.previous_output.clone(),
                value: vector.previous_value,
                height: 1,
                coinbase: false,
                address: Address::new(vector.address_version, decode_hex(&vector.address_hash))
                    .unwrap_or_else(|error| panic!("{} address: {error}", vector.id)),
                covenant: Covenant {
                    kind: CovenantKind::None,
                    items: Vec::new(),
                },
            };
            let flags = fixture_flags(&vector.flags);
            assert_eq!(
                count_script_sigops(&decode_hex(&vector.script_raw)),
                vector.sigops,
                "{} script sigops",
                vector.id
            );
            assert_eq!(
                transaction_sigops(&transaction, std::slice::from_ref(&coin))
                    .unwrap_or_else(|error| panic!("{} transaction sigops: {error}", vector.id)),
                vector.sigops,
                "{} transaction sigops",
                vector.id
            );
            let observed = match verify_witness_program(&transaction, 0, &coin, flags, &signatures)
            {
                Ok(()) => "OK",
                Err(error) => error.hsd_code(),
            };
            assert_eq!(observed, vector.result, "{} result", vector.id);
        }
    }

    fn fixture_flags(names: &[String]) -> ScriptFlags {
        let mut flags = ScriptFlags::NONE;
        for name in names {
            flags.0 |= match name.as_str() {
                "MINIMALDATA" => ScriptFlags::VERIFY_MINIMAL_DATA.0,
                "DISCOURAGE_UPGRADABLE_NOPS" => ScriptFlags::VERIFY_DISCOURAGE_UPGRADABLE_NOPS.0,
                "DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM" => {
                    ScriptFlags::VERIFY_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM.0
                }
                "MINIMALIF" => ScriptFlags::VERIFY_MINIMAL_IF.0,
                "NULLFAIL" => ScriptFlags::VERIFY_NULLFAIL.0,
                other => panic!("unknown fixture script flag {other}"),
            };
        }
        flags
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0, "hex fixture length");
        (0..value.len())
            .step_by(2)
            .map(|offset| {
                u8::from_str_radix(&value[offset..offset + 2], 16).expect("hex fixture byte")
            })
            .collect()
    }
}
