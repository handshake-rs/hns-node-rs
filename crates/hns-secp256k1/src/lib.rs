//! Safe Rust ownership wrapper around the exact
//! libsecp256k1 source revision vendored by HSD's pinned bcrypto dependency.
//!
//! Consensus code uses compact ECDSA verification. P2P transport additionally
//! uses public-key derivation, raw compressed ECDH, and Elligator-Squared. The
//! crate deliberately exposes no signing API. The FFI context is thread-local,
//! keeping all unsafe ownership details here without asserting `Send` or `Sync`
//! for a foreign pointer.

use std::{cell::RefCell, ffi::c_void, ptr::NonNull};

const CONTEXT_VERIFY_AND_SIGN: u32 = (1 << 0) | (1 << 8) | (1 << 9);
const EC_COMPRESSED: u32 = (1 << 1) | (1 << 8);

#[repr(C)]
struct SecpPublicKey {
    data: [u8; 64],
}

#[repr(C)]
struct SecpSignature {
    data: [u8; 64],
}

extern "C" {
    fn secp256k1_context_create(flags: u32) -> *mut c_void;
    fn secp256k1_context_destroy(context: *mut c_void);
    fn secp256k1_ec_pubkey_parse(
        context: *const c_void,
        output: *mut SecpPublicKey,
        input: *const u8,
        input_len: usize,
    ) -> i32;
    fn secp256k1_ec_pubkey_create(
        context: *const c_void,
        output: *mut SecpPublicKey,
        secret_key: *const u8,
    ) -> i32;
    fn secp256k1_ec_pubkey_serialize(
        context: *const c_void,
        output: *mut u8,
        output_len: *mut usize,
        public_key: *const SecpPublicKey,
        flags: u32,
    ) -> i32;
    fn secp256k1_ecdh(
        context: *const c_void,
        output: *mut u8,
        public_key: *const SecpPublicKey,
        secret_key: *const u8,
        hash_function: Option<EcdhHashFunction>,
        data: *mut c_void,
    ) -> i32;
    fn secp256k1_ec_pubkey_from_hash(
        context: *const c_void,
        output: *mut SecpPublicKey,
        bytes64: *const u8,
    ) -> i32;
    fn secp256k1_ec_pubkey_to_hash(
        context: *const c_void,
        output: *mut u8,
        public_key: *const SecpPublicKey,
        entropy: *const u8,
    ) -> i32;
    fn secp256k1_ecdsa_signature_parse_compact(
        context: *const c_void,
        output: *mut SecpSignature,
        input: *const u8,
    ) -> i32;
    fn secp256k1_ecdsa_signature_normalize(
        context: *const c_void,
        output: *mut SecpSignature,
        input: *const SecpSignature,
    ) -> i32;
    fn secp256k1_ecdsa_verify(
        context: *const c_void,
        signature: *const SecpSignature,
        message: *const u8,
        public_key: *const SecpPublicKey,
    ) -> i32;
}

type EcdhHashFunction = unsafe extern "C" fn(
    output: *mut u8,
    x_coordinate: *const u8,
    y_coordinate: *const u8,
    data: *mut c_void,
) -> i32;

unsafe extern "C" fn compressed_ecdh_point(
    output: *mut u8,
    x_coordinate: *const u8,
    y_coordinate: *const u8,
    _data: *mut c_void,
) -> i32 {
    // Match bcrypto's `ecdh_hash_function_raw(..., compress=true)`: the caller
    // hashes this 33-byte compressed point with SHA256 at the Noise layer.
    unsafe {
        *output = 0x02 | (*y_coordinate.add(31) & 1);
        std::ptr::copy_nonoverlapping(x_coordinate, output.add(1), 32);
    }
    1
}

#[derive(Debug)]
struct SecpContext {
    pointer: NonNull<c_void>,
}

impl SecpContext {
    fn new() -> Result<Self, SecpError> {
        let pointer = unsafe { secp256k1_context_create(CONTEXT_VERIFY_AND_SIGN) };
        let pointer = NonNull::new(pointer).ok_or(SecpError::ContextCreation)?;
        Ok(Self { pointer })
    }

    fn as_ptr(&self) -> *const c_void {
        self.pointer.as_ptr().cast_const()
    }
}

impl Drop for SecpContext {
    fn drop(&mut self) {
        unsafe { secp256k1_context_destroy(self.pointer.as_ptr()) };
    }
}

thread_local! {
    static SECP_CONTEXT: RefCell<Option<SecpContext>> = const { RefCell::new(None) };
}

fn with_context<T>(
    operation: impl FnOnce(&SecpContext) -> Result<T, SecpError>,
) -> Result<T, SecpError> {
    SECP_CONTEXT.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(SecpContext::new()?);
        }
        operation(slot.as_ref().expect("verification context initialized"))
    })
}

/// Stateless transport primitive provider backed by the same pinned context
/// as [`Secp256k1Verifier`]. Private keys are always supplied by the caller and
/// never retained by this type.
#[derive(Clone, Copy, Debug, Default)]
pub struct Secp256k1Transport;

impl Secp256k1Transport {
    /// Eagerly exercise context construction for startup/readiness checks.
    pub fn new() -> Result<Self, SecpError> {
        with_context(|_| Ok(()))?;
        Ok(Self)
    }

    /// Derive the compressed public key for a valid 32-byte private scalar.
    pub fn public_key(&self, private_key: &[u8; 32]) -> Result<[u8; 33], SecpError> {
        with_context(|context| {
            let mut public_key = SecpPublicKey { data: [0; 64] };
            let created = unsafe {
                secp256k1_ec_pubkey_create(context.as_ptr(), &mut public_key, private_key.as_ptr())
            };
            if created != 1 {
                return Err(SecpError::InvalidPrivateKey);
            }
            serialize_public_key(context, &public_key)
        })
    }

    /// Derive the raw compressed shared point used by HSD before its SHA256.
    pub fn derive_compressed(
        &self,
        remote_public_key: &[u8; 33],
        private_key: &[u8; 32],
    ) -> Result<[u8; 33], SecpError> {
        with_context(|context| {
            let public_key = parse_public_key(context, remote_public_key)?;
            let mut shared = [0u8; 33];
            let derived = unsafe {
                secp256k1_ecdh(
                    context.as_ptr(),
                    shared.as_mut_ptr(),
                    &public_key,
                    private_key.as_ptr(),
                    Some(compressed_ecdh_point),
                    std::ptr::null_mut(),
                )
            };
            if derived != 1 {
                return Err(SecpError::InvalidPrivateKey);
            }
            Ok(shared)
        })
    }

    /// Decode HSD's 64-byte Elligator-Squared representation.
    pub fn public_key_from_hash(&self, encoded: &[u8; 64]) -> Result<[u8; 33], SecpError> {
        with_context(|context| {
            let mut public_key = SecpPublicKey { data: [0; 64] };
            let decoded = unsafe {
                secp256k1_ec_pubkey_from_hash(context.as_ptr(), &mut public_key, encoded.as_ptr())
            };
            if decoded != 1 {
                return Err(SecpError::InvalidElligatorEncoding);
            }
            serialize_public_key(context, &public_key)
        })
    }

    /// Encode a compressed key with HSD's Elligator-Squared transform.
    /// `entropy` is explicit so callers can use an OS RNG in production and
    /// fixed oracle entropy in compatibility tests.
    pub fn public_key_to_hash(
        &self,
        public_key: &[u8; 33],
        entropy: &[u8; 32],
    ) -> Result<[u8; 64], SecpError> {
        with_context(|context| {
            let public_key = parse_public_key(context, public_key)?;
            let mut encoded = [0u8; 64];
            let encoded_ok = unsafe {
                secp256k1_ec_pubkey_to_hash(
                    context.as_ptr(),
                    encoded.as_mut_ptr(),
                    &public_key,
                    entropy.as_ptr(),
                )
            };
            if encoded_ok != 1 {
                return Err(SecpError::InvalidElligatorEncoding);
            }
            Ok(encoded)
        })
    }
}

/// Stateless, cloneable verifier. The actual libsecp256k1 context is created
/// lazily once per calling thread and destroyed when that thread exits.
#[derive(Clone, Copy, Debug, Default)]
pub struct Secp256k1Verifier;

impl Secp256k1Verifier {
    /// Eagerly exercise context construction for startup/readiness checks.
    pub fn new() -> Result<Self, SecpError> {
        with_context(|_| Ok(()))?;
        Ok(Self)
    }

    /// Parse a 64-byte compact `(r,s)` signature and enforce HSD's low-S rule.
    pub fn validate_compact_signature(&self, compact: &[u8; 64]) -> Result<(), SecpError> {
        with_context(|context| {
            let signature = parse_signature(context, compact)?;
            let was_high = unsafe {
                secp256k1_ecdsa_signature_normalize(
                    context.as_ptr(),
                    std::ptr::null_mut(),
                    &signature,
                )
            };
            if was_high != 0 {
                return Err(SecpError::HighS);
            }
            Ok(())
        })
    }

    /// Verify an HSD compact, low-S ECDSA signature against a compressed key.
    pub fn verify(
        &self,
        message: &[u8; 32],
        compact: &[u8; 64],
        compressed_public_key: &[u8; 33],
    ) -> Result<bool, SecpError> {
        with_context(|context| {
            let signature = parse_signature(context, compact)?;
            let was_high = unsafe {
                secp256k1_ecdsa_signature_normalize(
                    context.as_ptr(),
                    std::ptr::null_mut(),
                    &signature,
                )
            };
            if was_high != 0 {
                return Err(SecpError::HighS);
            }

            let mut public_key = SecpPublicKey { data: [0; 64] };
            let parsed = unsafe {
                secp256k1_ec_pubkey_parse(
                    context.as_ptr(),
                    &mut public_key,
                    compressed_public_key.as_ptr(),
                    compressed_public_key.len(),
                )
            };
            if parsed != 1 {
                return Err(SecpError::InvalidPublicKey);
            }

            let valid = unsafe {
                secp256k1_ecdsa_verify(context.as_ptr(), &signature, message.as_ptr(), &public_key)
            };
            Ok(valid == 1)
        })
    }
}

fn parse_signature(context: &SecpContext, compact: &[u8; 64]) -> Result<SecpSignature, SecpError> {
    let mut signature = SecpSignature { data: [0; 64] };
    let parsed = unsafe {
        secp256k1_ecdsa_signature_parse_compact(context.as_ptr(), &mut signature, compact.as_ptr())
    };
    if parsed != 1 {
        return Err(SecpError::InvalidCompactSignature);
    }
    Ok(signature)
}

fn parse_public_key(
    context: &SecpContext,
    compressed_public_key: &[u8; 33],
) -> Result<SecpPublicKey, SecpError> {
    let mut public_key = SecpPublicKey { data: [0; 64] };
    let parsed = unsafe {
        secp256k1_ec_pubkey_parse(
            context.as_ptr(),
            &mut public_key,
            compressed_public_key.as_ptr(),
            compressed_public_key.len(),
        )
    };
    if parsed != 1 {
        return Err(SecpError::InvalidPublicKey);
    }
    Ok(public_key)
}

fn serialize_public_key(
    context: &SecpContext,
    public_key: &SecpPublicKey,
) -> Result<[u8; 33], SecpError> {
    let mut compressed = [0u8; 33];
    let mut length = compressed.len();
    let serialized = unsafe {
        secp256k1_ec_pubkey_serialize(
            context.as_ptr(),
            compressed.as_mut_ptr(),
            &mut length,
            public_key,
            EC_COMPRESSED,
        )
    };
    if serialized != 1 || length != compressed.len() {
        return Err(SecpError::InvalidPublicKey);
    }
    Ok(compressed)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SecpError {
    #[error("libsecp256k1 verification context creation failed")]
    ContextCreation,
    #[error("compact ECDSA signature is invalid")]
    InvalidCompactSignature,
    #[error("compact ECDSA signature is not low-S")]
    HighS,
    #[error("compressed secp256k1 public key is invalid")]
    InvalidPublicKey,
    #[error("secp256k1 private key is invalid")]
    InvalidPrivateKey,
    #[error("Elligator-Squared public-key encoding is invalid")]
    InvalidElligatorEncoding,
}

#[cfg(test)]
mod tests {
    use super::*;

    // SEC 2 generator point and a deterministic compact signature generated by
    // the pinned bcrypto/libsecp256k1 oracle for message [0x42; 32], key = 1.
    const PUBLIC_KEY: [u8; 33] = [
        0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87,
        0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16,
        0xf8, 0x17, 0x98,
    ];
    const SIGNATURE: [u8; 64] = [
        0x91, 0xc5, 0xbd, 0x51, 0xba, 0x17, 0x51, 0x34, 0xee, 0x4a, 0x66, 0x34, 0xa9, 0x3c, 0x2f,
        0x5c, 0xc3, 0xae, 0x8f, 0xc9, 0xba, 0xc3, 0xc9, 0x8b, 0x89, 0x60, 0x55, 0xbf, 0x0e, 0x5c,
        0xf7, 0x1c, 0x44, 0xf3, 0xbb, 0x8f, 0x35, 0xcd, 0x8e, 0x27, 0x04, 0xc3, 0x63, 0x0a, 0xb1,
        0xa3, 0xa9, 0x24, 0x75, 0x50, 0x23, 0x16, 0xd2, 0x5c, 0xb8, 0xc1, 0x66, 0xd7, 0x7b, 0xda,
        0xd9, 0xf3, 0xa6, 0xc9,
    ];

    #[test]
    fn pinned_oracle_signature_verifies() {
        let verifier = Secp256k1Verifier::new().expect("context");
        assert!(verifier
            .verify(&[0x42; 32], &SIGNATURE, &PUBLIC_KEY)
            .expect("verify"));
        assert!(!verifier
            .verify(&[0x43; 32], &SIGNATURE, &PUBLIC_KEY)
            .expect("verify altered message"));
    }

    #[test]
    fn malformed_key_and_high_s_fail_closed() {
        let verifier = Secp256k1Verifier::new().expect("context");
        let mut bad_key = PUBLIC_KEY;
        bad_key[0] = 0x04;
        assert_eq!(
            verifier.verify(&[0x42; 32], &SIGNATURE, &bad_key),
            Err(SecpError::InvalidPublicKey)
        );

        // n - s for the low-S fixture above.
        let high_s = [
            0x91, 0xc5, 0xbd, 0x51, 0xba, 0x17, 0x51, 0x34, 0xee, 0x4a, 0x66, 0x34, 0xa9, 0x3c,
            0x2f, 0x5c, 0xc3, 0xae, 0x8f, 0xc9, 0xba, 0xc3, 0xc9, 0x8b, 0x89, 0x60, 0x55, 0xbf,
            0x0e, 0x5c, 0xf7, 0x1c, 0xbb, 0x0c, 0x44, 0x70, 0xca, 0x32, 0x71, 0xd8, 0xfb, 0x3c,
            0x9c, 0xf5, 0x4e, 0x5c, 0x56, 0xda, 0x45, 0x5e, 0xb9, 0xcf, 0xdc, 0xeb, 0xe7, 0x7a,
            0x58, 0xfa, 0xe2, 0xb1, 0xf6, 0x42, 0x9a, 0x78,
        ];
        assert_eq!(
            verifier.validate_compact_signature(&high_s),
            Err(SecpError::HighS)
        );
    }

    #[test]
    fn transport_public_key_ecdh_and_elligator_round_trip() {
        let transport = Secp256k1Transport::new().expect("context");
        let private_one = [1u8; 32];
        let private_two = [2u8; 32];
        let public_one = transport.public_key(&private_one).expect("public one");
        let public_two = transport.public_key(&private_two).expect("public two");

        let shared_one = transport
            .derive_compressed(&public_two, &private_one)
            .expect("shared one");
        let shared_two = transport
            .derive_compressed(&public_one, &private_two)
            .expect("shared two");
        assert_eq!(shared_one, shared_two);

        let encoded = transport
            .public_key_to_hash(&public_one, &[0x42; 32])
            .expect("encode");
        assert_eq!(
            transport.public_key_from_hash(&encoded).expect("decode"),
            public_one
        );
        assert_eq!(
            transport.public_key(&[0; 32]),
            Err(SecpError::InvalidPrivateKey)
        );
    }
}
