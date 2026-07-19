//! Verification-only, safe Rust ownership wrapper around the exact
//! libsecp256k1 source revision vendored by HSD's pinned bcrypto dependency.
//!
//! The crate deliberately exposes no signing or key-generation API. Consensus
//! code needs only compact ECDSA signature parsing, HSD's low-S rule, compressed
//! public-key parsing, and verification.

use std::{ffi::c_void, ptr::NonNull, sync::Arc};

const CONTEXT_VERIFY: u32 = (1 << 0) | (1 << 8);

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

#[derive(Debug)]
struct VerificationContext {
    pointer: NonNull<c_void>,
}

impl VerificationContext {
    fn new() -> Result<Self, SecpError> {
        let pointer = unsafe { secp256k1_context_create(CONTEXT_VERIFY) };
        let pointer = NonNull::new(pointer).ok_or(SecpError::ContextCreation)?;
        Ok(Self { pointer })
    }

    fn as_ptr(&self) -> *const c_void {
        self.pointer.as_ptr().cast_const()
    }
}

impl Drop for VerificationContext {
    fn drop(&mut self) {
        unsafe { secp256k1_context_destroy(self.pointer.as_ptr()) };
    }
}

// libsecp256k1 verification contexts are immutable after construction and its
// public documentation permits contexts to be shared for concurrent reads.
unsafe impl Send for VerificationContext {}
unsafe impl Sync for VerificationContext {}

/// Cloneable, thread-safe verifier backed by one immutable verification
/// context. Construction runs libsecp256k1's built-in self-test.
#[derive(Clone, Debug)]
pub struct Secp256k1Verifier {
    context: Arc<VerificationContext>,
}

impl Secp256k1Verifier {
    pub fn new() -> Result<Self, SecpError> {
        Ok(Self {
            context: Arc::new(VerificationContext::new()?),
        })
    }

    /// Parse a 64-byte compact `(r,s)` signature and enforce HSD's low-S rule.
    pub fn validate_compact_signature(&self, compact: &[u8; 64]) -> Result<(), SecpError> {
        let signature = self.parse_signature(compact)?;
        let was_high = unsafe {
            secp256k1_ecdsa_signature_normalize(
                self.context.as_ptr(),
                std::ptr::null_mut(),
                &signature,
            )
        };
        if was_high != 0 {
            return Err(SecpError::HighS);
        }
        Ok(())
    }

    /// Verify an HSD compact, low-S ECDSA signature against a compressed key.
    pub fn verify(
        &self,
        message: &[u8; 32],
        compact: &[u8; 64],
        compressed_public_key: &[u8; 33],
    ) -> Result<bool, SecpError> {
        let signature = self.parse_signature(compact)?;
        let was_high = unsafe {
            secp256k1_ecdsa_signature_normalize(
                self.context.as_ptr(),
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
                self.context.as_ptr(),
                &mut public_key,
                compressed_public_key.as_ptr(),
                compressed_public_key.len(),
            )
        };
        if parsed != 1 {
            return Err(SecpError::InvalidPublicKey);
        }

        let valid = unsafe {
            secp256k1_ecdsa_verify(
                self.context.as_ptr(),
                &signature,
                message.as_ptr(),
                &public_key,
            )
        };
        Ok(valid == 1)
    }

    fn parse_signature(&self, compact: &[u8; 64]) -> Result<SecpSignature, SecpError> {
        let mut signature = SecpSignature { data: [0; 64] };
        let parsed = unsafe {
            secp256k1_ecdsa_signature_parse_compact(
                self.context.as_ptr(),
                &mut signature,
                compact.as_ptr(),
            )
        };
        if parsed != 1 {
            return Err(SecpError::InvalidCompactSignature);
        }
        Ok(signature)
    }
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
}
