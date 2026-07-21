//! Verification-only ownership wrapper around the exact Goosig C source
//! shipped by HSD's pinned dependency.
//!
//! The crate exposes no signing, challenge, encryption, or key-generation
//! interface. Foreign context ownership remains thread-local so the public
//! verifier is safely `Send + Sync` without making claims about a C pointer.

use std::{cell::RefCell, ffi::c_void, ptr::NonNull};

pub const GOO_COMMITMENT_SIZE: usize = 256;

extern "C" {
    static GOO_RSA2048: [u8; GOO_COMMITMENT_SIZE];

    fn goo_create(
        modulus: *const u8,
        modulus_len: usize,
        generator: std::os::raw::c_ulong,
        secondary_generator: std::os::raw::c_ulong,
        bits: std::os::raw::c_ulong,
    ) -> *mut c_void;
    fn goo_destroy(context: *mut c_void);
    fn goo_verify(
        context: *mut c_void,
        message: *const u8,
        message_len: usize,
        signature: *const u8,
        signature_len: usize,
        commitment: *const u8,
        commitment_len: usize,
    ) -> i32;
}

#[derive(Debug)]
struct VerificationContext {
    pointer: NonNull<c_void>,
}

impl VerificationContext {
    fn new() -> Result<Self, GooSigError> {
        // SAFETY: the modulus points to the exact 256-byte static declared by
        // the linked Goosig source, and the integer parameters match HSD's
        // verifier-only construction. Ownership of a non-null result is
        // transferred to this value and released by `Drop`.
        let pointer = unsafe { goo_create(GOO_RSA2048.as_ptr(), GOO_COMMITMENT_SIZE, 2, 3, 0) };
        let pointer = NonNull::new(pointer).ok_or(GooSigError::ContextCreation)?;
        Ok(Self { pointer })
    }
}

impl Drop for VerificationContext {
    fn drop(&mut self) {
        // SAFETY: this is the unique owned context returned by `goo_create`;
        // it is destroyed exactly once and never used again.
        unsafe { goo_destroy(self.pointer.as_ptr()) };
    }
}

thread_local! {
    static VERIFY_CONTEXT: RefCell<Option<VerificationContext>> = const { RefCell::new(None) };
}

fn with_context<T>(
    operation: impl FnOnce(&VerificationContext) -> Result<T, GooSigError>,
) -> Result<T, GooSigError> {
    VERIFY_CONTEXT.with(|slot| {
        let mut slot = slot.borrow_mut();
        if slot.is_none() {
            *slot = Some(VerificationContext::new()?);
        }
        operation(slot.as_ref().expect("verification context initialized"))
    })
}

#[derive(Clone, Copy, Debug, Default)]
pub struct GooSigVerifier;

impl GooSigVerifier {
    /// Eagerly create the calling thread's verification context for startup
    /// readiness checks.
    pub fn new() -> Result<Self, GooSigError> {
        with_context(|_| Ok(()))?;
        Ok(Self)
    }

    pub fn verify(
        &self,
        message: &[u8],
        signature: &[u8],
        commitment: &[u8; GOO_COMMITMENT_SIZE],
    ) -> Result<bool, GooSigError> {
        with_context(|context| {
            // SAFETY: the context belongs exclusively to this thread, and all
            // byte pointers remain valid for their supplied lengths throughout
            // the synchronous verification call.
            let valid = unsafe {
                goo_verify(
                    context.pointer.as_ptr(),
                    message.as_ptr(),
                    message.len(),
                    signature.as_ptr(),
                    signature.len(),
                    commitment.as_ptr(),
                    commitment.len(),
                )
            };
            Ok(valid == 1)
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum GooSigError {
    #[error("Goosig verification context creation failed")]
    ContextCreation,
}
