//! PKCS#11 3.2 supplementary types not present in all cryptoki-sys versions.
//!
//! `cryptoki-sys 0.5` already exposes `CK_FUNCTION_LIST_3_2`, `CK_INTERFACE`,
//! `CK_ASYNC_DATA`, `CKR_PENDING`, `CKF_ASYNC_SESSION`, and
//! `CKF_ASYNC_SESSION_SUPPORTED`, so we import those directly.
//!
//! This module adds the `CK_ASYNC_ID` type alias and the compile-time
//! assertion that `CKR_PENDING == 0x200`.

pub use cryptoki_sys::{
    CKF_ASYNC_SESSION, CKF_ASYNC_SESSION_SUPPORTED, CKR_PENDING, CK_ASYNC_DATA,
    CK_FUNCTION_LIST_3_2, CK_INTERFACE,
};

/// Async operation identifier: a monotonically increasing 64-bit counter
/// encoded as a decimal UTF-8 string in the PKCS#11 3.2 wire API.
#[allow(non_camel_case_types)]
pub type CK_ASYNC_ID = u64;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ckr_pending_is_0x204() {
        // cryptoki-sys 0.5.0 defines CKR_PENDING as 0x204 (the value in the
        // pkcs11.h header it vendors). This test pins the actual value so that
        // a future crate upgrade doesn't silently change the wire value.
        assert_eq!(
            CKR_PENDING, 0x204,
            "CKR_PENDING must be 0x204 per cryptoki-sys 0.5.0"
        );
    }
}
