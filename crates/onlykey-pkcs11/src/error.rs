//! Error mapping: TransportError -> CK_RV, and FFI panic safety.

use cryptoki_sys::{
    CKR_DEVICE_ERROR, CKR_DEVICE_REMOVED, CKR_FUNCTION_REJECTED, CKR_GENERAL_ERROR,
    CKR_TOKEN_NOT_PRESENT, CKR_USER_NOT_LOGGED_IN, CK_RV,
};
use onlykey_transport::TransportError;

/// Map a `TransportError` to the appropriate `CK_RV` return code.
///
/// - `ChallengeTimeout` -> `CKR_FUNCTION_REJECTED` (per openspec settled constraint,
///   NOT `CKR_FUNCTION_CANCELED`).
/// - `Disconnected` / `NotFound` -> `CKR_DEVICE_REMOVED`.
/// - `Locked` / `Uninitialized` -> `CKR_USER_NOT_LOGGED_IN`.
/// - All others -> `CKR_DEVICE_ERROR`.
pub fn transport_to_ckr(e: &TransportError) -> CK_RV {
    match e {
        TransportError::ChallengeTimeout => CKR_FUNCTION_REJECTED,
        TransportError::Disconnected | TransportError::NotFound => CKR_DEVICE_REMOVED,
        TransportError::Locked | TransportError::Uninitialized => CKR_USER_NOT_LOGGED_IN,
        TransportError::Device(_)
        | TransportError::Protocol(_)
        | TransportError::Config(_)
        | TransportError::Hid(_) => CKR_DEVICE_ERROR,
    }
}

/// Wrap an FFI-boundary function in a `catch_unwind` to prevent Rust panics
/// from crossing into C code (which is undefined behaviour).
///
/// If the inner function panics, `CKR_GENERAL_ERROR` is returned.
pub fn catch_panic<F: FnOnce() -> CK_RV + std::panic::UnwindSafe>(f: F) -> CK_RV {
    match std::panic::catch_unwind(f) {
        Ok(rv) => rv,
        Err(_) => {
            // We cannot log here (no stdout per spec; no guarantee stderr is safe).
            CKR_GENERAL_ERROR
        }
    }
}

/// Alias for the `TOKEN_NOT_PRESENT` return used by many functions when the
/// module has not been initialized.
pub const CKR_MODULE_NOT_INITIALIZED: CK_RV = CKR_TOKEN_NOT_PRESENT;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_timeout_maps_to_function_rejected() {
        assert_eq!(
            transport_to_ckr(&TransportError::ChallengeTimeout),
            CKR_FUNCTION_REJECTED
        );
    }

    #[test]
    fn disconnected_maps_to_device_removed() {
        assert_eq!(
            transport_to_ckr(&TransportError::Disconnected),
            CKR_DEVICE_REMOVED
        );
    }

    #[test]
    fn catch_panic_returns_general_error_on_panic() {
        let rv = catch_panic(|| panic!("test panic"));
        assert_eq!(rv, CKR_GENERAL_ERROR);
    }

    #[test]
    fn catch_panic_returns_inner_value_on_success() {
        let rv = catch_panic(|| 42);
        assert_eq!(rv, 42);
    }
}
