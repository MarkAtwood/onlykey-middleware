//! OnlyKey PKCS#11 3.2 module.
//!
//! This crate exports `C_GetFunctionList` and `C_GetInterface`, which are the
//! two entry points a PKCS#11 loader calls into. All other PKCS#11 functions
//! are reached through the returned function table.
//!
//! # Safety
//!
//! All exported C functions are wrapped in `catch_panic` to prevent Rust
//! panics from crossing the FFI boundary. Callers must ensure all pointer
//! arguments are valid for the lifetime of the call.
//!
//! # Global state
//!
//! A single `OnceLock<Mutex<Option<ModuleState>>>` is used. `C_Initialize`
//! populates it; `C_Finalize` clears it. A subsequent `C_Initialize` call
//! repopulates it (PKCS#11 allows Initialize/Finalize in a loop).

#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(non_snake_case)]

pub mod ck32;
pub mod config;
pub mod error;
pub mod ffi;
pub mod mechanism;
pub mod object;
pub mod session;
pub mod token;

use std::sync::{Mutex, OnceLock};

use cryptoki_sys::{
    CKR_ARGUMENTS_BAD, CKR_FUNCTION_NOT_SUPPORTED, CKR_OK, CK_FUNCTION_LIST, CK_RV, CK_VERSION,
};

use ck32::{CK_FUNCTION_LIST_3_2, CK_INTERFACE};
use object::ObjectTable;
use onlykey_transport::OnlyKeyDevice;
use session::SessionTable;

/// The global module state, protected by a mutex.
///
/// `None` means `C_Initialize` has not been called (or `C_Finalize` was called).
pub struct ModuleState {
    pub device: std::sync::Arc<Mutex<OnlyKeyDevice>>,
    pub objects: ObjectTable,
    pub sessions: SessionTable,
    pub firmware_version: String,
    /// Key-derived pseudo-serial from the device, for use in CK_TOKEN_INFO.serialNumber.
    pub pseudo_serial: [u8; 4],
}

/// The singleton module state.
static MODULE: OnceLock<Mutex<Option<ModuleState>>> = OnceLock::new();

/// Get a reference to the module lock, initializing the OnceLock if needed.
pub fn module_lock() -> &'static Mutex<Option<ModuleState>> {
    MODULE.get_or_init(|| Mutex::new(None))
}

// --- Static function tables --------------------------------------------------

/// The PKCS#11 3.2 function table.
static FUNCTION_LIST_3_2: CK_FUNCTION_LIST_3_2 = ffi::FUNCTION_LIST_3_2;

/// The base PKCS#11 3.x function table (same functions, different struct type).
///
/// `C_GetFunctionList` returns a `CK_FUNCTION_LIST` (the 2.x base struct).
/// We populate it from the 3.2 table by copying matching function pointers.
static FUNCTION_LIST_BASE: CK_FUNCTION_LIST = ffi::FUNCTION_LIST_BASE;

// --- Exported entry points ---------------------------------------------------

/// `C_GetFunctionList` -- the primary PKCS#11 entry point.
///
/// Sets `*ppFunctionList` to the static base function table and returns
/// `CKR_OK`. This is the only entry point defined by the 2.x spec and is
/// the first function a caller will invoke.
///
/// # Safety
/// `ppFunctionList` must be a valid non-null pointer to a
/// `*mut CK_FUNCTION_LIST`.
#[no_mangle]
pub unsafe extern "C" fn C_GetFunctionList(ppFunctionList: *mut *mut CK_FUNCTION_LIST) -> CK_RV {
    error::catch_panic(|| {
        if ppFunctionList.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // SAFETY: checked non-null above; caller guarantees valid pointer.
        // The cast to *mut is safe: PKCS#11 callers are required to treat the
        // returned pointer as read-only (the standard uses non-const C pointers).
        unsafe {
            *ppFunctionList =
                &FUNCTION_LIST_BASE as *const CK_FUNCTION_LIST as *mut CK_FUNCTION_LIST
        };
        CKR_OK
    })
}

/// `C_GetInterface` -- PKCS#11 3.0+ entry point for interface negotiation.
///
/// Returns the 3.2 interface when version {3,2} or {0,0} is requested;
/// falls back to the base 3.x interface for other versions.
///
/// # Safety
/// All pointer arguments must be valid for the duration of the call.
// Wrapper to make CK_INTERFACE Sync for use in static items.
// CK_INTERFACE contains *mut raw pointers that point to compile-time constant
// data (string literals and function tables) that are never mutated.
struct SyncInterface(CK_INTERFACE);
// SAFETY: the raw pointers in these instances point to static data that is
// never mutated; sharing them across threads is sound.
unsafe impl Sync for SyncInterface {}

static IFACE_3_2: SyncInterface = SyncInterface(CK_INTERFACE {
    pInterfaceName: b"PKCS 11\0".as_ptr() as *mut u8,
    pFunctionList: &FUNCTION_LIST_3_2 as *const CK_FUNCTION_LIST_3_2 as *mut std::ffi::c_void,
    flags: 0,
});
static IFACE_BASE: SyncInterface = SyncInterface(CK_INTERFACE {
    pInterfaceName: b"PKCS 11\0".as_ptr() as *mut u8,
    pFunctionList: &FUNCTION_LIST_BASE as *const CK_FUNCTION_LIST as *mut std::ffi::c_void,
    flags: 0,
});

/// `C_GetInterface` -- PKCS#11 3.0+ entry point for interface negotiation.
///
/// Returns the 3.2 interface when version {3,2} or {0,0} is requested;
/// falls back to the base 3.x interface for other versions.
///
/// # Safety
/// All pointer arguments must be valid for the duration of the call per the
/// PKCS#11 specification.
#[no_mangle]
pub unsafe extern "C" fn C_GetInterface(
    pInterfaceName: *mut u8,
    pVersion: *mut CK_VERSION,
    ppInterface: *mut *mut CK_INTERFACE,
    flags: cryptoki_sys::CK_FLAGS,
) -> CK_RV {
    use std::ffi::CStr;
    error::catch_panic(|| {
        if ppInterface.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let _ = flags; // flags reserved, currently 0

        // Validate interface name if provided (must be "PKCS 11").
        if !pInterfaceName.is_null() {
            // SAFETY: caller guarantees null-terminated string.
            let name = unsafe { CStr::from_ptr(pInterfaceName as *const std::ffi::c_char) };
            if name.to_bytes() != b"PKCS 11" {
                return CKR_FUNCTION_NOT_SUPPORTED;
            }
        }

        // Determine requested version.
        let (major, minor) = if pVersion.is_null() {
            (0, 0)
        } else {
            // SAFETY: caller guarantees valid pointer.
            let v = unsafe { &*pVersion };
            (v.major, v.minor)
        };

        let iface: &'static CK_INTERFACE = match (major, minor) {
            (3, 2) | (0, 0) => &IFACE_3_2.0,
            _ => &IFACE_BASE.0,
        };

        // SAFETY: ppInterface is non-null (checked above). The cast to *mut is
        // safe: callers must treat the returned pointer as read-only.
        unsafe { *ppInterface = iface as *const CK_INTERFACE as *mut CK_INTERFACE };
        CKR_OK
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr;

    #[test]
    fn c_get_function_list_null_arg() {
        let rv = unsafe { C_GetFunctionList(ptr::null_mut()) };
        assert_eq!(rv, CKR_ARGUMENTS_BAD);
    }

    #[test]
    fn c_get_function_list_ok() {
        let mut p: *mut CK_FUNCTION_LIST = std::ptr::null_mut();
        let rv = unsafe { C_GetFunctionList(&mut p) };
        assert_eq!(rv, CKR_OK);
        assert!(!p.is_null());
    }
}
