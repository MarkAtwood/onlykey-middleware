//! Implementation of all PKCS#11 C_* functions.
//!
//! All functions are wrapped in `error::catch_panic` to prevent Rust panics
//! from crossing the FFI boundary.
//!
//! Locking discipline:
//! - Module state lock (`module_lock()`) is acquired for session/object lookups.
//! - Device lock (`state.device`) is acquired separately and NEVER while holding
//!   the module lock, to prevent deadlock with async background threads.

#![allow(non_snake_case)]
// All pub unsafe extern "C" functions in this module are PKCS#11 C API entry
// points. Their safety invariant is uniform: all pointer arguments must be
// valid for the duration of the call, per the PKCS#11 specification. Adding
// individual `# Safety` doc sections to 29+ functions would be pure boilerplate.
#![allow(clippy::missing_safety_doc)]

use std::ffi::c_void;
use std::sync::{Arc, Mutex};

use zeroize::Zeroizing;

use cryptoki_sys::{
    CKF_SERIAL_SESSION, CKM_ECDH1_DERIVE, CKR_ARGUMENTS_BAD, CKR_CRYPTOKI_ALREADY_INITIALIZED,
    CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DATA_LEN_RANGE, CKR_DEVICE_REMOVED, CKR_FUNCTION_REJECTED,
    CKR_GENERAL_ERROR, CKR_KEY_HANDLE_INVALID, CKR_KEY_TYPE_INCONSISTENT, CKR_MECHANISM_INVALID,
    CKR_MECHANISM_PARAM_INVALID, CKR_OK, CKR_OPERATION_ACTIVE, CKR_OPERATION_NOT_INITIALIZED,
    CKR_SESSION_HANDLE_INVALID, CKR_SLOT_ID_INVALID, CKR_USER_ALREADY_LOGGED_IN,
    CKR_USER_NOT_LOGGED_IN, CK_ECDH1_DERIVE_PARAMS, CK_FLAGS, CK_FUNCTION_LIST,
    CK_MECHANISM_PTR, CK_NOTIFY, CK_OBJECT_HANDLE, CK_RV, CK_SESSION_HANDLE, CK_SLOT_ID,
    CK_ULONG, CK_VERSION, CKO_PRIVATE_KEY,
};

use onlykey_transport::{
    DecryptOp, Decrypted, DeviceState, EccAlgorithm, KeySlot, OnlyKeyDevice, SignOp, TransportError,
};
use wolfcrypt::digest::digest_trait::Digest;
use wolfcrypt::digest::{Sha256, Sha384, Sha512};

use crate::ck32::{CKR_PENDING, CK_ASYNC_DATA, CK_FUNCTION_LIST_3_2};
use crate::config::SlotConfig;
use crate::error::{catch_panic, transport_to_ckr};
use crate::mechanism::{
    check_mechanism_key_compat, mechanism_info, resolve_sign_mechanism, SignMechanism, MECHANISMS,
};
use crate::object::{KeyObject, ObjectTable, SecretKeyObject, SlotAlgorithm};
use crate::session::{AsyncResult, PendingOp, SessionTable};
use crate::token::{slot_info, token_info};
use crate::{module_lock, ModuleState};

/// The single PKCS#11 slot ID exposed by this module.
const SLOT_ID: CK_SLOT_ID = 0;

// --- C_Initialize / C_Finalize ------------------------------------------------

pub unsafe extern "C" fn C_Initialize(_pInitArgs: *mut c_void) -> CK_RV {
    catch_panic(|| {
        let mut guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
        if guard.is_some() {
            return CKR_CRYPTOKI_ALREADY_INITIALIZED;
        }

        let config = onlykey_transport::Config::load().unwrap_or_default();

        let device = match OnlyKeyDevice::open(config) {
            Ok(d) => d,
            // Use transport_to_ckr so a locked/uninitialized device returns
            // CKR_USER_NOT_LOGGED_IN rather than CKR_DEVICE_REMOVED. The blanket
            // CKR_DEVICE_REMOVED was misleading: callers interpreted it as a
            // physically disconnected device and prompted "reconnect" rather than
            // "unlock your device". Issue OnlyKey-vob.
            Err(ref e) => return transport_to_ckr(e),
        };

        let firmware_version = device.firmware_version.clone();
        let pseudo_serial = device.pseudo_serial;
        let device = Arc::new(Mutex::new(device));

        // SlotConfig::load() returns Ok(empty) when slots.toml is absent (expected
        // for first-time users). It returns Err only when the file exists but
        // cannot be read or parsed -- that warrants a diagnostic so the user can
        // tell why no keys are showing up.
        let slot_config = SlotConfig::load().unwrap_or_else(|e| {
            eprintln!("onlykey-pkcs11: warning: failed to load slot configuration: {e}");
            eprintln!(
                "onlykey-pkcs11: no keys will be exposed; check ~/.config/onlykey/slots.toml"
            );
            SlotConfig::default()
        });
        let mut objects = ObjectTable::new();
        // Design decision (OnlyKey-qoo): slot query failures during initialization
        // are non-fatal. The token is still usable with the keys that did load
        // successfully. Failing C_Initialize on any slot error would make the entire
        // token unavailable due to a transient USB glitch or a slot the user simply
        // hasn't configured. The trade-off: an undetected firmware error on one slot
        // silently reduces the available key set. Callers can detect missing keys by
        // comparing C_FindObjects results against their expected slot configuration.
        enumerate_objects(&device, &slot_config, &mut objects);

        *guard = Some(ModuleState {
            device,
            objects,
            sessions: SessionTable::new(),
            firmware_version,
            pseudo_serial,
        });

        CKR_OK
    })
}

pub unsafe extern "C" fn C_Finalize(_pReserved: *mut c_void) -> CK_RV {
    catch_panic(|| {
        let mut guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
        if guard.is_none() {
            return CKR_CRYPTOKI_NOT_INITIALIZED;
        }
        *guard = None;
        CKR_OK
    })
}

// --- C_GetInfo ----------------------------------------------------------------

pub unsafe extern "C" fn C_GetInfo(pInfo: *mut cryptoki_sys::CK_INFO) -> CK_RV {
    catch_panic(|| {
        if pInfo.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mut info = cryptoki_sys::CK_INFO {
            cryptokiVersion: CK_VERSION { major: 3, minor: 2 },
            manufacturerID: [b' '; 32],
            flags: 0,
            libraryDescription: [b' '; 32],
            libraryVersion: CK_VERSION { major: 0, minor: 1 },
        };
        for (d, s) in info.manufacturerID.iter_mut().zip(b"CryptoTrust".iter()) {
            *d = *s;
        }
        for (d, s) in info
            .libraryDescription
            .iter_mut()
            .zip(b"OnlyKey PKCS#11".iter())
        {
            *d = *s;
        }
        unsafe { *pInfo = info };
        CKR_OK
    })
}

// --- Slot / Token info --------------------------------------------------------

pub unsafe extern "C" fn C_GetSlotList(
    _tokenPresent: cryptoki_sys::CK_BBOOL,
    pSlotList: *mut CK_SLOT_ID,
    pulCount: *mut CK_ULONG,
) -> CK_RV {
    catch_panic(|| {
        if pulCount.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if pSlotList.is_null() {
            unsafe { *pulCount = 1 };
            return CKR_OK;
        }
        if unsafe { *pulCount } < 1 {
            // PKCS#11 3.2 sec.11.5: write required count before returning CKR_BUFFER_TOO_SMALL
            // so callers using the two-call sizing pattern can allocate the right buffer.
            unsafe { *pulCount = 1 };
            return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
        }
        unsafe {
            *pSlotList = SLOT_ID;
            *pulCount = 1;
        }
        CKR_OK
    })
}

pub unsafe extern "C" fn C_GetSlotInfo(
    slotID: CK_SLOT_ID,
    pInfo: *mut cryptoki_sys::CK_SLOT_INFO,
) -> CK_RV {
    catch_panic(|| {
        if slotID != SLOT_ID {
            return CKR_SLOT_ID_INVALID;
        }
        if pInfo.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        unsafe { *pInfo = slot_info() };
        CKR_OK
    })
}

pub unsafe extern "C" fn C_GetTokenInfo(
    slotID: CK_SLOT_ID,
    pInfo: *mut cryptoki_sys::CK_TOKEN_INFO,
) -> CK_RV {
    catch_panic(|| {
        if slotID != SLOT_ID {
            return CKR_SLOT_ID_INVALID;
        }
        if pInfo.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
        let state = match guard.as_ref() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        };
        unsafe { *pInfo = token_info(&state.firmware_version, state.pseudo_serial, true) };
        CKR_OK
    })
}

// --- Mechanism list -----------------------------------------------------------

pub unsafe extern "C" fn C_GetMechanismList(
    slotID: CK_SLOT_ID,
    pMechanismList: *mut cryptoki_sys::CK_MECHANISM_TYPE,
    pulCount: *mut CK_ULONG,
) -> CK_RV {
    catch_panic(|| {
        if slotID != SLOT_ID {
            return CKR_SLOT_ID_INVALID;
        }
        if pulCount.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let count = MECHANISMS.len() as CK_ULONG;
        if pMechanismList.is_null() {
            unsafe { *pulCount = count };
            return CKR_OK;
        }
        if unsafe { *pulCount } < count {
            // PKCS#11 3.2 sec.11.6: write required count before returning CKR_BUFFER_TOO_SMALL.
            unsafe { *pulCount = count };
            return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
        }
        for (i, &m) in MECHANISMS.iter().enumerate() {
            unsafe { *pMechanismList.add(i) = m };
        }
        unsafe { *pulCount = count };
        CKR_OK
    })
}

pub unsafe extern "C" fn C_GetMechanismInfo(
    slotID: CK_SLOT_ID,
    mech_type: cryptoki_sys::CK_MECHANISM_TYPE,
    pInfo: *mut cryptoki_sys::CK_MECHANISM_INFO,
) -> CK_RV {
    catch_panic(|| {
        if slotID != SLOT_ID {
            return CKR_SLOT_ID_INVALID;
        }
        if pInfo.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        match mechanism_info(mech_type) {
            Some(info) => {
                unsafe { *pInfo = info };
                CKR_OK
            }
            None => CKR_MECHANISM_INVALID,
        }
    })
}

// --- Session management -------------------------------------------------------

pub unsafe extern "C" fn C_OpenSession(
    slotID: CK_SLOT_ID,
    flags: CK_FLAGS,
    _pApplication: *mut c_void,
    _Notify: CK_NOTIFY,
    phSession: *mut CK_SESSION_HANDLE,
) -> CK_RV {
    catch_panic(|| {
        if slotID != SLOT_ID {
            return CKR_SLOT_ID_INVALID;
        }
        if phSession.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if flags & CKF_SERIAL_SESSION == 0 {
            return CKR_ARGUMENTS_BAD;
        }
        let mut guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        };
        // Cap at 1024 sessions to prevent resource exhaustion (issue OnlyKey-eqa).
        // PKCS#11 does not mandate a maximum, but an unbounded table is a DoS
        // vector for callers that leak session handles.
        const MAX_SESSIONS: usize = 1024;
        if state.sessions.len() >= MAX_SESSIONS {
            return cryptoki_sys::CKR_SESSION_COUNT;
        }
        let handle = state.sessions.open(flags);
        unsafe { *phSession = handle };
        CKR_OK
    })
}

pub unsafe extern "C" fn C_CloseSession(hSession: CK_SESSION_HANDLE) -> CK_RV {
    catch_panic(|| {
        let mut guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        };
        if state.sessions.close(hSession) {
            state.objects.remove_session_objects(hSession);
            CKR_OK
        } else {
            CKR_SESSION_HANDLE_INVALID
        }
    })
}

pub unsafe extern "C" fn C_CloseAllSessions(slotID: CK_SLOT_ID) -> CK_RV {
    catch_panic(|| {
        if slotID != SLOT_ID {
            return CKR_SLOT_ID_INVALID;
        }
        let mut guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        };
        state.objects.clear_secrets();
        state.sessions.close_all();
        CKR_OK
    })
}

pub unsafe extern "C" fn C_GetSessionInfo(
    hSession: CK_SESSION_HANDLE,
    pInfo: *mut cryptoki_sys::CK_SESSION_INFO,
) -> CK_RV {
    catch_panic(|| {
        if pInfo.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
        let state = match guard.as_ref() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        };
        match state.sessions.get(hSession) {
            None => CKR_SESSION_HANDLE_INVALID,
            Some(s) => {
                unsafe {
                    *pInfo = cryptoki_sys::CK_SESSION_INFO {
                        slotID: SLOT_ID,
                        state: s.state(),
                        flags: s.flags,
                        ulDeviceError: 0,
                    };
                }
                CKR_OK
            }
        }
    })
}

// --- Login / Logout -----------------------------------------------------------

pub unsafe extern "C" fn C_Login(
    hSession: CK_SESSION_HANDLE,
    _userType: CK_ULONG,
    pPin: *mut u8,
    ulPinLen: CK_ULONG,
) -> CK_RV {
    catch_panic(|| {
        if !pPin.is_null() && ulPinLen > 0 {
            return CKR_ARGUMENTS_BAD;
        }

        // Extract the device Arc while holding the module lock.
        let device_arc = {
            let guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
            let state = match guard.as_ref() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED,
            };
            if state.sessions.get(hSession).is_none() {
                return CKR_SESSION_HANDLE_INVALID;
            }
            Arc::clone(&state.device)
        };

        // Check device state without holding module lock.
        let dev = device_arc.lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
        match dev.get_device_state() {
            Ok(DeviceState::Unlocked(_)) => CKR_USER_ALREADY_LOGGED_IN,
            Ok(DeviceState::Locked) => cryptoki_sys::CKR_PIN_INCORRECT,
            Ok(DeviceState::Uninitialized) => CKR_USER_NOT_LOGGED_IN,
            Err(TransportError::Disconnected) | Err(TransportError::NotFound) => CKR_DEVICE_REMOVED,
            Err(_) => CKR_GENERAL_ERROR,
        }
    })
}

pub unsafe extern "C" fn C_Logout(hSession: CK_SESSION_HANDLE) -> CK_RV {
    catch_panic(|| {
        let guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
        let state = match guard.as_ref() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        };
        if state.sessions.get(hSession).is_none() {
            return CKR_SESSION_HANDLE_INVALID;
        }
        CKR_OK
    })
}

// --- Object enumeration -------------------------------------------------------

pub unsafe extern "C" fn C_FindObjectsInit(
    hSession: CK_SESSION_HANDLE,
    pTemplate: *mut cryptoki_sys::CK_ATTRIBUTE,
    ulCount: CK_ULONG,
) -> CK_RV {
    catch_panic(|| {
        const MAX_TEMPLATE_ATTRS: CK_ULONG = 64;
        if ulCount > MAX_TEMPLATE_ATTRS {
            return CKR_ARGUMENTS_BAD;
        }
        // Parse template before acquiring the lock.
        let filters = if pTemplate.is_null() || ulCount == 0 {
            vec![]
        } else {
            let mut f = Vec::with_capacity(ulCount as usize);
            for i in 0..ulCount as usize {
                let attr = unsafe { &*pTemplate.add(i) };
                if attr.pValue.is_null() || attr.ulValueLen == 0 {
                    continue;
                }
                let val = unsafe {
                    std::slice::from_raw_parts(attr.pValue as *const u8, attr.ulValueLen as usize)
                }
                .to_vec();
                f.push((attr.type_, val));
            }
            f
        };

        let mut guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        };
        match state.sessions.get_mut(hSession) {
            None => CKR_SESSION_HANDLE_INVALID,
            Some(s) => {
                // PKCS#11 3.2 sec.11.7: C_FindObjectsInit returns CKR_OPERATION_ACTIVE
                // if *any* cryptographic operation (sign, digest, decrypt) is active on
                // the session. The previous guard checked only SignReady; DigestReady
                // and DecryptReady also count. Issue OnlyKey-wua.
                if !matches!(s.pending, PendingOp::None) {
                    return CKR_OPERATION_ACTIVE;
                }
                // A non-empty find_results means C_FindObjectsInit was called
                // again before C_FindObjectsFinal. Per PKCS#11 sec.11.7, starting
                // a new find without finalizing the previous one is an active
                // operation. Issue OnlyKey-ghb.
                if !s.find_results.is_empty() {
                    return CKR_OPERATION_ACTIVE;
                }
                // Pass hSession so find() filters derived secrets by owning
                // session — session B must not see objects created by session A.
                // PKCS#11 spec sec.10.1. Issue OnlyKey-lij.
                s.find_results = state.objects.find(&filters, hSession);
                CKR_OK
            }
        }
    })
}

pub unsafe extern "C" fn C_FindObjects(
    hSession: CK_SESSION_HANDLE,
    phObject: *mut CK_OBJECT_HANDLE,
    ulMaxObjectCount: CK_ULONG,
    pulObjectCount: *mut CK_ULONG,
) -> CK_RV {
    catch_panic(|| {
        if phObject.is_null() || pulObjectCount.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        const MAX_OBJECTS_PER_CALL: CK_ULONG = 64;
        let effective_max = ulMaxObjectCount.min(MAX_OBJECTS_PER_CALL);
        let mut guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        };
        match state.sessions.get_mut(hSession) {
            None => CKR_SESSION_HANDLE_INVALID,
            Some(s) => {
                let n = s.find_results.len().min(effective_max as usize);
                for i in 0..n {
                    unsafe { *phObject.add(i) = s.find_results[i] };
                }
                s.find_results.drain(..n);
                unsafe { *pulObjectCount = n as CK_ULONG };
                CKR_OK
            }
        }
    })
}

pub unsafe extern "C" fn C_FindObjectsFinal(hSession: CK_SESSION_HANDLE) -> CK_RV {
    catch_panic(|| {
        let mut guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        };
        match state.sessions.get_mut(hSession) {
            None => CKR_SESSION_HANDLE_INVALID,
            Some(s) => {
                s.find_results.clear();
                CKR_OK
            }
        }
    })
}

// --- C_GetAttributeValue ------------------------------------------------------

pub unsafe extern "C" fn C_GetAttributeValue(
    hSession: CK_SESSION_HANDLE,
    hObject: CK_OBJECT_HANDLE,
    pTemplate: *mut cryptoki_sys::CK_ATTRIBUTE,
    ulCount: CK_ULONG,
) -> CK_RV {
    catch_panic(|| {
        if pTemplate.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // Safety: cap ulCount before using it to index into the caller-supplied
        // pTemplate array. A C caller passing u64::MAX would cause unbounded
        // pointer arithmetic through pTemplate.add(i). The same cap is applied
        // in C_FindObjectsInit; keep them in sync. Issue OnlyKey-6f7.
        const MAX_TEMPLATE_ATTRS: CK_ULONG = 64;
        if ulCount > MAX_TEMPLATE_ATTRS {
            return CKR_ARGUMENTS_BAD;
        }
        let guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
        let state = match guard.as_ref() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        };
        if state.sessions.get(hSession).is_none() {
            return CKR_SESSION_HANDLE_INVALID;
        }
        // Look up the object -- may be a key or a transient secret.
        enum ObjRef<'a> {
            Key(&'a KeyObject),
            Secret(&'a SecretKeyObject),
        }
        let obj = match state.objects.get(hObject) {
            Some(o) => ObjRef::Key(o),
            // get_secret enforces session ownership: a handle from a different
            // session returns None here, producing CKR_KEY_HANDLE_INVALID per
            // PKCS#11 spec sec.10.1. Issue OnlyKey-lij.
            None => match state.objects.get_secret(hObject, hSession) {
                Some(s) => ObjRef::Secret(s),
                None => return CKR_KEY_HANDLE_INVALID,
            },
        };

        let attr_fn = |t| match &obj {
            ObjRef::Key(o) => o.attribute(t),
            ObjRef::Secret(s) => s.attribute(t),
        };

        let mut rv = CKR_OK;
        for i in 0..ulCount as usize {
            let attr = unsafe { &mut *pTemplate.add(i) };
            match attr_fn(attr.type_) {
                None => {
                    attr.ulValueLen = CK_ULONG::MAX;
                    rv = cryptoki_sys::CKR_ATTRIBUTE_TYPE_INVALID;
                }
                Some(val) => {
                    if attr.pValue.is_null() {
                        attr.ulValueLen = val.len() as CK_ULONG;
                    } else if attr.ulValueLen < val.len() as CK_ULONG {
                        attr.ulValueLen = val.len() as CK_ULONG;
                        rv = cryptoki_sys::CKR_BUFFER_TOO_SMALL;
                    } else {
                        unsafe {
                            std::ptr::copy_nonoverlapping(
                                val.as_ptr(),
                                attr.pValue as *mut u8,
                                val.len(),
                            );
                        }
                        attr.ulValueLen = val.len() as CK_ULONG;
                    }
                }
            }
        }
        rv
    })
}

// --- Signing ------------------------------------------------------------------

pub unsafe extern "C" fn C_SignInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_panic(|| {
        if pMechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mech_type = unsafe { (*pMechanism).mechanism };
        let mechanism = match resolve_sign_mechanism(mech_type) {
            Some(m) => m,
            None => return CKR_MECHANISM_INVALID,
        };
        // None of the signing mechanisms this token supports take parameters.
        // A non-zero ulParameterLen means the caller is passing mechanism params
        // to a mechanism that doesn't use them — reject per PKCS#11 sec.11.11.
        // Issue OnlyKey-2j3.
        if unsafe { (*pMechanism).ulParameterLen } != 0 {
            return CKR_MECHANISM_PARAM_INVALID;
        }

        let mut guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        };

        let session = match state.sessions.get_mut(hSession) {
            Some(s) => s,
            None => return CKR_SESSION_HANDLE_INVALID,
        };
        if !matches!(session.pending, PendingOp::None) {
            return CKR_OPERATION_ACTIVE;
        }
        let alg = match state.objects.get(hKey) {
            Some(o) => o.algorithm,
            None => return CKR_KEY_HANDLE_INVALID,
        };
        if !check_mechanism_key_compat(mechanism, alg) {
            return CKR_KEY_TYPE_INCONSISTENT;
        }

        if let Some(s) = state.sessions.get_mut(hSession) {
            s.pending = PendingOp::SignReady {
                key_handle: hKey,
                mechanism,
                accumulator: Zeroizing::new(Vec::new()),
            };
        }
        CKR_OK
    })
}

pub unsafe extern "C" fn C_Sign(
    hSession: CK_SESSION_HANDLE,
    pData: *mut u8,
    ulDataLen: CK_ULONG,
    pSignature: *mut u8,
    pulSignatureLen: *mut CK_ULONG,
) -> CK_RV {
    catch_panic(|| {
        if pData.is_null() || pulSignatureLen.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        if !pSignature.is_null() && pulSignatureLen.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let extra = unsafe { std::slice::from_raw_parts(pData as *const u8, ulDataLen as usize) };

        // Extract pending op and device Arc under the module lock.
        let (key_slot, algorithm, mechanism, payload, session_type, device_arc, timeout) = {
            let mut guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED,
            };

            let (key_handle, mechanism, mut acc) = match state.sessions.get_mut(hSession) {
                Some(s) => match std::mem::replace(&mut s.pending, PendingOp::None) {
                    PendingOp::SignReady {
                        key_handle,
                        mechanism,
                        accumulator,
                    } => (key_handle, mechanism, accumulator),
                    other => {
                        s.pending = other;
                        return CKR_OPERATION_NOT_INITIALIZED;
                    }
                },
                None => return CKR_SESSION_HANDLE_INVALID,
            };
            acc.extend_from_slice(extra);

            let obj = match state.objects.get(key_handle) {
                Some(o) => o,
                None => return CKR_KEY_HANDLE_INVALID,
            };

            let session_type = match state.sessions.get(hSession) {
                Some(s) => s.session_type,
                None => return CKR_SESSION_HANDLE_INVALID,
            };

            let payload = match apply_prehash(mechanism, &acc) {
                Ok(p) => p,
                Err(rv) => return rv,
            };

            // Firmware accepts at most 768 bytes per frame sequence (onlykey_hid::MAX_PAYLOAD).
            // For prehashed mechanisms the payload is a digest (<= 64 bytes) so this never
            // triggers there. For CKM_EDDSA (raw message), messages > 768 bytes are rejected
            // here rather than at the transport layer so we return CKR_DATA_LEN_RANGE instead
            // of a generic CKR_DEVICE_ERROR.
            // Previously a 512-byte hard limit was applied before accumulation/prehash, which
            // incorrectly rejected valid 600-byte Ed25519 messages. Issue OnlyKey-l9h.
            if payload.len() > 768 {
                return CKR_DATA_LEN_RANGE;
            }

            let timeout = state
                .device
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .config
                .challenge_timeout;

            (
                obj.slot,
                obj.algorithm,
                mechanism,
                payload,
                session_type,
                Arc::clone(&state.device),
                timeout,
            )
        };

        use crate::session::SessionType;

        // HMAC path: route to dev.hmac() instead of dev.sign().
        // No SignOp, no challenge code displayed, no button press required.
        if algorithm == SlotAlgorithm::HmacSha1 {
            let hmac_payload = payload.to_vec();

            if session_type == SessionType::Async {
                let thread = std::thread::spawn(move || {
                    let dev = device_arc.lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
                    match dev.hmac(key_slot, &hmac_payload) {
                        Ok(mac) => AsyncResult::Bytes(mac),
                        Err(TransportError::ChallengeTimeout) => AsyncResult::Rejected,
                        Err(e) => AsyncResult::DeviceError(e.to_string()),
                    }
                });
                let mut guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
                if let Some(state) = guard.as_mut() {
                    if let Some(session) = state.sessions.get_mut(hSession) {
                        let id = session.next_async_id();
                        session.pending = PendingOp::Async { id, thread };
                    }
                }
                return CKR_PENDING;
            }

            let mac_bytes = {
                let dev = device_arc.lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
                match dev.hmac(key_slot, &hmac_payload) {
                    Ok(mac) => mac,
                    Err(TransportError::ChallengeTimeout) => return CKR_FUNCTION_REJECTED,
                    Err(e) => return transport_to_ckr(&e),
                }
            };
            if pSignature.is_null() {
                unsafe { *pulSignatureLen = mac_bytes.len() as CK_ULONG };
                return CKR_OK;
            }
            if unsafe { *pulSignatureLen } < mac_bytes.len() as CK_ULONG {
                unsafe { *pulSignatureLen = mac_bytes.len() as CK_ULONG };
                return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
            }
            unsafe {
                std::ptr::copy_nonoverlapping(mac_bytes.as_ptr(), pSignature, mac_bytes.len());
                *pulSignatureLen = mac_bytes.len() as CK_ULONG;
            }
            return CKR_OK;
        }

        // Non-HMAC path: build a SignOp and call dev.sign().
        // Clone inner Vec<u8> for SignOp; the Zeroizing<Vec<u8>> is dropped (zeroized) at end
        // of this function after the device operation completes.
        let sign_op = match make_sign_op_from_slot(key_slot, algorithm, mechanism, payload.to_vec())
        {
            Ok(op) => op,
            Err(rv) => return rv,
        };

        if session_type == SessionType::Async {
            let thread = std::thread::spawn(move || {
                let dev = device_arc.lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
                let display = onlykey_transport::challenge_ui::StderrDisplay;
                match dev.sign(sign_op, &display, timeout) {
                    Ok(sig) => AsyncResult::Bytes(sig_to_bytes(sig)),
                    Err(TransportError::ChallengeTimeout) => AsyncResult::Rejected,
                    Err(e) => AsyncResult::DeviceError(e.to_string()),
                }
            });

            let mut guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
            if let Some(state) = guard.as_mut() {
                if let Some(session) = state.sessions.get_mut(hSession) {
                    let id = session.next_async_id();
                    session.pending = PendingOp::Async { id, thread };
                }
            }
            return CKR_PENDING;
        }

        // Sync path.
        let sig_bytes = {
            let dev = device_arc.lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
            let display = onlykey_transport::challenge_ui::StderrDisplay;
            match dev.sign(sign_op, &display, timeout) {
                Ok(sig) => sig_to_bytes(sig),
                Err(TransportError::ChallengeTimeout) => return CKR_FUNCTION_REJECTED,
                Err(e) => return transport_to_ckr(&e),
            }
        };

        if pSignature.is_null() {
            unsafe { *pulSignatureLen = sig_bytes.len() as CK_ULONG };
            return CKR_OK;
        }
        if unsafe { *pulSignatureLen } < sig_bytes.len() as CK_ULONG {
            unsafe { *pulSignatureLen = sig_bytes.len() as CK_ULONG };
            return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(sig_bytes.as_ptr(), pSignature, sig_bytes.len());
            *pulSignatureLen = sig_bytes.len() as CK_ULONG;
        }
        CKR_OK
    })
}

pub unsafe extern "C" fn C_SignUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: *mut u8,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    catch_panic(|| {
        // PKCS#11 sec.5.2: NULL pPart is allowed only when ulPartLen == 0 (no-op update).
        if pPart.is_null() && ulPartLen > 0 {
            return CKR_ARGUMENTS_BAD;
        }
        let part: &[u8] = if pPart.is_null() {
            // zero-length update: accumulate nothing and return OK
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(pPart as *const u8, ulPartLen as usize) }
        };
        let mut guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        };
        match state.sessions.get_mut(hSession) {
            None => CKR_SESSION_HANDLE_INVALID,
            Some(s) => match &mut s.pending {
                PendingOp::SignReady { accumulator, .. } => {
                    accumulator.extend_from_slice(part);
                    CKR_OK
                }
                _ => CKR_OPERATION_NOT_INITIALIZED,
            },
        }
    })
}

pub unsafe extern "C" fn C_SignFinal(
    hSession: CK_SESSION_HANDLE,
    pSignature: *mut u8,
    pulSignatureLen: *mut CK_ULONG,
) -> CK_RV {
    catch_panic(|| {
        if pulSignatureLen.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // Route through C_Sign with empty extra data.
        // SAFETY: the empty slice is valid; cast to *mut is safe (C_Sign does not write through it).
        unsafe {
            C_Sign(
                hSession,
                [0u8; 0].as_ptr() as *mut u8,
                0,
                pSignature,
                pulSignatureLen,
            )
        }
    })
}

// --- Async operations ---------------------------------------------------------

pub unsafe extern "C" fn C_AsyncComplete(
    hSession: CK_SESSION_HANDLE,
    _pOperationId: *mut u8,
    pData: *mut CK_ASYNC_DATA,
) -> CK_RV {
    catch_panic(|| {
        // Check if the operation is complete. AsyncCompleted means C_AsyncJoin
        // already joined the thread and stored the result; Async means the thread
        // may still be running.
        let finished = {
            let guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
            let state = match guard.as_ref() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED,
            };
            let session = match state.sessions.get(hSession) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID,
            };
            match &session.pending {
                PendingOp::AsyncCompleted(_) => true,
                PendingOp::Async { thread, .. } => thread.is_finished(),
                _ => return CKR_OPERATION_NOT_INITIALIZED,
            }
        };

        if !finished {
            return CKR_PENDING;
        }

        // Extract and (if necessary) join the thread.
        let result = {
            let mut guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED,
            };
            let session = match state.sessions.get_mut(hSession) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID,
            };
            match std::mem::replace(&mut session.pending, PendingOp::None) {
                // Result was pre-joined by C_AsyncJoin; consume directly.
                PendingOp::AsyncCompleted(result) => result,
                PendingOp::Async { thread, .. } => thread
                    .join()
                    .unwrap_or(AsyncResult::DeviceError("panicked".into())),
                _ => return CKR_OPERATION_NOT_INITIALIZED,
            }
        };

        match result {
            AsyncResult::Rejected => CKR_FUNCTION_REJECTED,
            AsyncResult::DeviceError(_) => CKR_GENERAL_ERROR,
            AsyncResult::Bytes(bytes) => {
                if pData.is_null() {
                    return CKR_ARGUMENTS_BAD;
                }
                let d = unsafe { &mut *pData };
                if d.pValue.is_null() || d.ulValue < bytes.len() as CK_ULONG {
                    d.ulValue = bytes.len() as CK_ULONG;
                    return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
                }
                unsafe {
                    std::ptr::copy_nonoverlapping(bytes.as_ptr(), d.pValue, bytes.len());
                }
                d.ulValue = bytes.len() as CK_ULONG;
                CKR_OK
            }
        }
    })
}

pub unsafe extern "C" fn C_AsyncGetID(
    hSession: CK_SESSION_HANDLE,
    pOperationId: *mut u8,
    pulOperationIdLen: *mut CK_ULONG,
) -> CK_RV {
    catch_panic(|| {
        if pulOperationIdLen.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
        let state = match guard.as_ref() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        };
        let session = match state.sessions.get(hSession) {
            Some(s) => s,
            None => return CKR_SESSION_HANDLE_INVALID,
        };
        let id = match &session.pending {
            PendingOp::Async { id, .. } => *id,
            _ => return CKR_OPERATION_NOT_INITIALIZED,
        };
        let id_str = id.to_string();
        let id_bytes = id_str.as_bytes();
        if pOperationId.is_null() {
            unsafe { *pulOperationIdLen = id_bytes.len() as CK_ULONG };
            return CKR_OK;
        }
        if unsafe { *pulOperationIdLen } < id_bytes.len() as CK_ULONG {
            // PKCS#11 3.2 sec.5.9.1: write required length before returning CKR_BUFFER_TOO_SMALL.
            unsafe { *pulOperationIdLen = id_bytes.len() as CK_ULONG };
            return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(id_bytes.as_ptr(), pOperationId, id_bytes.len());
            *pulOperationIdLen = id_bytes.len() as CK_ULONG;
        }
        CKR_OK
    })
}

pub unsafe extern "C" fn C_AsyncJoin(
    hSession: CK_SESSION_HANDLE,
    _pOperationId: *mut u8,
    _ulOperationIdLen: CK_ULONG,
    _pData: *mut u8,
    _ulDataLen: CK_ULONG,
) -> CK_RV {
    catch_panic(|| {
        // Take the thread out of the session under the lock so we can join it
        // without holding the lock (allowing concurrent C_AsyncComplete polling).
        let thread = {
            let mut guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED,
            };
            let session = match state.sessions.get_mut(hSession) {
                Some(s) => s,
                None => return CKR_SESSION_HANDLE_INVALID,
            };
            match std::mem::replace(&mut session.pending, PendingOp::None) {
                PendingOp::Async { thread, .. } => thread,
                _ => return CKR_OPERATION_NOT_INITIALIZED,
            }
        };

        // Block until done with module lock released.
        let result = thread
            .join()
            .unwrap_or(AsyncResult::DeviceError("panicked".into()));

        // Store the result so C_AsyncComplete can retrieve it.
        // Previously (OnlyKey-89r) AsyncResult::Bytes was discarded here with CKR_OK,
        // leaving the caller unable to retrieve signature/decrypt bytes via C_AsyncComplete.
        {
            let mut guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
            if let Some(state) = guard.as_mut() {
                if let Some(session) = state.sessions.get_mut(hSession) {
                    session.pending = PendingOp::AsyncCompleted(result);
                    return CKR_OK;
                }
            }
        }
        // Session was closed while we were blocking -- result cannot be delivered.
        CKR_SESSION_HANDLE_INVALID
    })
}

// --- Digest -------------------------------------------------------------------

pub unsafe extern "C" fn C_DigestInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
) -> CK_RV {
    catch_panic(|| {
        if pMechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mech_type = unsafe { (*pMechanism).mechanism };
        if !matches!(
            mech_type,
            cryptoki_sys::CKM_SHA256 | cryptoki_sys::CKM_SHA384 | cryptoki_sys::CKM_SHA512
        ) {
            return CKR_MECHANISM_INVALID;
        }
        let mut guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        };
        match state.sessions.get_mut(hSession) {
            None => CKR_SESSION_HANDLE_INVALID,
            Some(s) => {
                if !matches!(s.pending, PendingOp::None) {
                    return CKR_OPERATION_ACTIVE;
                }
                s.pending = PendingOp::DigestReady {
                    mechanism: mech_type,
                    accumulator: Zeroizing::new(Vec::new()),
                };
                CKR_OK
            }
        }
    })
}

pub unsafe extern "C" fn C_DigestUpdate(
    hSession: CK_SESSION_HANDLE,
    pPart: *mut u8,
    ulPartLen: CK_ULONG,
) -> CK_RV {
    catch_panic(|| {
        // PKCS#11 sec.5.2: NULL pPart is allowed only when ulPartLen == 0 (no-op update).
        if pPart.is_null() && ulPartLen > 0 {
            return CKR_ARGUMENTS_BAD;
        }
        let part: &[u8] = if pPart.is_null() {
            // zero-length update: accumulate nothing and return OK
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(pPart as *const u8, ulPartLen as usize) }
        };
        let mut guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        };
        match state.sessions.get_mut(hSession) {
            None => CKR_SESSION_HANDLE_INVALID,
            Some(s) => match &mut s.pending {
                PendingOp::DigestReady { accumulator, .. } => {
                    accumulator.extend_from_slice(part);
                    CKR_OK
                }
                _ => CKR_OPERATION_NOT_INITIALIZED,
            },
        }
    })
}

pub unsafe extern "C" fn C_DigestFinal(
    hSession: CK_SESSION_HANDLE,
    pDigest: *mut u8,
    pulDigestLen: *mut CK_ULONG,
) -> CK_RV {
    catch_panic(|| {
        if pulDigestLen.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mut guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        };
        let session = match state.sessions.get_mut(hSession) {
            None => return CKR_SESSION_HANDLE_INVALID,
            Some(s) => s,
        };
        // Hash directly from the accumulator reference — no clone needed.
        // The hash is computed inside the match arm so the borrow on session.pending
        // ends before the later `session.pending = PendingOp::None` mutation.
        let hash: Vec<u8> = match &session.pending {
            PendingOp::DigestReady {
                mechanism,
                accumulator,
            } => match *mechanism {
                cryptoki_sys::CKM_SHA256 => Sha256::digest(accumulator.as_slice()).to_vec(),
                cryptoki_sys::CKM_SHA384 => Sha384::digest(accumulator.as_slice()).to_vec(),
                cryptoki_sys::CKM_SHA512 => Sha512::digest(accumulator.as_slice()).to_vec(),
                _ => return CKR_MECHANISM_INVALID,
            },
            _ => return CKR_OPERATION_NOT_INITIALIZED,
        };

        if pDigest.is_null() {
            unsafe { *pulDigestLen = hash.len() as CK_ULONG };
            return CKR_OK;
        }
        if unsafe { *pulDigestLen } < hash.len() as CK_ULONG {
            // PKCS#11 3.2 sec.11.10: write required length before returning CKR_BUFFER_TOO_SMALL.
            unsafe { *pulDigestLen = hash.len() as CK_ULONG };
            return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(hash.as_ptr(), pDigest, hash.len());
            *pulDigestLen = hash.len() as CK_ULONG;
        }
        session.pending = PendingOp::None;
        CKR_OK
    })
}

pub unsafe extern "C" fn C_Digest(
    hSession: CK_SESSION_HANDLE,
    pData: *mut u8,
    ulDataLen: CK_ULONG,
    pDigest: *mut u8,
    pulDigestLen: *mut CK_ULONG,
) -> CK_RV {
    catch_panic(|| {
        if pData.is_null() || pulDigestLen.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let data = unsafe { std::slice::from_raw_parts(pData as *const u8, ulDataLen as usize) };
        let mut guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        };
        let session = match state.sessions.get_mut(hSession) {
            None => return CKR_SESSION_HANDLE_INVALID,
            Some(s) => s,
        };
        let mechanism = match &session.pending {
            PendingOp::DigestReady {
                mechanism,
                accumulator,
            } if accumulator.is_empty() => *mechanism,
            PendingOp::DigestReady { .. } => return CKR_OPERATION_ACTIVE,
            _ => return CKR_OPERATION_NOT_INITIALIZED,
        };

        let hash: Vec<u8> = match mechanism {
            cryptoki_sys::CKM_SHA256 => Sha256::digest(data).to_vec(),
            cryptoki_sys::CKM_SHA384 => Sha384::digest(data).to_vec(),
            cryptoki_sys::CKM_SHA512 => Sha512::digest(data).to_vec(),
            _ => return CKR_MECHANISM_INVALID,
        };

        if pDigest.is_null() {
            // Size-query mode: return required length but do NOT clear pending.
            // PKCS#11 3.2 sec.11.10: when pDigest is NULL the operation remains
            // active so the caller can call C_Digest again with an adequate buffer.
            unsafe { *pulDigestLen = hash.len() as CK_ULONG };
            return CKR_OK;
        }
        if unsafe { *pulDigestLen } < hash.len() as CK_ULONG {
            // PKCS#11 3.2 sec.11.10: write required length and return BUFFER_TOO_SMALL.
            // The operation remains active (pending is NOT cleared) so the caller
            // can retry C_Digest with a larger buffer. Issue OnlyKey-nu4.
            unsafe { *pulDigestLen = hash.len() as CK_ULONG };
            return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
        }
        // Success path: copy the digest, then clear the pending operation.
        // pending = None is intentionally placed after all error returns above;
        // any error exit above leaves the operation active for retry.
        unsafe {
            std::ptr::copy_nonoverlapping(hash.as_ptr(), pDigest, hash.len());
            *pulDigestLen = hash.len() as CK_ULONG;
        }
        session.pending = PendingOp::None;
        CKR_OK
    })
}

// --- Decrypt ------------------------------------------------------------------

pub unsafe extern "C" fn C_DecryptInit(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hKey: CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_panic(|| {
        if pMechanism.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        let mech_type = unsafe { (*pMechanism).mechanism };
        if mech_type != cryptoki_sys::CKM_RSA_PKCS_OAEP {
            return CKR_MECHANISM_INVALID;
        }
        // CKM_RSA_PKCS_OAEP requires a CK_RSA_PKCS_OAEP_PARAMS block per
        // PKCS#11 sec.11.12. We forward the ciphertext to the device which
        // handles OAEP internally, but a null pParameter means the caller is
        // non-conformant; reject it so bugs surface early. Issue OnlyKey-2j3.
        if unsafe { (*pMechanism).pParameter.is_null() }
            || unsafe { (*pMechanism).ulParameterLen } == 0
        {
            return CKR_MECHANISM_PARAM_INVALID;
        }
        let mut guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        };
        // PKCS#11 spec requires *Init functions to validate key type and usage
        // upfront so callers don't have to wait until C_Decrypt to discover a
        // key type mismatch. C_DecryptInit only supports CKM_RSA_PKCS_OAEP
        // (already checked above), so the key must be a private RSA key.
        // Accepting any handle — including public keys or non-RSA keys — and
        // deferring rejection to C_Decrypt violates PKCS#11 sec.11.12 and
        // misleads callers that rely on DecryptInit for upfront validation.
        // Issue OnlyKey-4c3.
        match state.objects.get(hKey) {
            None => return CKR_KEY_HANDLE_INVALID,
            Some(obj) => {
                if obj.class != CKO_PRIVATE_KEY {
                    return CKR_KEY_TYPE_INCONSISTENT;
                }
                if !matches!(obj.algorithm, SlotAlgorithm::Rsa2048 | SlotAlgorithm::Rsa4096) {
                    return CKR_KEY_TYPE_INCONSISTENT;
                }
            }
        }
        match state.sessions.get_mut(hSession) {
            None => CKR_SESSION_HANDLE_INVALID,
            Some(s) => {
                if !matches!(s.pending, PendingOp::None) {
                    return CKR_OPERATION_ACTIVE;
                }
                s.pending = PendingOp::DecryptReady { key_handle: hKey };
                CKR_OK
            }
        }
    })
}

pub unsafe extern "C" fn C_Decrypt(
    hSession: CK_SESSION_HANDLE,
    pEncryptedData: *mut u8,
    ulEncryptedDataLen: CK_ULONG,
    pData: *mut u8,
    pulDataLen: *mut CK_ULONG,
) -> CK_RV {
    catch_panic(|| {
        if pEncryptedData.is_null() || pulDataLen.is_null() {
            return CKR_ARGUMENTS_BAD;
        }
        // C_Decrypt two-call pattern: pData=NULL means "return required output
        // length in *pulDataLen"; pData!=NULL means "decrypt into this buffer".
        // pulDataLen is always required (checked above). pEncryptedData is always
        // required. No further null-check needed here.
        // (A prior check `!pData.is_null() && pulDataLen.is_null()` was removed:
        // it was dead code — pulDataLen.is_null() is already false at this point.
        // Issue OnlyKey-2uo.)
        let ciphertext = unsafe {
            std::slice::from_raw_parts(pEncryptedData as *const u8, ulEncryptedDataLen as usize)
        }
        .to_vec();

        // Extract key slot and device Arc while holding the module lock.
        let (slot, session_type, device_arc, timeout) = {
            let mut guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
            let state = match guard.as_mut() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED,
            };

            let key_handle = match state.sessions.get_mut(hSession) {
                Some(s) => match std::mem::replace(&mut s.pending, PendingOp::None) {
                    PendingOp::DecryptReady { key_handle } => key_handle,
                    other => {
                        s.pending = other;
                        return CKR_OPERATION_NOT_INITIALIZED;
                    }
                },
                None => return CKR_SESSION_HANDLE_INVALID,
            };

            let obj = match state.objects.get(key_handle) {
                Some(o) => o,
                None => return CKR_KEY_HANDLE_INVALID,
            };
            if !matches!(
                obj.algorithm,
                SlotAlgorithm::Rsa2048 | SlotAlgorithm::Rsa4096
            ) {
                return CKR_KEY_TYPE_INCONSISTENT;
            }

            let session_type = match state.sessions.get(hSession) {
                Some(s) => s.session_type,
                None => return CKR_SESSION_HANDLE_INVALID,
            };
            let timeout = state
                .device
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .config
                .challenge_timeout;

            (obj.slot, session_type, Arc::clone(&state.device), timeout)
        };

        let decrypt_op = DecryptOp::Rsa { slot, ciphertext };

        use crate::session::SessionType;
        if session_type == SessionType::Async {
            let thread = std::thread::spawn(move || {
                let dev = device_arc.lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
                let display = onlykey_transport::challenge_ui::StderrDisplay;
                match dev.decrypt(decrypt_op, &display, timeout) {
                    // Use `ref v` + clone because Decrypted implements Drop (ZeroizeOnDrop);
                    // moving Vec<u8> out of a Drop type is not allowed. The clone gives the
                    // caller a fresh Vec; the original inside Decrypted is zeroized on drop.
                    Ok(Decrypted::RsaPlaintext(ref v)) => AsyncResult::Bytes(v.to_vec()),
                    Ok(_) => AsyncResult::DeviceError("unexpected decrypt variant".into()),
                    Err(TransportError::ChallengeTimeout) => AsyncResult::Rejected,
                    Err(e) => AsyncResult::DeviceError(e.to_string()),
                }
            });
            let mut guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
            if let Some(state) = guard.as_mut() {
                if let Some(session) = state.sessions.get_mut(hSession) {
                    let id = session.next_async_id();
                    session.pending = PendingOp::Async { id, thread };
                }
            }
            return CKR_PENDING;
        }

        // Sync path.
        let plaintext = {
            let dev = device_arc.lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
            let display = onlykey_transport::challenge_ui::StderrDisplay;
            match dev.decrypt(decrypt_op, &display, timeout) {
                // ref v + clone: Decrypted implements Drop (ZeroizeOnDrop), so
                // Vec<u8> cannot be moved out. Clone gives the caller a fresh
                // copy; the original inside Decrypted is zeroized on drop.
                Ok(Decrypted::RsaPlaintext(ref v)) => v.to_vec(),
                Ok(_) => return CKR_GENERAL_ERROR,
                Err(TransportError::ChallengeTimeout) => return CKR_FUNCTION_REJECTED,
                Err(e) => return transport_to_ckr(&e),
            }
        };

        if pData.is_null() {
            unsafe { *pulDataLen = plaintext.len() as CK_ULONG };
            return CKR_OK;
        }
        if unsafe { *pulDataLen } < plaintext.len() as CK_ULONG {
            unsafe { *pulDataLen = plaintext.len() as CK_ULONG };
            return cryptoki_sys::CKR_BUFFER_TOO_SMALL;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(plaintext.as_ptr(), pData, plaintext.len());
            *pulDataLen = plaintext.len() as CK_ULONG;
        }
        CKR_OK
    })
}

// --- DeriveKey ----------------------------------------------------------------

pub unsafe extern "C" fn C_DeriveKey(
    hSession: CK_SESSION_HANDLE,
    pMechanism: CK_MECHANISM_PTR,
    hBaseKey: CK_OBJECT_HANDLE,
    pTemplate: *mut cryptoki_sys::CK_ATTRIBUTE,
    ulAttributeCount: CK_ULONG,
    phKey: *mut CK_OBJECT_HANDLE,
) -> CK_RV {
    catch_panic(|| {
        if pMechanism.is_null() || phKey.is_null() {
            return CKR_ARGUMENTS_BAD;
        }

        let mech = unsafe { &*pMechanism };
        if mech.mechanism != CKM_ECDH1_DERIVE {
            return CKR_MECHANISM_INVALID;
        }

        // Parse CK_ECDH1_DERIVE_PARAMS to get the peer public key.
        if mech.pParameter.is_null()
            || mech.ulParameterLen < std::mem::size_of::<CK_ECDH1_DERIVE_PARAMS>() as CK_ULONG
        {
            return CKR_ARGUMENTS_BAD;
        }
        let params = unsafe { &*(mech.pParameter as *const CK_ECDH1_DERIVE_PARAMS) };
        if params.pPublicData.is_null() || params.ulPublicDataLen == 0 {
            return CKR_ARGUMENTS_BAD;
        }
        let peer_bytes = unsafe {
            std::slice::from_raw_parts(
                params.pPublicData as *const u8,
                params.ulPublicDataLen as usize,
            )
        };

        // Parse optional CKA_VALUE_LEN from the caller's template.
        let requested_len: Option<usize> = if !pTemplate.is_null() {
            let mut found = None;
            for i in 0..ulAttributeCount as usize {
                let a = unsafe { &*pTemplate.add(i) };
                if a.type_ == cryptoki_sys::CKA_VALUE_LEN
                    && !a.pValue.is_null()
                    && a.ulValueLen as usize == std::mem::size_of::<CK_ULONG>()
                {
                    let bytes = unsafe {
                        std::slice::from_raw_parts(
                            a.pValue as *const u8,
                            std::mem::size_of::<CK_ULONG>(),
                        )
                    };
                    if let Ok(arr) = bytes.try_into() {
                        let len = CK_ULONG::from_ne_bytes(arr) as usize;
                        found = Some(len);
                    }
                    break;
                }
            }
            found
        } else {
            None
        };

        // Extract key info while holding the module lock.
        let (decrypt_op, session_type, device_arc, timeout) = {
            let guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
            let state = match guard.as_ref() {
                Some(s) => s,
                None => return CKR_CRYPTOKI_NOT_INITIALIZED,
            };
            if state.sessions.get(hSession).is_none() {
                return CKR_SESSION_HANDLE_INVALID;
            }
            let obj = match state.objects.get(hBaseKey) {
                Some(o) => o,
                None => return CKR_KEY_HANDLE_INVALID,
            };

            let op = match obj.algorithm {
                SlotAlgorithm::Curve25519 => {
                    if peer_bytes.len() != 32 {
                        return CKR_ARGUMENTS_BAD;
                    }
                    let mut pk = [0u8; 32];
                    pk.copy_from_slice(peer_bytes);
                    DecryptOp::Curve25519 {
                        slot: obj.slot,
                        peer_key: pk,
                    }
                }
                SlotAlgorithm::NistP256 => {
                    // Accept 65-byte uncompressed (04 || x || y) or 64-byte raw.
                    let raw: &[u8] = if peer_bytes.len() == 65 && peer_bytes[0] == 0x04 {
                        &peer_bytes[1..]
                    } else if peer_bytes.len() == 64 {
                        peer_bytes
                    } else {
                        return CKR_ARGUMENTS_BAD;
                    };
                    let mut pk = [0u8; 64];
                    pk.copy_from_slice(raw);
                    DecryptOp::NistP256 {
                        slot: obj.slot,
                        peer_key: pk,
                    }
                }
                _ => return CKR_KEY_TYPE_INCONSISTENT,
            };

            // Re-fetch session_type inside the device lock to avoid holding the session lock
            // across device I/O; the session could have been closed since the earlier validation.
            let session_type = match state.sessions.get(hSession) {
                Some(s) => s.session_type,
                None => return CKR_SESSION_HANDLE_INVALID,
            };
            let timeout = state
                .device
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .config
                .challenge_timeout;

            (op, session_type, Arc::clone(&state.device), timeout)
        };

        // Call device (lock released).
        use crate::session::SessionType;
        let secret_bytes: Zeroizing<Vec<u8>> = if session_type == SessionType::Async {
            // Async sessions for ECDH are rare; run sync to simplify output routing.
            // Async C_DeriveKey is not in the PKCS#11 3.2 async call table.
            let dev = device_arc.lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
            let display = onlykey_transport::challenge_ui::StderrDisplay;
            match dev.decrypt(decrypt_op, &display, timeout) {
                Ok(Decrypted::SharedSecret32(b)) => Zeroizing::new(b.to_vec()),
                Ok(_) => return CKR_GENERAL_ERROR,
                Err(TransportError::ChallengeTimeout) => return CKR_FUNCTION_REJECTED,
                Err(e) => return transport_to_ckr(&e),
            }
        } else {
            let dev = device_arc.lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
            let display = onlykey_transport::challenge_ui::StderrDisplay;
            match dev.decrypt(decrypt_op, &display, timeout) {
                Ok(Decrypted::SharedSecret32(b)) => Zeroizing::new(b.to_vec()),
                Ok(_) => return CKR_GENERAL_ERROR,
                Err(TransportError::ChallengeTimeout) => return CKR_FUNCTION_REJECTED,
                Err(e) => return transport_to_ckr(&e),
            }
        };

        // Optionally truncate to caller-requested length.
        let secret: Zeroizing<Vec<u8>> = if let Some(len) = requested_len {
            if len > secret_bytes.len() {
                return CKR_ARGUMENTS_BAD;
            }
            Zeroizing::new(secret_bytes[..len].to_vec())
        } else {
            secret_bytes
        };

        // Insert transient secret object and return its handle.
        let mut guard = module_lock().lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });
        let state = match guard.as_mut() {
            Some(s) => s,
            None => return CKR_CRYPTOKI_NOT_INITIALIZED,
        };
        let handle = state.objects.insert_secret(hSession, secret);
        unsafe { *phKey = handle };
        CKR_OK
    })
}

// --- Internal helpers ---------------------------------------------------------

fn apply_prehash(mechanism: SignMechanism, data: &[u8]) -> Result<Zeroizing<Vec<u8>>, CK_RV> {
    use crate::mechanism::HashAlg;
    match mechanism.hash_alg() {
        None => Ok(Zeroizing::new(data.to_vec())),
        Some(HashAlg::Sha1) => Err(CKR_MECHANISM_INVALID),
        Some(HashAlg::Sha256) => Ok(Zeroizing::new(Sha256::digest(data).to_vec())),
        Some(HashAlg::Sha384) => Ok(Zeroizing::new(Sha384::digest(data).to_vec())),
        Some(HashAlg::Sha512) => Ok(Zeroizing::new(Sha512::digest(data).to_vec())),
    }
}

fn make_sign_op_from_slot(
    slot: u8,
    algorithm: SlotAlgorithm,
    _mechanism: SignMechanism,
    payload: Vec<u8>,
) -> Result<SignOp, CK_RV> {
    match algorithm {
        SlotAlgorithm::Ed25519 => Ok(SignOp::Ed25519 { slot, payload }),
        SlotAlgorithm::NistP256 | SlotAlgorithm::Secp256k1 => {
            Ok(SignOp::EcdsaP256 { slot, payload })
        }
        SlotAlgorithm::Rsa2048 | SlotAlgorithm::Rsa4096 => Ok(SignOp::Rsa {
            slot,
            digest: payload,
        }),
        SlotAlgorithm::Curve25519 => Err(CKR_KEY_TYPE_INCONSISTENT),
        // HmacSha1 is handled before this function is called (C_Sign routes HMAC
        // through dev.hmac() and returns early). This arm is unreachable in practice.
        SlotAlgorithm::HmacSha1 => Err(CKR_KEY_TYPE_INCONSISTENT),
    }
}

fn sig_to_bytes(sig: onlykey_transport::Signature) -> Vec<u8> {
    match sig {
        onlykey_transport::Signature::Ed25519(b) => b.to_vec(),
        onlykey_transport::Signature::EcdsaRaw(b) => b.to_vec(),
        onlykey_transport::Signature::Rsa(v) => v,
    }
}

/// Enumerate key objects from the device and insert them into the object table.
pub fn enumerate_objects(
    device: &Arc<Mutex<OnlyKeyDevice>>,
    slot_config: &SlotConfig,
    objects: &mut ObjectTable,
) {
    let dev = device.lock().unwrap_or_else(|e| {
            // A prior thread panicked while holding the module lock, leaving
            // shared state potentially partially updated. We recover rather
            // than propagating the poison (which would make the PKCS#11 module
            // permanently unusable after any internal panic). Log a warning
            // so the problem is visible in stderr even when the caller
            // receives CKR_OK. Issue OnlyKey-8er.
            eprintln!(
                "onlykey-pkcs11: WARNING: module mutex was poisoned; \
                 recovering with potentially partial state"
            );
            e.into_inner()
        });

    // ECC slots 101-116
    for slot_num in 101u8..=116u8 {
        let alg = match slot_config.get_ecc(slot_num) {
            Some(a) => a,
            None => {
                eprintln!(
                    "onlykey-pkcs11: ECC slot {}: no algorithm in slots.toml, skipping",
                    slot_num
                );
                continue;
            }
        };

        let key_slot = KeySlot::EccStored(slot_num);
        let ecc_alg = match alg {
            SlotAlgorithm::Ed25519 => EccAlgorithm::Ed25519,
            SlotAlgorithm::Curve25519 => EccAlgorithm::Curve25519,
            SlotAlgorithm::NistP256 => EccAlgorithm::NistP256,
            SlotAlgorithm::Secp256k1 => EccAlgorithm::Secp256k1,
            _ => continue,
        };

        let raw_bytes = match dev.get_ecc_pubkey_raw(key_slot, ecc_alg) {
            Ok((_key, bytes)) => bytes,
            Err(e) => {
                eprintln!(
                    "onlykey-pkcs11: ECC slot {}: pubkey query failed: {}",
                    slot_num, e
                );
                continue;
            }
        };

        let label = slot_config
            .get_label(slot_num)
            .unwrap_or("OnlyKey key")
            .to_string();
        let id = vec![slot_num];
        objects.insert(KeyObject {
            handle: 0,
            class: cryptoki_sys::CKO_PUBLIC_KEY,
            slot: slot_num,
            algorithm: alg,
            label: label.clone(),
            id: id.clone(),
            pubkey_bytes: Some(raw_bytes),
        });
        objects.insert(KeyObject {
            handle: 0,
            class: cryptoki_sys::CKO_PRIVATE_KEY,
            slot: slot_num,
            algorithm: alg,
            label,
            id,
            pubkey_bytes: None,
        });
    }

    // RSA slots 1-4
    for slot_num in 1u8..=4u8 {
        let alg = match slot_config.get_rsa(slot_num) {
            Some(a) => a,
            None => continue,
        };

        let key_slot = KeySlot::RsaStored(slot_num);
        let raw_bytes = match dev.get_pubkey_raw(key_slot) {
            Ok((_key, bytes)) => bytes,
            Err(e) => {
                eprintln!(
                    "onlykey-pkcs11: RSA slot {}: pubkey query failed: {}",
                    slot_num, e
                );
                continue;
            }
        };

        let label = slot_config
            .get_label(slot_num)
            .unwrap_or("OnlyKey RSA key")
            .to_string();
        let id = vec![slot_num];
        objects.insert(KeyObject {
            handle: 0,
            class: cryptoki_sys::CKO_PUBLIC_KEY,
            slot: slot_num,
            algorithm: alg,
            label: label.clone(),
            id: id.clone(),
            pubkey_bytes: Some(raw_bytes),
        });
        objects.insert(KeyObject {
            handle: 0,
            class: cryptoki_sys::CKO_PRIVATE_KEY,
            slot: slot_num,
            algorithm: alg,
            label,
            id,
            pubkey_bytes: None,
        });
    }

    // HMAC slots 1-2. No device query is needed; we simply expose a
    // CKO_SECRET_KEY object for each configured HMAC slot. The HMAC key
    // material is entirely hardware-bound and never queried from the device.
    for slot_num in 1u8..=2u8 {
        match slot_config.get_hmac(slot_num) {
            Some(_) => {}
            None => continue,
        }

        let label = slot_config
            .get_label(slot_num)
            .unwrap_or("OnlyKey HMAC key")
            .to_string();
        let id = vec![slot_num];
        objects.insert(KeyObject {
            handle: 0,
            class: cryptoki_sys::CKO_SECRET_KEY,
            slot: slot_num,
            algorithm: SlotAlgorithm::HmacSha1,
            label,
            id,
            pubkey_bytes: None,
        });
    }
}

// --- Static function tables ---------------------------------------------------

/// The static PKCS#11 3.2 function table.
///
/// Unsupported function slots are set to `None` (null pointer). Compliant
/// PKCS#11 callers treat null function pointers as `CKR_FUNCTION_NOT_SUPPORTED`.
pub const FUNCTION_LIST_3_2: CK_FUNCTION_LIST_3_2 = CK_FUNCTION_LIST_3_2 {
    version: CK_VERSION { major: 3, minor: 2 },
    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: Some(crate::C_GetFunctionList),
    C_GetSlotList: Some(C_GetSlotList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: Some(C_GetMechanismList),
    C_GetMechanismInfo: Some(C_GetMechanismInfo),
    C_InitToken: None,
    C_InitPIN: None,
    C_SetPIN: None,
    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: Some(C_CloseSession),
    C_CloseAllSessions: Some(C_CloseAllSessions),
    C_GetSessionInfo: Some(C_GetSessionInfo),
    C_GetOperationState: None,
    C_SetOperationState: None,
    C_Login: Some(C_Login),
    C_Logout: Some(C_Logout),
    C_CreateObject: None,
    C_CopyObject: None,
    C_DestroyObject: None,
    C_GetObjectSize: None,
    C_GetAttributeValue: Some(C_GetAttributeValue),
    C_SetAttributeValue: None,
    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),
    C_EncryptInit: None,
    C_Encrypt: None,
    C_EncryptUpdate: None,
    C_EncryptFinal: None,
    C_DecryptInit: Some(C_DecryptInit),
    C_Decrypt: Some(C_Decrypt),
    C_DecryptUpdate: None,
    C_DecryptFinal: None,
    C_DigestInit: Some(C_DigestInit),
    C_Digest: Some(C_Digest),
    C_DigestUpdate: Some(C_DigestUpdate),
    C_DigestKey: None,
    C_DigestFinal: Some(C_DigestFinal),
    C_SignInit: Some(C_SignInit),
    C_Sign: Some(C_Sign),
    C_SignUpdate: Some(C_SignUpdate),
    C_SignFinal: Some(C_SignFinal),
    C_SignRecoverInit: None,
    C_SignRecover: None,
    C_VerifyInit: None,
    C_Verify: None,
    C_VerifyUpdate: None,
    C_VerifyFinal: None,
    C_VerifyRecoverInit: None,
    C_VerifyRecover: None,
    C_DigestEncryptUpdate: None,
    C_DecryptDigestUpdate: None,
    C_SignEncryptUpdate: None,
    C_DecryptVerifyUpdate: None,
    C_GenerateKey: None,
    C_GenerateKeyPair: None,
    C_WrapKey: None,
    C_UnwrapKey: None,
    C_DeriveKey: Some(C_DeriveKey),
    C_SeedRandom: None,
    C_GenerateRandom: None,
    C_GetFunctionStatus: None,
    C_CancelFunction: None,
    C_WaitForSlotEvent: None,
    C_GetInterfaceList: None,
    C_GetInterface: Some(crate::C_GetInterface),
    C_LoginUser: None,
    C_SessionCancel: None,
    C_MessageEncryptInit: None,
    C_EncryptMessage: None,
    C_EncryptMessageBegin: None,
    C_EncryptMessageNext: None,
    C_MessageEncryptFinal: None,
    C_MessageDecryptInit: None,
    C_DecryptMessage: None,
    C_DecryptMessageBegin: None,
    C_DecryptMessageNext: None,
    C_MessageDecryptFinal: None,
    C_MessageSignInit: None,
    C_SignMessage: None,
    C_SignMessageBegin: None,
    C_SignMessageNext: None,
    C_MessageSignFinal: None,
    C_MessageVerifyInit: None,
    C_VerifyMessage: None,
    C_VerifyMessageBegin: None,
    C_VerifyMessageNext: None,
    C_MessageVerifyFinal: None,
    C_EncapsulateKey: None,
    C_DecapsulateKey: None,
    C_VerifySignatureInit: None,
    C_VerifySignature: None,
    C_VerifySignatureUpdate: None,
    C_VerifySignatureFinal: None,
    C_GetSessionValidationFlags: None,
    C_AsyncComplete: Some(C_AsyncComplete),
    C_AsyncGetID: Some(C_AsyncGetID),
    C_AsyncJoin: Some(C_AsyncJoin),
    C_WrapKeyAuthenticated: None,
    C_UnwrapKeyAuthenticated: None,
};

/// The base PKCS#11 3.x `CK_FUNCTION_LIST`.
pub const FUNCTION_LIST_BASE: CK_FUNCTION_LIST = CK_FUNCTION_LIST {
    version: CK_VERSION { major: 3, minor: 1 },
    C_Initialize: Some(C_Initialize),
    C_Finalize: Some(C_Finalize),
    C_GetInfo: Some(C_GetInfo),
    C_GetFunctionList: Some(crate::C_GetFunctionList),
    C_GetSlotList: Some(C_GetSlotList),
    C_GetSlotInfo: Some(C_GetSlotInfo),
    C_GetTokenInfo: Some(C_GetTokenInfo),
    C_GetMechanismList: Some(C_GetMechanismList),
    C_GetMechanismInfo: Some(C_GetMechanismInfo),
    C_InitToken: None,
    C_InitPIN: None,
    C_SetPIN: None,
    C_OpenSession: Some(C_OpenSession),
    C_CloseSession: Some(C_CloseSession),
    C_CloseAllSessions: Some(C_CloseAllSessions),
    C_GetSessionInfo: Some(C_GetSessionInfo),
    C_GetOperationState: None,
    C_SetOperationState: None,
    C_Login: Some(C_Login),
    C_Logout: Some(C_Logout),
    C_CreateObject: None,
    C_CopyObject: None,
    C_DestroyObject: None,
    C_GetObjectSize: None,
    C_GetAttributeValue: Some(C_GetAttributeValue),
    C_SetAttributeValue: None,
    C_FindObjectsInit: Some(C_FindObjectsInit),
    C_FindObjects: Some(C_FindObjects),
    C_FindObjectsFinal: Some(C_FindObjectsFinal),
    C_EncryptInit: None,
    C_Encrypt: None,
    C_EncryptUpdate: None,
    C_EncryptFinal: None,
    C_DecryptInit: Some(C_DecryptInit),
    C_Decrypt: Some(C_Decrypt),
    C_DecryptUpdate: None,
    C_DecryptFinal: None,
    C_DigestInit: Some(C_DigestInit),
    C_Digest: Some(C_Digest),
    C_DigestUpdate: Some(C_DigestUpdate),
    C_DigestKey: None,
    C_DigestFinal: Some(C_DigestFinal),
    C_SignInit: Some(C_SignInit),
    C_Sign: Some(C_Sign),
    C_SignUpdate: Some(C_SignUpdate),
    C_SignFinal: Some(C_SignFinal),
    C_SignRecoverInit: None,
    C_SignRecover: None,
    C_VerifyInit: None,
    C_Verify: None,
    C_VerifyUpdate: None,
    C_VerifyFinal: None,
    C_VerifyRecoverInit: None,
    C_VerifyRecover: None,
    C_DigestEncryptUpdate: None,
    C_DecryptDigestUpdate: None,
    C_SignEncryptUpdate: None,
    C_DecryptVerifyUpdate: None,
    C_GenerateKey: None,
    C_GenerateKeyPair: None,
    C_WrapKey: None,
    C_UnwrapKey: None,
    C_DeriveKey: Some(C_DeriveKey),
    C_SeedRandom: None,
    C_GenerateRandom: None,
    C_GetFunctionStatus: None,
    C_CancelFunction: None,
    C_WaitForSlotEvent: None,
};

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki_sys::CKR_BUFFER_TOO_SMALL;

    // --- C_GetSlotList --------------------------------------------------------

    /// Calling with pSlotList=null writes 1 to pulCount and returns CKR_OK.
    /// This is the "query count" leg of the two-call sizing pattern.
    #[test]
    fn get_slot_list_null_list_returns_count() {
        let mut count: CK_ULONG = 0;
        let rv = unsafe { C_GetSlotList(0, std::ptr::null_mut(), &mut count) };
        assert_eq!(rv, CKR_OK);
        assert_eq!(count, 1);
    }

    /// Calling with pSlotList non-null but pulCount=0 writes 1 to pulCount and
    /// returns CKR_BUFFER_TOO_SMALL.
    #[test]
    fn get_slot_list_buffer_too_small() {
        let mut count: CK_ULONG = 0;
        let mut slot: CK_SLOT_ID = 0xFFFF_FFFF;
        let rv = unsafe { C_GetSlotList(0, &mut slot, &mut count) };
        assert_eq!(rv, CKR_BUFFER_TOO_SMALL);
        assert_eq!(
            count, 1,
            "pulCount must hold required size on CKR_BUFFER_TOO_SMALL"
        );
    }

    /// Calling with pSlotList non-null and pulCount=1 fills the slot ID and
    /// returns CKR_OK.
    #[test]
    fn get_slot_list_fills_slot_id() {
        let mut count: CK_ULONG = 1;
        let mut slot: CK_SLOT_ID = 0xFFFF_FFFF;
        let rv = unsafe { C_GetSlotList(0, &mut slot, &mut count) };
        assert_eq!(rv, CKR_OK);
        assert_eq!(count, 1);
        assert_eq!(slot, SLOT_ID);
    }

    // --- C_GetMechanismList ---------------------------------------------------

    /// Calling with pMechanismList=null writes the mechanism count to pulCount
    /// and returns CKR_OK.
    #[test]
    fn get_mechanism_list_null_list_returns_count() {
        let mut count: CK_ULONG = 0;
        let rv = unsafe { C_GetMechanismList(SLOT_ID, std::ptr::null_mut(), &mut count) };
        assert_eq!(rv, CKR_OK);
        assert_eq!(count, MECHANISMS.len() as CK_ULONG);
    }

    /// Calling with pMechanismList non-null but pulCount=0 writes the required
    /// count to pulCount and returns CKR_BUFFER_TOO_SMALL.
    #[test]
    fn get_mechanism_list_buffer_too_small() {
        let mut count: CK_ULONG = 0;
        let mut list = vec![0u64; MECHANISMS.len()];
        let rv = unsafe { C_GetMechanismList(SLOT_ID, list.as_mut_ptr(), &mut count) };
        assert_eq!(rv, CKR_BUFFER_TOO_SMALL);
        assert_eq!(
            count,
            MECHANISMS.len() as CK_ULONG,
            "pulCount must hold required size on CKR_BUFFER_TOO_SMALL"
        );
    }

    /// Calling with a correctly sized buffer fills every mechanism type and
    /// returns CKR_OK.
    #[test]
    fn get_mechanism_list_fills_mechanisms() {
        let n = MECHANISMS.len();
        let mut count: CK_ULONG = n as CK_ULONG;
        let mut list = vec![0u64; n];
        let rv = unsafe { C_GetMechanismList(SLOT_ID, list.as_mut_ptr(), &mut count) };
        assert_eq!(rv, CKR_OK);
        assert_eq!(count, n as CK_ULONG);
        for (i, &expected) in MECHANISMS.iter().enumerate() {
            assert_eq!(list[i], expected, "mechanism[{i}] mismatch");
        }
    }
}
