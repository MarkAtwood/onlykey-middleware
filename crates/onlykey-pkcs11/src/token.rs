//! PKCS#11 slot and token info construction.

use cryptoki_sys::{
    CKF_PROTECTED_AUTHENTICATION_PATH, CKF_RW_SESSION, CKF_TOKEN_INITIALIZED,
    CKF_TOKEN_PRESENT, CK_SLOT_INFO, CK_TOKEN_INFO, CK_VERSION,
};

use crate::ck32::CKF_ASYNC_SESSION_SUPPORTED;

/// Pad or truncate a string to fill a fixed-length blank-padded UTF-8 byte slice.
fn pad(dst: &mut [u8], s: &str) {
    let bytes = s.as_bytes();
    let n = bytes.len().min(dst.len());
    dst[..n].copy_from_slice(&bytes[..n]);
    for b in &mut dst[n..] {
        *b = b' ';
    }
}

/// Build a `CK_SLOT_INFO` for slot 0 (the single OnlyKey slot).
pub fn slot_info() -> CK_SLOT_INFO {
    let mut info = CK_SLOT_INFO {
        slotDescription: [b' '; 64],
        manufacturerID: [b' '; 32],
        flags: CKF_TOKEN_PRESENT,
        hardwareVersion: CK_VERSION { major: 1, minor: 0 },
        firmwareVersion: CK_VERSION { major: 1, minor: 0 },
    };
    pad(&mut info.slotDescription, "OnlyKey HID Security Key");
    pad(&mut info.manufacturerID, "CryptoTrust");
    info
}

/// Build a `CK_TOKEN_INFO` for the OnlyKey token.
///
/// `firmware_version`: e.g. "3.0.4" (truncated to 16 chars in firmwareVersion label).
/// `serial`: 4-byte pseudo-serial from `ops::get_device_pseudo_serial`, formatted as
///   8 lowercase hex digits in `serialNumber` (right-padded with spaces to 16).
/// `unlocked`: whether the device is currently unlocked.
pub fn token_info(_firmware_version: &str, serial: [u8; 4], _unlocked: bool) -> CK_TOKEN_INFO {
    let mut info = CK_TOKEN_INFO {
        label: [b' '; 32],
        manufacturerID: [b' '; 32],
        model: [b' '; 16],
        serialNumber: [b' '; 16],
        // CKF_LOGIN_REQUIRED is intentionally absent: C_Login is a no-op stub
        // (the OnlyKey device authenticates via physical button press, not a
        // host-side PIN/password). Advertising CKF_LOGIN_REQUIRED would cause
        // PKCS#11 callers to call C_Login before any operation, receive CKR_OK
        // from the stub, and then incorrectly believe the session requires a
        // credential that was never validated. Issue OnlyKey-3sc.
        flags: CKF_TOKEN_INITIALIZED
            | CKF_PROTECTED_AUTHENTICATION_PATH
            | CKF_ASYNC_SESSION_SUPPORTED
            | CKF_RW_SESSION,
        ulMaxSessionCount: u64::MAX as _,
        ulSessionCount: 0,
        ulMaxRwSessionCount: u64::MAX as _,
        ulRwSessionCount: 0,
        ulMaxPinLen: 0,
        ulMinPinLen: 0,
        ulTotalPublicMemory: u64::MAX as _,
        ulFreePublicMemory: u64::MAX as _,
        ulTotalPrivateMemory: u64::MAX as _,
        ulFreePrivateMemory: u64::MAX as _,
        hardwareVersion: CK_VERSION { major: 1, minor: 0 },
        firmwareVersion: CK_VERSION { major: 1, minor: 0 },
        utcTime: [b' '; 16],
    };
    pad(&mut info.label, "OnlyKey");
    pad(&mut info.manufacturerID, "CryptoTrust");
    pad(&mut info.model, "OnlyKey");
    // PKCS#11 v3.2 sec.4.4: serialNumber is a 16-byte space-padded string.
    // We format the 4-byte pseudo-serial as 8 lowercase hex digits.
    // Previously this was set to the firmware version string, which is not unique.
    let serial_hex = format!("{:08x}", u32::from_be_bytes(serial));
    pad(&mut info.serialNumber, &serial_hex);
    info
}

#[cfg(test)]
mod tests {
    use super::*;
    use cryptoki_sys::CKF_LOGIN_REQUIRED;

    #[test]
    fn token_flags_include_required_set() {
        let info = token_info("3.0.4", [0, 0, 0, 1], true);
        assert_ne!(info.flags & CKF_TOKEN_INITIALIZED, 0);
        assert_ne!(info.flags & CKF_PROTECTED_AUTHENTICATION_PATH, 0);
        // CKF_LOGIN_REQUIRED must NOT be set: C_Login is a no-op stub.
        // See the flags comment in token_info() for the full rationale. Issue OnlyKey-3sc.
        assert_eq!(info.flags & CKF_LOGIN_REQUIRED, 0);
        assert_ne!(info.flags & CKF_ASYNC_SESSION_SUPPORTED, 0);
    }

    #[test]
    fn slot_info_has_token_present() {
        let si = slot_info();
        assert_ne!(si.flags & CKF_TOKEN_PRESENT, 0);
    }
}
