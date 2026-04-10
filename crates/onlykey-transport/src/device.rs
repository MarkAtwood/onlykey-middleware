use std::time::{Duration, SystemTime};

use hidapi::HidApi;
use onlykey_hid::{Command, DeviceState, HidFrame, KeySlot};

use crate::challenge_ui::ChallengeDisplay;
use crate::config::Config;
use crate::error::TransportError;
use crate::io::RawIo;
use crate::ops;
use crate::types::{DecryptOp, Decrypted, EccAlgorithm, PublicKey, SignOp, Signature};

/// OnlyKey VID/PID pairs (standard and original firmware).
const VID_PID_PAIRS: &[(u16, u16)] = &[
    (0x16C0, 0x0486), // Standard OnlyKey (TeensyDuino)
    (0x1D50, 0x60FC), // OnlyKey with OpenSK firmware
];

/// A connected, unlocked OnlyKey device.
///
/// All operations (sign, decrypt, HMAC, get_pubkey) go through the `io` field.
/// The device mutex is managed by the caller in PKCS#11 and vcard contexts.
pub struct OnlyKeyDevice {
    pub io: RawIo,
    pub firmware_version: String,
    pub config: Config,
    /// 4-byte pseudo-serial derived from ECC slot 101's public key at connect time.
    ///
    /// The OnlyKey firmware exposes no unique device identifier. This field provides
    /// a stable, key-derived surrogate so that two devices with different key material
    /// appear distinct to PKCS#11 and OpenPGP Card consumers. See `ops::derive_pseudo_serial`.
    ///
    /// Falls back to `[0, 0, 0, 1]` when slot 101 is empty.
    pub pseudo_serial: [u8; 4],
}

impl OnlyKeyDevice {
    /// Open and connect to the first available unlocked OnlyKey.
    ///
    /// Tries all known VID/PID pairs. Returns the first device that responds
    /// to OKCONNECT with `DeviceState::Unlocked`.
    pub fn open(config: Config) -> Result<Self, TransportError> {
        let api = HidApi::new()?;
        for &(vid, pid) in VID_PID_PAIRS {
            for device_info in api.device_list() {
                if device_info.vendor_id() != vid || device_info.product_id() != pid {
                    continue;
                }
                match device_info.open_device(&api) {
                    Ok(hid) => {
                        let io = RawIo::new(hid, config.inter_frame_timeout.as_millis() as i32);
                        match connect(&io) {
                            Ok(firmware_version) => {
                                let pseudo_serial = ops::get_device_pseudo_serial(&io);
                                if pseudo_serial == ops::FALLBACK_PSEUDO_SERIAL {
                                    // Slot 101 (OpenPGP signature slot) is empty — typically
                                    // a PIV-only device. Multiple such devices present the
                                    // same serialNumber to PKCS#11 and OpenPGP Card consumers,
                                    // making them indistinguishable. This is harmless for
                                    // single-device setups but breaks key attribution when
                                    // two devices are connected simultaneously.
                                    eprintln!(
                                        "warning: ECC slot 101 is empty; \
                                         using fallback serial 00000001. \
                                         If you use multiple devices, load any ECC key into \
                                         slot 101 to get a unique per-device serial."
                                    );
                                }
                                return Ok(OnlyKeyDevice {
                                    io,
                                    firmware_version,
                                    config,
                                    pseudo_serial,
                                });
                            }
                            Err(TransportError::Locked) | Err(TransportError::Uninitialized) => {
                                return Err(TransportError::Locked);
                            }
                            Err(_) => {
                                // Try the next device.
                                continue;
                            }
                        }
                    }
                    Err(e) => {
                        // Previously all open errors were silently swallowed as
                        // continue -> NotFound, losing permission-denied diagnostics.
                        // Surface permission errors explicitly so callers can report
                        // "add udev rule" instead of "device not found". Issue OnlyKey-czc.
                        let msg = e.to_string().to_ascii_lowercase();
                        if msg.contains("permission")
                            || msg.contains("access denied")
                            || msg.contains("operation not permitted")
                        {
                            return Err(TransportError::Hid(e));
                        }
                        continue;
                    }
                }
            }
        }
        Err(TransportError::NotFound)
    }

    /// Re-check device state without reconnecting.
    ///
    /// Useful for `C_Login` to verify the device is still unlocked.
    pub fn get_device_state(&self) -> Result<DeviceState, TransportError> {
        send_connect_and_parse(&self.io)
    }

    /// Perform a signing operation, delegating to `ops::sign`.
    pub fn sign(
        &self,
        op: SignOp,
        display: &dyn ChallengeDisplay,
        timeout: Duration,
    ) -> Result<Signature, TransportError> {
        ops::sign(&self.io, op, display, timeout)
    }

    /// Perform a decrypt / ECDH operation, delegating to `ops::decrypt`.
    pub fn decrypt(
        &self,
        op: DecryptOp,
        display: &dyn ChallengeDisplay,
        timeout: Duration,
    ) -> Result<Decrypted, TransportError> {
        ops::decrypt(&self.io, op, display, timeout)
    }

    /// Compute HMAC-SHA1 using a hardware HMAC key slot.
    ///
    /// Does not require a button press -- uses a fixed 3-second timeout
    /// (see `io::HMAC_TIMEOUT_MS`). `slot` must be 1 or 2.
    pub fn hmac(&self, slot: u8, challenge: &[u8]) -> Result<Vec<u8>, TransportError> {
        ops::hmac(&self.io, slot, challenge)
    }

    /// Retrieve an RSA public key and its raw modulus bytes.
    ///
    /// Used by the PKCS#11 layer at initialization to populate `CKA_MODULUS`.
    pub fn get_pubkey_raw(&self, slot: KeySlot) -> Result<(PublicKey, Vec<u8>), TransportError> {
        ops::get_pubkey_with_bytes(&self.io, slot)
    }

    /// Retrieve an ECC public key and its raw wire bytes.
    ///
    /// Used by the PKCS#11 layer at initialization to populate `CKA_EC_POINT`.
    pub fn get_ecc_pubkey_raw(
        &self,
        slot: KeySlot,
        algorithm: EccAlgorithm,
    ) -> Result<(PublicKey, Vec<u8>), TransportError> {
        ops::get_ecc_pubkey_with_bytes(&self.io, slot, algorithm)
    }
}

/// Send OKCONNECT and return the firmware version on success.
fn connect(io: &RawIo) -> Result<String, TransportError> {
    match send_connect_and_parse(io)? {
        DeviceState::Unlocked(v) => Ok(v),
        DeviceState::Locked => Err(TransportError::Locked),
        DeviceState::Uninitialized => Err(TransportError::Uninitialized),
    }
}

/// Send the OKCONNECT command and parse the response.
fn send_connect_and_parse(io: &RawIo) -> Result<DeviceState, TransportError> {
    // OKCONNECT payload: Unix timestamp as little-endian u32.
    // The wire format is fixed at u32 by the OnlyKey firmware.
    // Saturate rather than wrap: u32 overflows in 2106, not 2038 (which is
    // the signed-i32 boundary). A saturated value (2106-02-07) is clearly
    // wrong and will be visible in device logs; wrapping to 1970 would be
    // silent and confusing.
    // If the system clock is before the UNIX epoch, duration_since returns Err;
    // treat that as 0 (firmware will reject or ignore it).
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or(std::time::Duration::ZERO)
        .as_secs()
        .min(u64::from(u32::MAX)) as u32;
    let ts = now.to_le_bytes();

    let frame = HidFrame::command(Command::Connect.wire_byte(), 0, &ts)?;
    io.write(&frame)?;

    // Read the OKCONNECT response. It arrives as a single frame within ~2 seconds.
    let response_frame = io.read_frame(2000)?;
    response_frame
        .device_state()
        .ok_or_else(|| TransportError::Protocol("unrecognized OKCONNECT response".into()))
}
