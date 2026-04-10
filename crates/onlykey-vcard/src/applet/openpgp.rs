//! OpenPGP Card 3.4 applet implementation.
//!
//! Implements the OpenPGP smart card specification v3.4. Receives ISO 7816-4
//! APDUs from scdaemon (via ifd-vpcd -> pcscd) and dispatches them to the
//! OnlyKey device for signing and decryption.

use std::time::Duration;

use onlykey_transport::challenge_ui::ChallengeDisplay;
use onlykey_transport::TransportError;
use onlykey_transport::{DecryptOp, EccAlgorithm, KeySlot, OnlyKeyDevice, SignOp};
use onlykey_transport::{Decrypted, DeviceState, Signature};
use zeroize::Zeroizing;

use super::Applet;
use crate::apdu::{parse_tlv, parse_tlv_nested, tlv, Apdu, RApdu};
use crate::certstore::Certstore;

// ---------------------------------------------------------------------------
// AID / ATR constants
// ---------------------------------------------------------------------------

const ATR: [u8; 5] = [0x3B, 0x80, 0x80, 0x01, 0x6F];

fn build_aid(serial: [u8; 4]) -> [u8; 16] {
    [
        0xD2, 0x76, 0x00, 0x01, 0x24, 0x01, // OpenPGP Card fixed prefix
        0x03, 0x04, // Version 3.4
        0x00, 0x00, // Manufacturer (unofficial/test)
        serial[0], serial[1], serial[2], serial[3], 0x00, 0x00, // RFU
    ]
}

// ---------------------------------------------------------------------------
// Slot assignment and payload limit constants
// ---------------------------------------------------------------------------

/// OnlyKey ECC slot assignments for OpenPGP Card 3.4 operations.
///
/// These slot numbers are fixed by the OpenPGP-to-OnlyKey mapping and must
/// be consistent with the user's `slots.toml` and the `onlykey-tool` config
/// generator. Any change requires coordinating all three places.
const SLOT_SIG: u8 = 101; // COMPUTE DIGITAL SIGNATURE -- Ed25519, PW1 required
const SLOT_DEC: u8 = 102; // DECIPHER -- Curve25519 ECDH, PW2 required
const SLOT_AUT: u8 = 103; // INTERNAL AUTHENTICATE -- Ed25519, PW2 required

/// Ed25519 payload limit imposed by the OnlyKey HID protocol.
///
/// Payloads larger than this are rejected before the device call so callers
/// receive SW=6A80 (wrong data) rather than an opaque transport error.
/// Value must stay in sync with `onlykey_hid::MAX_PAYLOAD` (768 bytes).
const MAX_ED25519_PAYLOAD: usize = 768;

/// OpenPGP Card 3.4 maximum byte lengths for PUT DATA metadata fields.
///
/// Defined in OpenPGP Card 3.4 sec. 4.4.1. Enforced at PUT DATA time so
/// GET DATA never returns an out-of-spec length. Issue OnlyKey-9cfv.
const MAX_NAME_BYTES: usize = 39; // DO 5B: Cardholder Name
const MAX_URL_BYTES: usize = 254; // DO 5F50: URL

/// Encode a remaining-byte count into an ISO 7816-4 SW2 value for GET RESPONSE
/// chaining (SW1=0x61).
///
/// ISO 7816-4 sec.5.1.3: SW2 encodes the bytes available in the next GET RESPONSE.
/// SW2=0x00 is the special encoding for 256 bytes (not zero). SW2=N (1..=255)
/// means exactly N bytes. Passing count ≥ 256 therefore returns 0x00.
///
/// **Do not call with count = 0.** SW2=0x00 means 256 bytes available, so passing
/// 0 here produces the wrong encoding. All current call sites guarantee count ≥ 1.
///
/// Using `.min(255) as u8` is WRONG: when count == 256 it produces 0xFF (255)
/// instead of 0x00 (256), causing clients (including OpenSC/GnuPG scdaemon) to
/// request one fewer byte than available and issue an extra unnecessary GET
/// RESPONSE round-trip. Issue OnlyKey-9gbl.
fn sw2_remaining(count: usize) -> u8 {
    debug_assert!(count > 0, "sw2_remaining called with 0; SW2=0x00 means 256, not 0");
    if count >= 256 {
        0x00
    } else {
        count as u8
    }
}

// ---------------------------------------------------------------------------
// Signature counter persistence
// ---------------------------------------------------------------------------

/// Write the counter every this many increments.
///
/// The batch size and recovery margin are tightly coupled: we write every
/// `COUNTER_BATCH` signatures and recover by adding `COUNTER_RECOVERY_MARGIN`
/// on startup. This guarantees the counter is monotonically non-decreasing
/// even if the process crashes between batch writes (matching the strategy
/// used by OpenPGP smartcard firmware, RFC 4880-bis annex B).
const COUNTER_BATCH: u32 = 16;

/// Added to the stored counter value on recovery to bound the true counter
/// from above after a crash between batch writes.
///
/// Defined as `COUNTER_BATCH - 1` so the relationship is enforced by the
/// compiler: changing `COUNTER_BATCH` automatically updates this value.
/// Named rather than written inline so call sites read as
/// `saturating_add(COUNTER_RECOVERY_MARGIN)` instead of the opaque
/// `saturating_add(COUNTER_BATCH - 1)`.
const COUNTER_RECOVERY_MARGIN: u32 = COUNTER_BATCH - 1;

/// Return the path to the per-device signature counter file.
///
/// The file is keyed by the device pseudo-serial so that swapping devices
/// does not carry over the wrong counter.
///
/// Returns `None` if the XDG data directory cannot be determined.
fn counter_file_path(serial: [u8; 4]) -> Option<std::path::PathBuf> {
    dirs::data_local_dir().map(|d| {
        d.join("onlykey")
            .join(format!("sig_counter_{:08x}", u32::from_be_bytes(serial)))
    })
}

/// Load the signature counter from disk, returning the conservative upper bound.
///
/// Returns 0 if the file is missing. Logs a warning and returns 0 on parse
/// failure. Adds `COUNTER_RECOVERY_MARGIN` (== `COUNTER_BATCH - 1`) to the
/// stored value so that a crash between writes cannot produce a non-monotonic counter.
fn load_persisted_counter(serial: [u8; 4]) -> u32 {
    let path = match counter_file_path(serial) {
        Some(p) => p,
        None => {
            eprintln!("onlykey-vcard [openpgp]: warning: cannot determine data dir; signature counter starts at 0");
            return 0;
        }
    };
    match std::fs::read_to_string(&path) {
        Ok(s) => match s.trim().parse::<u32>() {
            Ok(n) => {
                let recovered = n.saturating_add(COUNTER_RECOVERY_MARGIN);
                eprintln!(
                    "onlykey-vcard [openpgp]: signature counter recovered: {} + {} = {}",
                    n,
                    COUNTER_RECOVERY_MARGIN,
                    recovered
                );
                recovered
            }
            Err(_) => {
                eprintln!(
                    "onlykey-vcard [openpgp]: warning: corrupt signature counter at {:?}; starting at 0",
                    path
                );
                0
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
        Err(e) => {
            eprintln!(
                "onlykey-vcard [openpgp]: warning: cannot read signature counter: {}; starting at 0",
                e
            );
            0
        }
    }
}

/// Persist the signature counter to disk.
///
/// Writes atomically (tmp + rename) and fsyncs before rename so the value
/// survives a power loss between write and rename. Logs a warning on failure;
/// callers keep the in-RAM counter regardless.
fn save_persisted_counter(serial: [u8; 4], counter: u32) {
    use std::io::Write;
    let path = match counter_file_path(serial) {
        Some(p) => p,
        None => return,
    };
    if let Some(parent) = path.parent() {
        if let Err(e) = std::fs::create_dir_all(parent) {
            eprintln!(
                "onlykey-vcard [openpgp]: warning: cannot create data dir: {}",
                e
            );
            return;
        }
    }
    let tmp_path = path.with_extension("tmp");
    match std::fs::File::create(&tmp_path) {
        Ok(mut f) => {
            if write!(f, "{}", counter).is_err() {
                return;
            }
            if f.sync_all().is_err() {
                return;
            }
            drop(f);
            if let Err(e) = std::fs::rename(&tmp_path, &path) {
                eprintln!(
                    "onlykey-vcard [openpgp]: warning: cannot rename counter tmp file: {}",
                    e
                );
            }
        }
        Err(e) => {
            eprintln!(
                "onlykey-vcard [openpgp]: warning: cannot write signature counter: {}",
                e
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Struct
// ---------------------------------------------------------------------------

/// OpenPGP Card 3.4 applet state.
pub struct OpenPgpApplet {
    selected: bool,
    /// PW1 (0x81) verified -- required for COMPUTE DIGITAL SIGNATURE.
    pin1_verified: bool,
    /// PW2 (0x82) verified -- required for DECIPHER and INTERNAL AUTHENTICATE.
    pin2_verified: bool,
    /// Signature counter (incremented on each successful COMPUTE DIGITAL SIGNATURE).
    sig_counter: u32,
    /// Buffered response for GET RESPONSE chaining.
    chained_response: Vec<u8>,
    /// Number of consecutive GET RESPONSE calls for the current chained response.
    chain_depth: u32,
    /// 4-byte serial number embedded in the AID.
    serial: [u8; 4],
    /// Pre-built AID bytes (depends on serial, stored to allow &[u8] lifetime).
    aid: [u8; 16],
}

impl Default for OpenPgpApplet {
    fn default() -> Self {
        Self::new()
    }
}

impl OpenPgpApplet {
    pub fn new() -> Self {
        let serial = [0, 0, 0, 1];
        OpenPgpApplet {
            selected: false,
            pin1_verified: false,
            pin2_verified: false,
            sig_counter: 0,
            chained_response: Vec::new(),
            chain_depth: 0,
            serial,
            aid: build_aid(serial),
        }
    }

    pub fn with_serial(serial: [u8; 4]) -> Self {
        // Restore counter from disk; adds COUNTER_BATCH-1 as conservative upper bound.
        let sig_counter = load_persisted_counter(serial);
        OpenPgpApplet {
            selected: false,
            pin1_verified: false,
            pin2_verified: false,
            sig_counter,
            chained_response: Vec::new(),
            chain_depth: 0,
            serial,
            aid: build_aid(serial),
        }
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    fn begin_chained_response(&mut self, data: Vec<u8>) -> RApdu {
        if data.len() > 65535 {
            return RApdu {
                sw1: 0x6F,
                sw2: 0x00,
                data: vec![],
            };
        }
        self.chain_depth = 0;
        if data.len() <= 256 {
            return RApdu::ok(data);
        }
        let first: Vec<u8> = data[..256].to_vec();
        self.chained_response = data[256..].to_vec();
        let remaining = sw2_remaining(self.chained_response.len());
        RApdu::more_data(first, remaining)
    }

    // -----------------------------------------------------------------------
    // Command handlers
    // -----------------------------------------------------------------------

    fn cmd_select(&mut self, apdu: &Apdu) -> RApdu {
        if apdu.p1 != 0x04 || apdu.p2 != 0x00 {
            return RApdu::wrong_parameters();
        }
        let aid_prefix = &self.aid[..6];
        if apdu.data.len() < 6 || !apdu.data.starts_with(aid_prefix) {
            return RApdu::file_not_found();
        }
        self.selected = true;
        // Do NOT call self.reset() here. OpenPGP Card 3.4 spec sec.7.2.3 requires
        // PW1/PW2 verification state to persist until power-off; re-selecting the
        // applet does not invalidate a prior VERIFY. Only clear the response-chaining
        // state, which is meaningless after a new SELECT.
        self.chained_response.clear();
        self.chain_depth = 0;
        let aid_bytes = self.aid;
        RApdu::ok(tlv(b"\x6F", &tlv(b"\x84", &aid_bytes)))
    }

    fn cmd_verify(&mut self, apdu: &Apdu, device: &OnlyKeyDevice) -> RApdu {
        if apdu.p1 != 0x00 || (apdu.p2 != 0x81 && apdu.p2 != 0x82) {
            return RApdu::wrong_parameters();
        }
        let unlocked = match device.get_device_state() {
            Ok(DeviceState::Unlocked(_)) => true,
            Ok(_) => false,
            Err(e) => {
                eprintln!(
                    "onlykey-vcard [openpgp]: VERIFY: device state check failed: {}",
                    e
                );
                return RApdu::conditions_not_satisfied();
            }
        };
        if !unlocked {
            return RApdu::security_not_satisfied();
        }
        match apdu.p2 {
            0x81 => {
                self.pin1_verified = true;
                RApdu::ok_empty()
            }
            0x82 => {
                self.pin2_verified = true;
                RApdu::ok_empty()
            }
            // P2 was validated at the start of this function to be 0x81 or 0x82.
            _ => unreachable!("p2 validated at function entry"),
        }
    }

    fn cmd_compute_sig(
        &mut self,
        apdu: &Apdu,
        device: &OnlyKeyDevice,
        display: &dyn ChallengeDisplay,
        timeout: Duration,
    ) -> RApdu {
        if !self.pin1_verified {
            return RApdu::security_not_satisfied();
        }
        if apdu.data.is_empty() {
            // Empty data field: SW=6A80 (wrong data) per OpenPGP Card spec sec.7.2.7
            // -- 6C00 would wrongly imply the expected length is zero.
            return RApdu::wrong_data();
        }
        // Ed25519 on the OnlyKey device accepts at most MAX_ED25519_PAYLOAD bytes.
        // Reject here with a clear wrong-data error rather than forwarding to the
        // transport layer and receiving an opaque conditions_not_satisfied.
        if apdu.data.len() > MAX_ED25519_PAYLOAD {
            eprintln!(
                "onlykey-vcard [openpgp]: COMPUTE DIGITAL SIGNATURE rejected: \
                 payload {} bytes exceeds Ed25519 device limit ({} bytes)",
                apdu.data.len(),
                MAX_ED25519_PAYLOAD
            );
            return RApdu::wrong_data();
        }
        let op = SignOp::Ed25519 {
            slot: SLOT_SIG,
            payload: apdu.data.clone(),
        };
        match device.sign(op, display, timeout) {
            Ok(Signature::Ed25519(bytes)) => {
                self.sig_counter = self.sig_counter.saturating_add(1);
                // Persist every COUNTER_BATCH increments.
                // Also persist on the very first signature after a fresh install
                // (sig_counter == 1): on a fresh device there is no counter file,
                // load_persisted_counter returns 0, and the first increment reaches 1.
                // Note: after any recovery from disk, load_persisted_counter returns
                // stored + COUNTER_RECOVERY_MARGIN (>= 15), so sig_counter never
                // reaches 1 post-recovery and this branch is unreachable in that case.
                if self.sig_counter % COUNTER_BATCH == 0 || self.sig_counter == 1 {
                    save_persisted_counter(self.serial, self.sig_counter);
                }
                RApdu::ok(bytes.to_vec())
            }
            Ok(_) => {
                // The device returned a signature type other than Ed25519 for
                // SLOT_SIG. This should never happen if slots.toml is correct.
                eprintln!(
                    "onlykey-vcard [openpgp]: COMPUTE DIGITAL SIGNATURE: \
                     unexpected signature variant from slot {}; \
                     expected Ed25519 -- check slots.toml",
                    SLOT_SIG
                );
                RApdu::conditions_not_satisfied()
            }
            Err(TransportError::ChallengeTimeout) => RApdu::security_not_satisfied(),
            Err(e) => {
                eprintln!(
                    "onlykey-vcard [openpgp]: COMPUTE DIGITAL SIGNATURE: \
                     device error: {}",
                    e
                );
                RApdu::conditions_not_satisfied()
            }
        }
    }

    fn cmd_decipher(
        &mut self,
        apdu: &Apdu,
        device: &OnlyKeyDevice,
        display: &dyn ChallengeDisplay,
        timeout: Duration,
    ) -> RApdu {
        if !self.pin2_verified {
            return RApdu::security_not_satisfied();
        }
        // parse_decipher_data handles the leading 0x00 padding byte that scdaemon
        // prepends (OpenPGP Card spec sec.7.2.11) and validates the full
        // A6 { 7F49 { 86 { 32-byte peer key } } } structure. Returning wrong_data
        // here is sufficient; the pre-validation that was here previously was
        // redundant with parse_decipher_data's own checks.
        let peer_key = match parse_decipher_data(&apdu.data) {
            Some(k) => k,
            None => return RApdu::wrong_data(),
        };
        let op = DecryptOp::Curve25519 {
            slot: SLOT_DEC,
            peer_key,
        };
        match device.decrypt(op, display, timeout) {
            Ok(Decrypted::SharedSecret32(bytes)) => {
                let secret = Zeroizing::new(bytes.to_vec());
                // OpenPGP Card spec sec.7.2.11: prefix the ECDH shared secret with
                // 0x00 to distinguish it from a symmetric-key decryption response.
                RApdu::ok([&[0x00u8], secret.as_slice()].concat())
            }
            Ok(_) => {
                eprintln!(
                    "onlykey-vcard [openpgp]: DECIPHER: unexpected response variant \
                     from slot {}; expected Curve25519 shared secret -- check slots.toml",
                    SLOT_DEC
                );
                RApdu::conditions_not_satisfied()
            }
            Err(TransportError::ChallengeTimeout) => RApdu::security_not_satisfied(),
            Err(e) => {
                eprintln!("onlykey-vcard [openpgp]: DECIPHER: device error: {}", e);
                RApdu::conditions_not_satisfied()
            }
        }
    }

    fn cmd_internal_auth(
        &mut self,
        apdu: &Apdu,
        device: &OnlyKeyDevice,
        display: &dyn ChallengeDisplay,
        timeout: Duration,
    ) -> RApdu {
        if apdu.p1 != 0x00 || apdu.p2 != 0x00 {
            return RApdu::wrong_parameters();
        }
        if !self.pin2_verified {
            return RApdu::security_not_satisfied();
        }
        if apdu.data.is_empty() {
            return RApdu::wrong_data();
        }
        if apdu.data.len() > MAX_ED25519_PAYLOAD {
            eprintln!(
                "onlykey-vcard [openpgp]: INTERNAL AUTHENTICATE rejected: \
                 payload {} bytes exceeds Ed25519 device limit ({} bytes)",
                apdu.data.len(),
                MAX_ED25519_PAYLOAD
            );
            return RApdu::wrong_data();
        }
        let op = SignOp::Ed25519 {
            slot: SLOT_AUT,
            payload: apdu.data.clone(),
        };
        match device.sign(op, display, timeout) {
            Ok(Signature::Ed25519(bytes)) => RApdu::ok(bytes.to_vec()),
            Ok(_) => {
                eprintln!(
                    "onlykey-vcard [openpgp]: INTERNAL AUTHENTICATE: unexpected \
                     signature variant from slot {}; expected Ed25519 -- check slots.toml",
                    SLOT_AUT
                );
                RApdu::conditions_not_satisfied()
            }
            Err(TransportError::ChallengeTimeout) => RApdu::security_not_satisfied(),
            Err(e) => {
                eprintln!(
                    "onlykey-vcard [openpgp]: INTERNAL AUTHENTICATE: device error: {}",
                    e
                );
                RApdu::conditions_not_satisfied()
            }
        }
    }

    fn cmd_generate_key(&mut self, apdu: &Apdu, device: &OnlyKeyDevice) -> RApdu {
        // P1=0x81: read the current public key -- our implementation supports this.
        // P1=0x80: generate a new key pair on the card -- NOT supported. The OnlyKey
        // device does not accept key generation APDUs; keys must be loaded externally
        // via onlykey-tool. Rejecting P1=0x80 prevents silently returning an existing
        // key when the caller asked for a freshly generated one.
        // Other P1 values are undefined by the spec.
        match apdu.p1 {
            0x81 => {} // read public key -- fall through
            0x80 => return RApdu::func_not_supported(),
            _ => return RApdu::wrong_parameters(),
        }

        let tlv_entries = parse_tlv(&apdu.data);
        let (slot_num, algorithm) = if tlv_entries.iter().any(|(t, _)| t.as_slice() == b"\xB6") {
            (SLOT_SIG, EccAlgorithm::Ed25519)
        } else if tlv_entries.iter().any(|(t, _)| t.as_slice() == b"\xB8") {
            (SLOT_DEC, EccAlgorithm::Curve25519)
        } else if tlv_entries.iter().any(|(t, _)| t.as_slice() == b"\xA4") {
            (SLOT_AUT, EccAlgorithm::Ed25519)
        } else {
            return RApdu::wrong_data();
        };

        match device.get_ecc_pubkey_raw(KeySlot::EccStored(slot_num), algorithm) {
            Ok((_key, raw_bytes)) => RApdu::ok(tlv(b"\x7F\x49", &tlv(b"\x86", &raw_bytes))),
            Err(e) => {
                eprintln!(
                    "onlykey-vcard [openpgp]: GENERATE KEY (read): failed to read \
                     public key from slot {}: {}",
                    slot_num, e
                );
                RApdu::conditions_not_satisfied()
            }
        }
    }

    fn cmd_get_data(&mut self, apdu: &Apdu, certstore: &mut Certstore) -> RApdu {
        if apdu.p1 != 0x00 && apdu.p1 != 0x5F {
            return RApdu::wrong_parameters();
        }
        let tag = (apdu.p1 as u16) << 8 | apdu.p2 as u16;
        match tag {
            0x006E => {
                let aid_bytes = self.aid;
                // PW status, fingerprints, and key generation dates are fixed for this virtual
                // card implementation. Retry counters are not tracked -- there is no real PIN
                // management on a virtual device. Values follow OpenPGP Card spec sec.7.2.6 for
                // an uninitialized card. gpg --card-status will show these as-is.
                let pw_status: &[u8] = &[0xFF, 0x00, 0x20, 0x20, 0x03, 0x00, 0x03];
                let fingerprints = [0u8; 60];
                let gen_dates = [0u8; 12];
                let alg_sig = algorithm_attributes(EccAlgorithm::Ed25519);
                let alg_dec = algorithm_attributes(EccAlgorithm::Curve25519);
                let alg_aut = algorithm_attributes(EccAlgorithm::Ed25519);

                let mut inner = Vec::new();
                inner.extend_from_slice(&tlv(b"\x4F", &aid_bytes));
                inner.extend_from_slice(&tlv(b"\xC4", pw_status));
                inner.extend_from_slice(&tlv(b"\xC5", &fingerprints));
                inner.extend_from_slice(&tlv(b"\xCD", &gen_dates));
                inner.extend_from_slice(&tlv(b"\xC1", &alg_sig));
                inner.extend_from_slice(&tlv(b"\xC2", &alg_dec));
                inner.extend_from_slice(&tlv(b"\xC3", &alg_aut));

                let response = tlv(b"\x6E", &inner);
                self.begin_chained_response(response)
            }

            0x007A => {
                let counter = self.sig_counter;
                let counter_bytes = [(counter >> 16) as u8, (counter >> 8) as u8, counter as u8];
                let inner = tlv(b"\x93", &counter_bytes);
                RApdu::ok(tlv(b"\x7A", &inner))
            }

            0x00C4 => RApdu::ok(vec![0xFF, 0x00, 0x20, 0x20, 0x03, 0x00, 0x03]),

            0x00C5 => RApdu::ok(vec![0u8; 60]),

            0x00C1 => RApdu::ok(algorithm_attributes(EccAlgorithm::Ed25519)),

            0x00C2 => RApdu::ok(algorithm_attributes(EccAlgorithm::Curve25519)),

            0x00C3 => RApdu::ok(algorithm_attributes(EccAlgorithm::Ed25519)),

            0x0065 => {
                let inner = tlv(b"\x5B", &[]);
                RApdu::ok(tlv(b"\x65", &inner))
            }

            0x005B => {
                let name = certstore
                    .get_metadata("openpgp", "name")
                    .unwrap_or(None)
                    .unwrap_or_default();
                RApdu::ok(name.into_bytes())
            }

            0x5F50 => {
                let url = certstore
                    .get_metadata("openpgp", "url")
                    .unwrap_or(None)
                    .unwrap_or_default();
                RApdu::ok(url.into_bytes())
            }

            _ => RApdu::file_not_found(),
        }
    }

    fn cmd_put_data(&mut self, apdu: &Apdu, certstore: &mut Certstore) -> RApdu {
        let tag = (apdu.p1 as u16) << 8 | apdu.p2 as u16;
        match tag {
            0x005B => {
                // OpenPGP Card 3.4 sec.4.4.1 caps Cardholder Name at 39 bytes. Issue OnlyKey-9cfv.
                if apdu.data.len() > MAX_NAME_BYTES {
                    return RApdu::wrong_data();
                }
                let value = match std::str::from_utf8(&apdu.data) {
                    Ok(s) => s,
                    Err(_) => return RApdu::wrong_data(),
                };
                match certstore.put_metadata("openpgp", "name", value) {
                    Ok(()) => RApdu::ok_empty(),
                    Err(e) => {
                        eprintln!(
                            "onlykey-vcard [openpgp]: PUT DATA 005B (name): certstore error: {}",
                            e
                        );
                        RApdu::conditions_not_satisfied()
                    }
                }
            }

            0x5F50 => {
                // OpenPGP Card 3.4 sec.4.4.1 caps URL at 254 bytes. Issue OnlyKey-9cfv.
                if apdu.data.len() > MAX_URL_BYTES {
                    return RApdu::wrong_data();
                }
                let value = match std::str::from_utf8(&apdu.data) {
                    Ok(s) => s,
                    Err(_) => return RApdu::wrong_data(),
                };
                match certstore.put_metadata("openpgp", "url", value) {
                    Ok(()) => RApdu::ok_empty(),
                    Err(e) => {
                        eprintln!(
                            "onlykey-vcard [openpgp]: PUT DATA 5F50 (url): certstore error: {}",
                            e
                        );
                        RApdu::conditions_not_satisfied()
                    }
                }
            }

            _ => RApdu::func_not_supported(),
        }
    }

    fn cmd_get_response(&mut self) -> RApdu {
        if self.chained_response.is_empty() {
            return RApdu::ok_empty();
        }
        self.chain_depth += 1;
        // 257 = ceil(65535 / 256) + 1 empty terminal GET RESPONSE.
        // Any client that issues more than 257 GET RESPONSE calls for a single
        // chained reply is misbehaving; abort rather than loop forever.
        if self.chain_depth > 257 {
            self.chained_response.clear();
            self.chain_depth = 0;
            return RApdu {
                sw1: 0x6F,
                sw2: 0x00,
                data: vec![],
            };
        }
        if self.chained_response.len() <= 256 {
            let data: Vec<u8> = self.chained_response.drain(..).collect();
            return RApdu::ok(data);
        }
        let chunk: Vec<u8> = self.chained_response.drain(..256).collect();
        let remaining = sw2_remaining(self.chained_response.len());
        RApdu::more_data(chunk, remaining)
    }
}

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

fn parse_decipher_data(data: &[u8]) -> Option<[u8; 32]> {
    const MAX_DEPTH: usize = 8;
    // Strip leading 0x00 padding byte if present (scdaemon adds it).
    let data = if data.first() == Some(&0x00) {
        &data[1..]
    } else {
        data
    };
    // Parse A6 tag -> find 7F49 tag inside -> find 86 tag inside.
    // Depth budget: level 1 = outer, level 2 = A6 contents, level 3 = 7F49 contents.
    let outer = parse_tlv_nested(data, MAX_DEPTH);
    let inner_a6 = &outer.iter().find(|(tag, _)| tag.as_slice() == b"\xA6")?.1;
    let inner = parse_tlv_nested(inner_a6, MAX_DEPTH - 1);
    let inner_7f49 = &inner
        .iter()
        .find(|(tag, _)| tag.as_slice() == b"\x7F\x49")?
        .1;
    let innermost = parse_tlv_nested(inner_7f49, MAX_DEPTH - 2);
    let key_bytes = &innermost
        .iter()
        .find(|(tag, _)| tag.as_slice() == b"\x86")?
        .1;
    if key_bytes.len() == 32 {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(key_bytes);
        Some(arr)
    } else {
        None
    }
}

fn algorithm_attributes(alg: EccAlgorithm) -> Vec<u8> {
    match alg {
        EccAlgorithm::Ed25519 => vec![0x16, 0x2B, 0x65, 0x70],
        EccAlgorithm::Curve25519 => vec![0x12, 0x2B, 0x65, 0x6E],
        EccAlgorithm::NistP256 => vec![0x13, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07],
        // OID 1.3.132.0.10 (secp256k1), DER base-128: 2B 81 04 00 0A.
        // Previously used P-256's OID (2A 86 48 CE 3D 03 01 07) here by mistake.
        EccAlgorithm::Secp256k1 => vec![0x13, 0x2B, 0x81, 0x04, 0x00, 0x0A],
    }
}

// ---------------------------------------------------------------------------
// Applet trait implementation
// ---------------------------------------------------------------------------

impl Applet for OpenPgpApplet {
    fn aid(&self) -> &[u8] {
        &self.aid
    }

    fn atr(&self) -> &[u8] {
        &ATR
    }

    fn reset(&mut self) {
        self.pin1_verified = false;
        self.pin2_verified = false;
        self.chained_response.clear();
        self.chain_depth = 0;
        // sig_counter persists across resets per OpenPGP Card spec.
    }

    fn process(
        &mut self,
        apdu: &Apdu,
        device: &OnlyKeyDevice,
        display: &dyn ChallengeDisplay,
        timeout: Duration,
        certstore: &mut Certstore,
    ) -> RApdu {
        // Validate CLA byte (OnlyKey-370).
        if apdu.cla & 0x0C != 0 {
            return RApdu::func_not_supported();
        }
        let cla_base = apdu.cla & 0xF0;
        if cla_base != 0x00 && cla_base != 0x80 && apdu.cla != 0x10 {
            return RApdu::cla_not_supported();
        }
        // Reject reserved INS (OnlyKey-7ha).
        if apdu.ins == 0xFF {
            return RApdu::ins_not_supported();
        }
        // SELECT is allowed before selection.
        if apdu.ins == 0xA4 {
            return self.cmd_select(apdu);
        }
        // All other commands require selection.
        if !self.selected {
            return RApdu::conditions_not_satisfied();
        }
        match (apdu.ins, apdu.p1, apdu.p2) {
            (0x20, _, _) => self.cmd_verify(apdu, device),
            (0x2A, 0x9E, 0x9A) => self.cmd_compute_sig(apdu, device, display, timeout),
            (0x2A, 0x80, 0x86) => self.cmd_decipher(apdu, device, display, timeout),
            (0x88, _, _) => self.cmd_internal_auth(apdu, device, display, timeout),
            (0x47, _, _) => self.cmd_generate_key(apdu, device),
            (0xCA | 0xCB, _, _) => self.cmd_get_data(apdu, certstore),
            (0xDA | 0xDB, _, _) => self.cmd_put_data(apdu, certstore),
            (0xC0, p1, p2) if p1 == 0x00 && p2 == 0x00 => self.cmd_get_response(),
            (0xC0, _, _) => RApdu::wrong_parameters(),
            _ => RApdu::ins_not_supported(),
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apdu::tlv;

    #[test]
    fn algorithm_attributes_ed25519() {
        assert_eq!(
            algorithm_attributes(EccAlgorithm::Ed25519),
            vec![0x16, 0x2B, 0x65, 0x70]
        );
    }

    #[test]
    fn algorithm_attributes_curve25519() {
        assert_eq!(
            algorithm_attributes(EccAlgorithm::Curve25519),
            vec![0x12, 0x2B, 0x65, 0x6E]
        );
    }

    #[test]
    fn algorithm_attributes_nistp256() {
        let attrs = algorithm_attributes(EccAlgorithm::NistP256);
        assert_eq!(attrs.len(), 9);
        assert_eq!(&attrs[..2], &[0x13, 0x2A]);
    }

    #[test]
    fn begin_chained_response_small_returns_ok() {
        let mut applet = OpenPgpApplet::new();
        let data = vec![0xABu8; 100];
        let resp = applet.begin_chained_response(data.clone());
        assert_eq!(resp.sw1, 0x90);
        assert_eq!(resp.sw2, 0x00);
        assert_eq!(resp.data, data);
        assert!(applet.chained_response.is_empty());
    }

    #[test]
    fn begin_chained_response_large_chains() {
        let mut applet = OpenPgpApplet::new();
        let data = vec![0xCDu8; 400];
        let resp = applet.begin_chained_response(data.clone());
        // First chunk: SW=61xx.
        assert_eq!(resp.sw1, 0x61);
        assert_eq!(resp.data.len(), 256);
        assert_eq!(resp.data, &data[..256]);
        // Remaining 144 bytes buffered.
        assert_eq!(applet.chained_response.len(), 144);
        assert_eq!(resp.sw2, 144u8);
    }

    #[test]
    fn parse_decipher_data_valid() {
        let peer_key = [0x42u8; 32];
        // Build A6 { 7F49 { 86 { key } } }
        let inner_86 = tlv(b"\x86", &peer_key);
        let inner_7f49 = tlv(b"\x7F\x49", &inner_86);
        let outer_a6 = tlv(b"\xA6", &inner_7f49);

        let result = parse_decipher_data(&outer_a6);
        assert_eq!(result, Some(peer_key));
    }

    #[test]
    fn parse_decipher_data_with_leading_zero() {
        let peer_key = [0x55u8; 32];
        let inner_86 = tlv(b"\x86", &peer_key);
        let inner_7f49 = tlv(b"\x7F\x49", &inner_86);
        let outer_a6 = tlv(b"\xA6", &inner_7f49);
        // Prepend 0x00 as scdaemon would.
        let mut data_with_pad = vec![0x00u8];
        data_with_pad.extend_from_slice(&outer_a6);

        let result = parse_decipher_data(&data_with_pad);
        assert_eq!(result, Some(peer_key));
    }

    /// parse_decipher_data rejects a key that is not exactly 32 bytes.
    #[test]
    fn parse_decipher_data_wrong_key_length() {
        let peer_key = [0x42u8; 33]; // 33 bytes: should be rejected
        let inner_86 = tlv(b"\x86", &peer_key);
        let inner_7f49 = tlv(b"\x7F\x49", &inner_86);
        let outer_a6 = tlv(b"\xA6", &inner_7f49);
        assert_eq!(parse_decipher_data(&outer_a6), None);
    }

    /// parse_decipher_data rejects entirely empty input.
    #[test]
    fn parse_decipher_data_empty_input() {
        assert_eq!(parse_decipher_data(&[]), None);
    }

    /// parse_decipher_data rejects input that has no A6 tag.
    #[test]
    fn parse_decipher_data_missing_a6_tag() {
        // Build 7F49 { 86 { key } } without wrapping in A6.
        let peer_key = [0x11u8; 32];
        let inner_86 = tlv(b"\x86", &peer_key);
        let inner_7f49 = tlv(b"\x7F\x49", &inner_86);
        assert_eq!(parse_decipher_data(&inner_7f49), None);
    }

    #[test]
    fn cmd_get_response_empty() {
        let mut applet = OpenPgpApplet::new();
        let resp = applet.cmd_get_response();
        assert_eq!(resp.sw1, 0x90);
        assert_eq!(resp.sw2, 0x00);
        assert!(resp.data.is_empty());
    }

    #[test]
    fn aid_bytes_contain_prefix_and_serial() {
        let serial = [0x01, 0x02, 0x03, 0x04];
        let applet = OpenPgpApplet::with_serial(serial);
        let aid = applet.aid();
        assert_eq!(aid.len(), 16);
        // Fixed prefix.
        assert_eq!(&aid[..6], &[0xD2, 0x76, 0x00, 0x01, 0x24, 0x01]);
        // Version 3.4.
        assert_eq!(&aid[6..8], &[0x03, 0x04]);
        // Serial embedded at bytes 10-13.
        assert_eq!(&aid[10..14], &serial);
    }

    /// Slot constants must match documented OpenPGP-to-OnlyKey mapping.
    #[test]
    fn slot_constants_are_correct() {
        assert_eq!(SLOT_SIG, 101);
        assert_eq!(SLOT_DEC, 102);
        assert_eq!(SLOT_AUT, 103);
    }

    /// MAX_ED25519_PAYLOAD must match onlykey_hid::MAX_PAYLOAD.
    #[test]
    fn max_ed25519_payload_matches_hid_limit() {
        assert_eq!(MAX_ED25519_PAYLOAD, 768);
    }

    // --- sw2_remaining tests (OnlyKey-9gbl) ---

    /// ISO 7816-4: SW2=0x00 encodes 256 bytes remaining, not 0 or 255.
    #[test]
    fn sw2_remaining_256_encodes_as_zero() {
        assert_eq!(sw2_remaining(256), 0x00);
    }

    #[test]
    fn sw2_remaining_large_encodes_as_zero() {
        assert_eq!(sw2_remaining(512), 0x00);
        assert_eq!(sw2_remaining(65535), 0x00);
    }

    #[test]
    fn sw2_remaining_255_encodes_as_ff() {
        assert_eq!(sw2_remaining(255), 0xFF);
    }

    #[test]
    fn sw2_remaining_small_values_are_identity() {
        assert_eq!(sw2_remaining(1), 1);
        assert_eq!(sw2_remaining(100), 100);
        assert_eq!(sw2_remaining(144), 144);
    }

    /// begin_chained_response with exactly 512 bytes: after first 256-byte chunk,
    /// 256 remain — SW2 must be 0x00 (not 0xFF). Issue OnlyKey-9gbl.
    #[test]
    fn begin_chained_response_256_remaining_encodes_sw2_zero() {
        let mut applet = OpenPgpApplet::new();
        let data = vec![0xABu8; 512];
        let resp = applet.begin_chained_response(data);
        assert_eq!(resp.sw1, 0x61);
        assert_eq!(resp.data.len(), 256);
        assert_eq!(applet.chained_response.len(), 256);
        // 256 remaining must encode as SW2=0x00 per ISO 7816-4 sec.5.1.3.
        assert_eq!(resp.sw2, 0x00);
    }
}
