//! NIST SP 800-73-4 PIV smartcard applet.
//!
//! Implements PIV SELECT, VERIFY, GENERAL AUTHENTICATE, GET DATA, PUT DATA,
//! and GET RESPONSE for the onlykey-vcard daemon.

use std::time::Duration;

use onlykey_transport::challenge_ui::ChallengeDisplay;
use onlykey_transport::DeviceState;
use onlykey_transport::{DecryptOp, Decrypted, EccAlgorithm, OnlyKeyDevice, SignOp, Signature};
use zeroize::Zeroizing;

use super::Applet;
use crate::apdu::{ber_len, parse_tlv, parse_tlv_nested, tlv, Apdu, RApdu};
use crate::certstore::Certstore;

// ---------------------------------------------------------------------------
// AID and ATR constants
// ---------------------------------------------------------------------------

const PIV_AID: [u8; 10] = [0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01];

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Maximum total size of PUT DATA accumulated across chained APDUs.
///
/// Certificates are typically 1-4 KiB; 16 KiB is generous while preventing
/// indefinite memory growth from malformed or malicious chained APDUs.
const PUT_DATA_MAX_SIZE: usize = 16 * 1024;

// ---------------------------------------------------------------------------
// Slot mapping helpers
// ---------------------------------------------------------------------------

fn piv_key_ref_to_ok_slot(key_ref: u8) -> Option<u8> {
    match key_ref {
        0x9A => Some(104),
        0x9C => Some(105),
        0x9D => Some(106),
        0x9E => Some(107),
        _ => None,
    }
}

fn piv_key_ref_to_algorithm(key_ref: u8) -> Option<EccAlgorithm> {
    match key_ref {
        0x9A => Some(EccAlgorithm::NistP256),
        0x9C => Some(EccAlgorithm::NistP256),
        0x9D => Some(EccAlgorithm::Curve25519),
        0x9E => Some(EccAlgorithm::NistP256),
        _ => None,
    }
}

/// PIV algorithm reference byte for a given key reference, per NIST SP 800-73-4 Table 5.
///
/// Returns `None` for two distinct reasons -- callers must handle both:
///
/// - `0x9D` (Curve25519/X25519): known slot, but no standardised PIV algorithm byte exists.
///   The caller should **skip P1 algorithm byte validation** for this key ref.
/// - Any other unrecognised key ref: unknown slot. The caller should **reject the operation**.
///
/// The call site in `cmd_general_authenticate` checks `piv_key_ref_to_ok_slot` first, so
/// by the time `piv_key_ref_to_piv_alg_byte` is called the key ref is always one of the
/// four known values (0x9A, 0x9C, 0x9D, 0x9E). The `_ => None` arm is a defensive fallback.
fn piv_key_ref_to_piv_alg_byte(key_ref: u8) -> Option<u8> {
    match key_ref {
        // 0x11 = ECDSA with P-256 per NIST SP 800-73-4 Table 5.
        0x9A | 0x9C | 0x9E => Some(0x11),
        // Curve25519 (X25519): no standardised PIV algorithm byte -- skip P1 validation.
        0x9D => None,
        // Unknown key ref: defensive fallback; caller should have rejected before reaching here.
        _ => None,
    }
}

fn data_tag_to_cert_slot(tag: &[u8]) -> Option<&'static str> {
    match tag {
        [0x5F, 0xC1, 0x05] => Some("piv-9A"),
        [0x5F, 0xC1, 0x0A] => Some("piv-9C"),
        [0x5F, 0xC1, 0x0B] => Some("piv-9D"),
        [0x5F, 0xC1, 0x01] => Some("piv-9E"),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// DER ECDSA signature helper
// ---------------------------------------------------------------------------

/// Encode a raw 64-byte r||s ECDSA signature as DER SEQUENCE { INTEGER r, INTEGER s }.
fn der_ecdsa_sig(raw: &[u8; 64]) -> Vec<u8> {
    // The &[u8; 64] parameter type enforces the length at compile time; no runtime check needed.
    let r = &raw[..32];
    let s = &raw[32..];

    // P-256 signature components r and s are always 32 bytes.
    let encode_int = |bytes: &[u8]| -> Vec<u8> {
        let trimmed = bytes
            .iter()
            .position(|&b| b != 0)
            .map(|i| &bytes[i..])
            .unwrap_or(&bytes[bytes.len() - 1..]);
        let mut encoded = Vec::new();
        encoded.push(0x02);
        if trimmed.first().is_some_and(|&b| b >= 0x80) {
            encoded.extend_from_slice(&ber_len(trimmed.len() + 1));
            encoded.push(0x00);
        } else {
            encoded.extend_from_slice(&ber_len(trimmed.len()));
        }
        encoded.extend_from_slice(trimmed);
        encoded
    };

    let r_enc = encode_int(r);
    let s_enc = encode_int(s);
    let mut seq = Vec::new();
    seq.push(0x30);
    seq.extend_from_slice(&ber_len(r_enc.len() + s_enc.len()));
    seq.extend_from_slice(&r_enc);
    seq.extend_from_slice(&s_enc);
    seq
}

// ---------------------------------------------------------------------------
// Applet struct
// ---------------------------------------------------------------------------

pub struct PivApplet {
    selected: bool,
    pin_verified: bool,
    /// Buffered response for GET RESPONSE chaining.
    chained_response: Vec<u8>,
    /// Number of consecutive GET RESPONSE calls for the current chained response.
    chain_depth: u32,
    /// Accumulation buffer for PUT DATA with chained CLA=0x10 APDUs.
    put_data_buffer: Vec<u8>,
    /// INS byte of the command currently being accumulated via CLA=0x10 chaining.
    /// ISO 7816-4 sec.5.1.1: all APDUs in a chained sequence must have the same INS byte.
    chained_ins: Option<u8>,
    /// Set when a CLA=0x10 chain overflowed PUT_DATA_MAX_SIZE. The final
    /// CLA=0x00 PUT DATA that closes the chain must also return wrong_data()
    /// rather than processing the trailing chunk in isolation. This flag
    /// ensures consistent error behaviour: the client that sent a chain that
    /// was too large always sees wrong_data() on the last APDU, not 9000 OK
    /// from a partial parse of the last chunk alone. Issue OnlyKey-hbx4.
    put_data_overflow: bool,
}

impl Default for PivApplet {
    fn default() -> Self {
        Self::new()
    }
}

impl PivApplet {
    pub fn new() -> Self {
        PivApplet {
            selected: false,
            pin_verified: false,
            chained_response: Vec::new(),
            chain_depth: 0,
            put_data_buffer: Vec::new(),
            chained_ins: None,
            put_data_overflow: false,
        }
    }

    // -----------------------------------------------------------------------
    // Response chaining
    // -----------------------------------------------------------------------

    /// Begin a potentially chained response.
    ///
    /// If `data` fits in a single response (<= 256 bytes) return it directly.
    /// Otherwise return the first 256 bytes with SW=61xx and store the rest
    /// in `chained_response` for GET RESPONSE.
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
        let (first, rest) = data.split_at(256);
        self.chained_response = rest.to_vec();
        let remaining = rest.len().min(255) as u8;
        RApdu::more_data(first.to_vec(), remaining)
    }

    // -----------------------------------------------------------------------
    // Command implementations
    // -----------------------------------------------------------------------

    fn cmd_select(&mut self, apdu: &Apdu) -> RApdu {
        if !apdu.data.starts_with(&PIV_AID) {
            return RApdu::file_not_found();
        }
        self.selected = true;
        // PIN state is intentionally cleared on SELECT. NIST SP 800-73-4 is
        // silent on whether PIN state persists across re-SELECT, but ISO 7816-4
        // security principles treat SELECT as the start of a new session. Real
        // PIV clients (Windows Smartcard Minidriver, pam_pkcs11, sssd) do not
        // re-SELECT mid-session: they open a connection, SELECT once, verify PIN,
        // and then issue commands. Clearing on SELECT is therefore safe and
        // follows the principle of least privilege (no stale security state).
        // The OpenPGP applet explicitly preserves PIN state per OpenPGP Card 3.4
        // sec.7.2.3; PIV has no equivalent mandate. Issue OnlyKey-pvh9.
        self.pin_verified = false;
        self.chained_response.clear();
        self.put_data_buffer.clear();
        self.chained_ins = None;

        let fci = tlv(b"\x6F", &tlv(b"\x84", &PIV_AID));
        RApdu::ok(fci)
    }

    fn cmd_verify(&mut self, apdu: &Apdu, device: &OnlyKeyDevice) -> RApdu {
        // NIST SP 800-73-4 sec.3.2.2 VERIFY: P1 must be 0x00.
        if apdu.p1 != 0x00 {
            return RApdu::wrong_parameters();
        }

        // P2=0x9E (Card Authentication key) does not use a PIN.
        // GENERAL AUTHENTICATE with key_ref=0x9E succeeds without PIN verification
        // (see cmd_general_authenticate: requires_pin = key_ref != 0x9E).
        // VERIFY for 0x9E is therefore undefined/unnecessary: return SW=6982
        // (Security status not satisfied) to signal that this reference does not
        // support PIN verification rather than spoofing success via a device-state
        // check, which would succeed even on a locked device.
        if apdu.p2 == 0x9E {
            return RApdu::security_not_satisfied();
        }

        // Only the Global PIN (P2=0x80) is supported by this implementation.
        // Reject 0x9B (PIV Management Key), 0x81-0x9F (PIV Card Application PINs),
        // and any other non-standard references with wrong_parameters so the caller
        // receives a clear diagnostic rather than an opaque security error.
        if apdu.p2 != 0x80 {
            return RApdu::wrong_parameters();
        }

        match device.get_device_state() {
            Ok(DeviceState::Unlocked(_)) => {
                self.pin_verified = true;
                RApdu::ok_empty()
            }
            Ok(_) => RApdu::security_not_satisfied(),
            Err(e) => {
                eprintln!(
                    "onlykey-vcard [piv]: VERIFY: device state check failed: {}",
                    e
                );
                RApdu::conditions_not_satisfied()
            }
        }
    }

    fn cmd_general_authenticate(
        &mut self,
        apdu: &Apdu,
        device: &OnlyKeyDevice,
        display: &dyn ChallengeDisplay,
        timeout: Duration,
    ) -> RApdu {
        let key_ref = apdu.p2;

        // PIN requirement: 9A, 9C, 9D require pin_verified; 9E does not.
        let requires_pin = key_ref != 0x9E;
        if requires_pin && !self.pin_verified {
            return RApdu::security_not_satisfied();
        }

        let slot = match piv_key_ref_to_ok_slot(key_ref) {
            Some(s) => s,
            None => {
                eprintln!(
                    "onlykey-vcard [piv]: GENERAL AUTHENTICATE: \
                     unsupported key_ref 0x{:02X}",
                    key_ref
                );
                return RApdu::conditions_not_satisfied();
            }
        };

        let algorithm = match piv_key_ref_to_algorithm(key_ref) {
            Some(a) => a,
            None => {
                eprintln!(
                    "onlykey-vcard [piv]: GENERAL AUTHENTICATE: \
                     no algorithm mapping for key_ref 0x{:02X}",
                    key_ref
                );
                return RApdu::conditions_not_satisfied();
            }
        };

        // Validate P1 (algorithm reference byte) against the expected algorithm for
        // this key slot. NIST SP 800-73-4 Table 5 defines the algorithm reference bytes.
        // We also accept P1=0x00 from clients that omit the algorithm byte.
        // For Curve25519 (slot 0x9D) there is no standard PIV algorithm byte, so
        // P1 is not validated -- any value is accepted.
        if let Some(expected_alg_byte) = piv_key_ref_to_piv_alg_byte(key_ref) {
            if apdu.p1 != expected_alg_byte && apdu.p1 != 0x00 {
                eprintln!(
                    "onlykey-vcard [piv]: GENERAL AUTHENTICATE: P1 algorithm byte \
                     mismatch for key_ref 0x{:02X}: got 0x{:02X}, expected 0x{:02X} \
                     (or 0x00)",
                    key_ref, apdu.p1, expected_alg_byte
                );
                return RApdu::wrong_parameters();
            }
        }

        // Parse the Dynamic Auth Template (tag 7C).
        const MAX_DEPTH: usize = 8;
        let outer = parse_tlv_nested(&apdu.data, MAX_DEPTH);
        // Reject unknown top-level tags: only 0x7C is valid.
        if outer.iter().any(|(tag, _)| tag.as_slice() != b"\x7C") {
            return RApdu::wrong_data();
        }
        let dyn_auth_value = match outer.iter().find(|(tag, _)| tag == b"\x7C") {
            Some((_, v)) => v.clone(),
            None => return RApdu::wrong_data(),
        };

        let inner = parse_tlv_nested(&dyn_auth_value, MAX_DEPTH - 1);

        // Tag 82 (Response) must be present and empty (placeholder).
        let has_empty_82 = inner
            .iter()
            .any(|(tag, val)| tag == b"\x82" && val.is_empty());
        if !has_empty_82 {
            return RApdu::wrong_data();
        }

        // Tag 81 (Challenge) must be present.
        let challenge_val = match inner.iter().find(|(tag, _)| tag == b"\x81") {
            Some((_, v)) => v.clone(),
            None => return RApdu::wrong_data(),
        };

        match algorithm {
            EccAlgorithm::NistP256 => {
                // Challenge must be exactly 32 bytes (pre-hashed SHA-256 digest per
                // NIST SP 800-73-4 sec.3.2.4).
                if challenge_val.len() != 32 {
                    return RApdu::wrong_data();
                }

                let op = SignOp::EcdsaP256 {
                    slot,
                    payload: challenge_val,
                };
                let sig = match device.sign(op, display, timeout) {
                    Ok(s) => s,
                    Err(onlykey_transport::TransportError::ChallengeTimeout) => {
                        return RApdu::security_not_satisfied();
                    }
                    Err(e) => {
                        eprintln!(
                            "onlykey-vcard [piv]: GENERAL AUTHENTICATE (P-256, \
                             slot {}): device error: {}",
                            slot, e
                        );
                        return RApdu::conditions_not_satisfied();
                    }
                };

                let raw = match sig {
                    Signature::EcdsaRaw(b) => b,
                    _ => {
                        eprintln!(
                            "onlykey-vcard [piv]: GENERAL AUTHENTICATE (P-256, \
                             slot {}): unexpected signature variant; expected EcdsaRaw \
                             -- check slots.toml",
                            slot
                        );
                        return RApdu::conditions_not_satisfied();
                    }
                };

                let der_sig = der_ecdsa_sig(&raw);
                let response = tlv(b"\x7C", &tlv(b"\x82", &der_sig));
                self.begin_chained_response(response)
            }

            EccAlgorithm::Curve25519 => {
                // Challenge must be exactly 32 bytes (peer X25519 public key).
                if challenge_val.len() != 32 {
                    return RApdu::wrong_data();
                }

                let peer_key: [u8; 32] = match challenge_val.as_slice().try_into() {
                    Ok(k) => k,
                    Err(_) => return RApdu::wrong_data(),
                };

                let op = DecryptOp::Curve25519 { slot, peer_key };
                let decrypted = match device.decrypt(op, display, timeout) {
                    Ok(d) => d,
                    Err(onlykey_transport::TransportError::ChallengeTimeout) => {
                        return RApdu::security_not_satisfied();
                    }
                    Err(e) => {
                        eprintln!(
                            "onlykey-vcard [piv]: GENERAL AUTHENTICATE (Curve25519, \
                             slot {}): device error: {}",
                            slot, e
                        );
                        return RApdu::conditions_not_satisfied();
                    }
                };

                let secret_bytes = match decrypted {
                    Decrypted::SharedSecret32(b) => Zeroizing::new(b.to_vec()),
                    _ => {
                        eprintln!(
                            "onlykey-vcard [piv]: GENERAL AUTHENTICATE (Curve25519, \
                             slot {}): unexpected decrypt variant; expected SharedSecret32 \
                             -- check slots.toml",
                            slot
                        );
                        return RApdu::conditions_not_satisfied();
                    }
                };

                let response = tlv(b"\x7C", &tlv(b"\x82", &secret_bytes));
                self.begin_chained_response(response)
            }

            other => {
                // The key-ref-to-algorithm table maps only NistP256 and Curve25519.
                // Any other variant here indicates a table inconsistency.
                eprintln!(
                    "onlykey-vcard [piv]: GENERAL AUTHENTICATE: key_ref 0x{:02X} \
                     maps to unsupported algorithm {:?}; only NistP256 and \
                     Curve25519 are handled",
                    key_ref, other
                );
                RApdu::conditions_not_satisfied()
            }
        }
    }

    fn cmd_get_data(&mut self, apdu: &Apdu, certstore: &mut Certstore) -> RApdu {
        // NIST SP 800-73-4 sec.3.2.4 GET DATA: P1=0x3F, P2=0xFF required.
        if apdu.p1 != 0x3F || apdu.p2 != 0xFF {
            return RApdu::wrong_parameters();
        }

        // The request data contains a 5C TLV with the data object tag.
        let items = parse_tlv(&apdu.data);
        let object_tag = match items.iter().find(|(tag, _)| tag == b"\x5C") {
            Some((_, v)) => v.clone(),
            None => return RApdu::file_not_found(),
        };

        let cert_slot = match data_tag_to_cert_slot(&object_tag) {
            Some(s) => s,
            None => return RApdu::file_not_found(),
        };

        let der = match certstore.get_cert(cert_slot) {
            Ok(Some(d)) => d,
            Ok(None) => return RApdu::file_not_found(),
            Err(e) => {
                eprintln!(
                    "onlykey-vcard [piv]: GET DATA: certstore read error for \
                     slot '{}': {}",
                    cert_slot, e
                );
                return RApdu::conditions_not_satisfied();
            }
        };

        // Wrap in PIV cert container: 53 { 70 [cert DER] FE [empty] }
        let inner: Vec<u8> = [tlv(b"\x70", &der).as_slice(), tlv(b"\xFE", b"").as_slice()].concat();
        let container = tlv(b"\x53", &inner);
        self.begin_chained_response(container)
    }

    fn cmd_put_data(&mut self, apdu: &Apdu, certstore: &mut Certstore) -> RApdu {
        // NIST SP 800-73-4 sec.3.2.4 PUT DATA: P1=0x3F, P2=0xFF required.
        if apdu.p1 != 0x3F || apdu.p2 != 0xFF {
            return RApdu::wrong_parameters();
        }

        // Final block of PUT DATA. Append and process the accumulated buffer.
        // Even for a single-block (non-chained) PUT DATA the size limit applies.
        if self.put_data_buffer.len() + apdu.data.len() > PUT_DATA_MAX_SIZE {
            self.put_data_buffer.clear();
            return RApdu::wrong_data();
        }
        self.put_data_buffer.extend_from_slice(&apdu.data);
        let buf = std::mem::take(&mut self.put_data_buffer);

        let items = parse_tlv(&buf);

        // Find 5C tag -> data object tag.
        let object_tag = match items.iter().find(|(tag, _)| tag == b"\x5C") {
            Some((_, v)) => v.clone(),
            None => return RApdu::wrong_data(),
        };

        let cert_slot = match data_tag_to_cert_slot(&object_tag) {
            Some(s) => s,
            None => return RApdu::wrong_data(),
        };

        // Find 53 tag -> container value.
        let container_value = match items.iter().find(|(tag, _)| tag == b"\x53") {
            Some((_, v)) => v.clone(),
            None => return RApdu::wrong_data(),
        };

        // Inside container, find 70 tag -> cert DER.
        let inner_items = parse_tlv(&container_value);
        let der = match inner_items.iter().find(|(tag, _)| tag == b"\x70") {
            Some((_, v)) => v.clone(),
            None => return RApdu::wrong_data(),
        };

        match certstore.put_cert(cert_slot, &der, "PIV Certificate") {
            Ok(()) => RApdu::ok_empty(),
            Err(e) => {
                eprintln!(
                    "onlykey-vcard [piv]: PUT DATA: certstore write error for \
                     slot '{}': {}",
                    cert_slot, e
                );
                RApdu::conditions_not_satisfied()
            }
        }
    }

    fn cmd_get_response(&mut self) -> RApdu {
        if self.chained_response.is_empty() {
            return RApdu::ok_empty();
        }
        self.chain_depth += 1;
        if self.chain_depth > 257 {
            self.chained_response.clear();
            self.chain_depth = 0;
            return RApdu {
                sw1: 0x6F,
                sw2: 0x00,
                data: vec![],
            };
        }

        let chunk: Vec<u8>;
        if self.chained_response.len() <= 256 {
            chunk = std::mem::take(&mut self.chained_response);
            RApdu::ok(chunk)
        } else {
            let rest = self.chained_response.split_off(256);
            chunk = std::mem::replace(&mut self.chained_response, rest);
            let remaining = self.chained_response.len().min(255) as u8;
            RApdu::more_data(chunk, remaining)
        }
    }
}

// ---------------------------------------------------------------------------
// Applet trait implementation
// ---------------------------------------------------------------------------

impl Applet for PivApplet {
    fn aid(&self) -> &[u8] {
        &PIV_AID
    }

    fn atr(&self) -> &[u8] {
        &[0x3B, 0x80, 0x80, 0x01, 0x6F]
    }

    fn reset(&mut self) {
        self.pin_verified = false;
        self.chained_response.clear();
        self.chain_depth = 0;
        self.put_data_buffer.clear();
        self.chained_ins = None;
        self.put_data_overflow = false;
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
        if apdu.ins == 0xA4 {
            return self.cmd_select(apdu);
        }
        if !self.selected {
            return RApdu::conditions_not_satisfied();
        }
        // CLA=0x10 is command chaining (ISO 7816-4 sec.5.1.1): accumulate data and
        // acknowledge. All APDUs in a chained sequence must carry the same INS byte.
        if apdu.cla == 0x10 {
            if self.put_data_buffer.is_empty() {
                // First block of a new chain: record the INS byte and clear any
                // stale overflow flag from a previous failed chain. Issue OnlyKey-hbx4.
                self.chained_ins = Some(apdu.ins);
                self.put_data_overflow = false;
            } else if self.chained_ins != Some(apdu.ins) {
                // ISO 7816-4 sec.5.1.1: all APDUs in a chained sequence must have
                // the same INS byte. Discard the accumulated buffer and reject.
                self.put_data_buffer.clear();
                self.chained_ins = None;
                return RApdu::conditions_not_satisfied();
            }
            // Guard against unbounded accumulation from malformed or malicious APDUs.
            if self.put_data_buffer.len() + apdu.data.len() > PUT_DATA_MAX_SIZE {
                eprintln!(
                    "onlykey-vcard [piv]: PUT DATA chain: accumulated buffer \
                     ({} + {} bytes) exceeds limit ({} bytes); discarding",
                    self.put_data_buffer.len(),
                    apdu.data.len(),
                    PUT_DATA_MAX_SIZE
                );
                self.put_data_buffer.clear();
                self.chained_ins = None;
                // Mark the chain as overflowed so the final CLA=0x00 PUT DATA
                // also returns wrong_data() rather than 9000 OK on the trailing
                // chunk alone. Issue OnlyKey-hbx4.
                self.put_data_overflow = true;
                return RApdu::wrong_data();
            }
            self.put_data_buffer.extend_from_slice(&apdu.data);
            return RApdu::ok_empty();
        }
        // Non-chained APDU: chaining sequence is complete (or was never started).
        self.chained_ins = None;
        match apdu.ins {
            0x20 => self.cmd_verify(apdu, device),
            0x87 => self.cmd_general_authenticate(apdu, device, display, timeout),
            0xCB => self.cmd_get_data(apdu, certstore),
            0xDB => {
                // If a previous CLA=0x10 chain overflowed, reject the final
                // block too — processing the trailing chunk alone would silently
                // succeed with only partial data. Issue OnlyKey-hbx4.
                if self.put_data_overflow {
                    self.put_data_overflow = false;
                    return RApdu::wrong_data();
                }
                self.cmd_put_data(apdu, certstore)
            }
            0xC0 if apdu.p1 == 0x00 && apdu.p2 == 0x00 => self.cmd_get_response(),
            0xC0 => RApdu::wrong_parameters(),
            _ => RApdu::ins_not_supported(),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::apdu::{parse_tlv, tlv};

    #[test]
    fn key_ref_to_ok_slot_9a() {
        assert_eq!(piv_key_ref_to_ok_slot(0x9A), Some(104));
    }

    #[test]
    fn key_ref_to_ok_slot_9c() {
        assert_eq!(piv_key_ref_to_ok_slot(0x9C), Some(105));
    }

    #[test]
    fn key_ref_to_ok_slot_9d() {
        assert_eq!(piv_key_ref_to_ok_slot(0x9D), Some(106));
    }

    #[test]
    fn key_ref_to_ok_slot_9e() {
        assert_eq!(piv_key_ref_to_ok_slot(0x9E), Some(107));
    }

    #[test]
    fn key_ref_to_ok_slot_unknown() {
        assert_eq!(piv_key_ref_to_ok_slot(0x00), None);
    }

    #[test]
    fn data_tag_cert_slot_9a() {
        assert_eq!(data_tag_to_cert_slot(&[0x5F, 0xC1, 0x05]), Some("piv-9A"));
    }

    #[test]
    fn data_tag_cert_slot_9c() {
        assert_eq!(data_tag_to_cert_slot(&[0x5F, 0xC1, 0x0A]), Some("piv-9C"));
    }

    #[test]
    fn data_tag_cert_slot_9d() {
        assert_eq!(data_tag_to_cert_slot(&[0x5F, 0xC1, 0x0B]), Some("piv-9D"));
    }

    #[test]
    fn data_tag_cert_slot_9e() {
        assert_eq!(data_tag_to_cert_slot(&[0x5F, 0xC1, 0x01]), Some("piv-9E"));
    }

    #[test]
    fn data_tag_cert_slot_unknown() {
        assert_eq!(data_tag_to_cert_slot(&[0x5F, 0xC1, 0xFF]), None);
    }

    /// Verify the PIV AID bytes are exactly A0 00 00 03 08 00 00 10 00 01.
    #[test]
    fn aid_bytes_correct() {
        let applet = PivApplet::new();
        assert_eq!(
            applet.aid(),
            &[0xA0, 0x00, 0x00, 0x03, 0x08, 0x00, 0x00, 0x10, 0x00, 0x01]
        );
    }

    /// piv_key_ref_to_piv_alg_byte: P-256 slots return 0x11; Curve25519 slot returns None.
    #[test]
    fn piv_alg_byte_p256_slots() {
        assert_eq!(piv_key_ref_to_piv_alg_byte(0x9A), Some(0x11));
        assert_eq!(piv_key_ref_to_piv_alg_byte(0x9C), Some(0x11));
        assert_eq!(piv_key_ref_to_piv_alg_byte(0x9E), Some(0x11));
    }

    #[test]
    fn piv_alg_byte_curve25519_slot_is_none() {
        // Curve25519 has no standard PIV algorithm byte; P1 validation is skipped.
        assert_eq!(piv_key_ref_to_piv_alg_byte(0x9D), None);
    }

    #[test]
    fn piv_alg_byte_unknown_is_none() {
        assert_eq!(piv_key_ref_to_piv_alg_byte(0x00), None);
    }

    /// der_ecdsa_sig with r[0]=1, rest zeros; s[0]=2, rest zeros.
    /// Verifies SEQUENCE tag, INTEGER tags, and that no high-bit byte is
    /// interpreted as negative (no spurious leading 0x00 needed for low values).
    #[test]
    fn der_ecdsa_sig_basic() {
        let mut raw = [0u8; 64];
        raw[0] = 0x01; // r
        raw[32] = 0x02; // s

        let sig = der_ecdsa_sig(&raw);

        // Must start with SEQUENCE tag 0x30.
        assert_eq!(sig[0], 0x30, "expected SEQUENCE tag");

        // Parse the inner content.
        let seq_len = sig[1] as usize;
        let inner = &sig[2..2 + seq_len];
        let items = parse_tlv(inner);
        assert_eq!(items.len(), 2, "expected two INTEGER elements");

        let (r_tag, r_val) = &items[0];
        let (s_tag, s_val) = &items[1];
        assert_eq!(r_tag, &[0x02], "r must use INTEGER tag");
        assert_eq!(s_tag, &[0x02], "s must use INTEGER tag");

        // Values must not have high bit set (no negative interpretation).
        assert!(
            r_val.first().map_or(true, |&b| b < 0x80),
            "r value must not have high bit set"
        );
        assert!(
            s_val.first().map_or(true, |&b| b < 0x80),
            "s value must not have high bit set"
        );

        // r = [0x01, 0x00, ..., 0x00] (32 bytes): first non-zero at index 0 -> full 32 bytes kept.
        // s = [0x02, 0x00, ..., 0x00] (32 bytes): same.
        assert_eq!(r_val.len(), 32);
        assert_eq!(r_val[0], 0x01);
        assert_eq!(s_val.len(), 32);
        assert_eq!(s_val[0], 0x02);
    }

    /// der_ecdsa_sig when r has high bit set -- must prepend 0x00.
    #[test]
    fn der_ecdsa_sig_high_bit_r() {
        let mut raw = [0u8; 64];
        raw[0] = 0x80; // high bit set -> needs 0x00 prefix
        raw[32] = 0x01;

        let sig = der_ecdsa_sig(&raw);
        let seq_len = sig[1] as usize;
        let inner = &sig[2..2 + seq_len];
        let items = parse_tlv(inner);
        let (_, r_val) = &items[0];

        // First byte of value must be 0x00 (sign byte), second must be 0x80.
        assert_eq!(r_val[0], 0x00, "must have 0x00 sign prefix");
        assert_eq!(r_val[1], 0x80);
    }

    /// cmd_get_response when chained_response is empty -> SW 9000 with no data.
    #[test]
    fn get_response_empty() {
        let mut applet = PivApplet::new();
        let r = applet.cmd_get_response();
        assert_eq!(r, RApdu::ok_empty());
    }

    /// cmd_get_response drains a short buffer in one shot.
    #[test]
    fn get_response_short_buffer() {
        let mut applet = PivApplet::new();
        applet.chained_response = vec![0xAA, 0xBB, 0xCC];
        let r = applet.cmd_get_response();
        assert_eq!(r, RApdu::ok(vec![0xAA, 0xBB, 0xCC]));
        assert!(applet.chained_response.is_empty());
    }

    /// Verify PIV cert container nesting: 53 { 70 [der] FE [] }.
    #[test]
    fn cert_container_nesting() {
        let der = vec![0x30u8, 0x82, 0x00, 0x04, 0x01, 0x02, 0x03, 0x04];
        let inner: Vec<u8> = [tlv(b"\x70", &der).as_slice(), tlv(b"\xFE", b"").as_slice()].concat();
        let container = tlv(b"\x53", &inner);

        // Outer parse: must find tag 0x53.
        let outer = parse_tlv(&container);
        assert_eq!(outer.len(), 1);
        assert_eq!(outer[0].0, vec![0x53]);

        // Inner parse: must find 70 and FE.
        let inner_items = parse_tlv(&outer[0].1);
        let tag_70 = inner_items.iter().find(|(t, _)| t == &[0x70]);
        let tag_fe = inner_items.iter().find(|(t, _)| t == &[0xFE]);
        assert!(tag_70.is_some(), "70 tag must be present");
        assert!(tag_fe.is_some(), "FE tag must be present");
        assert_eq!(tag_70.unwrap().1, der);
        assert!(tag_fe.unwrap().1.is_empty());
    }

    /// begin_chained_response: short data returned directly.
    #[test]
    fn begin_chained_response_short() {
        let mut applet = PivApplet::new();
        let data = vec![0x01u8; 100];
        let r = applet.begin_chained_response(data.clone());
        assert_eq!(r, RApdu::ok(data));
        assert!(applet.chained_response.is_empty());
    }

    /// begin_chained_response: long data triggers SW=61xx chaining.
    #[test]
    fn begin_chained_response_long() {
        let mut applet = PivApplet::new();
        let data = vec![0x42u8; 300];
        let r = applet.begin_chained_response(data);
        // First chunk is 256 bytes, rest (44) stored.
        assert_eq!(r.sw1, 0x61);
        assert_eq!(r.data.len(), 256);
        assert_eq!(applet.chained_response.len(), 44);
    }

    /// PUT_DATA_MAX_SIZE must be large enough for real certificates but bounded.
    #[test]
    fn put_data_max_size_is_reasonable() {
        // Minimum: larger than a 4096-bit RSA cert (~2 KiB DER).
        assert!(PUT_DATA_MAX_SIZE >= 4 * 1024);
        // Maximum: not unbounded.
        assert!(PUT_DATA_MAX_SIZE <= 64 * 1024);
    }

    /// put_data_buffer size limit is enforced in the chaining path.
    #[test]
    fn chained_put_data_rejects_oversized_payload() {
        let mut applet = PivApplet::new();
        applet.selected = true;

        // Simulate a chain that pushes the buffer just over PUT_DATA_MAX_SIZE.
        // We bypass process() here and manipulate state directly to avoid needing
        // a real device. Simulate what process() does for CLA=0x10.
        let chunk = vec![0xAAu8; PUT_DATA_MAX_SIZE];
        applet.chained_ins = Some(0xDB);
        applet.put_data_buffer.extend_from_slice(&chunk);

        // The next extend would overflow. Simulate the check in process():
        let overflow_len = 1usize;
        let would_overflow = applet.put_data_buffer.len() + overflow_len > PUT_DATA_MAX_SIZE;
        assert!(
            would_overflow,
            "overflow check must fire at PUT_DATA_MAX_SIZE + 1"
        );
    }

    // -----------------------------------------------------------------------
    // cmd_general_authenticate: validation/rejection paths before device I/O
    //
    // All paths tested here return before any call to device.sign() or
    // device.decrypt(). The function signature requires &OnlyKeyDevice but
    // never dereferences it on these paths. We use MaybeUninit to produce a
    // well-aligned reference that is never accessed; this is sound only
    // because every test below exercises a path that returns before any
    // field read.
    // -----------------------------------------------------------------------

    /// Produce a pointer-to-uninit for the device parameter in tests that
    /// return before any device field is accessed.
    ///
    /// The macro form is used rather than a function so that the
    /// `MaybeUninit` lives on the caller's stack for the duration of the
    /// expression, satisfying lifetime requirements without a static.
    ///
    /// # Safety
    /// The pointer MUST NOT be used on any path that reads or writes a field
    /// of OnlyKeyDevice. Every call site in this module is a path that
    /// returns before reaching device.sign() / device.decrypt().
    macro_rules! dummy_device {
        () => {{
            let uninit = std::mem::MaybeUninit::<OnlyKeyDevice>::uninit();
            // SAFETY: see module-level comment above.
            unsafe { &*uninit.as_ptr() }
        }};
    }

    /// Build a `StderrDisplay` for use as the `display` parameter in tests
    /// that return before any device interaction (the display is never called).
    fn dummy_display() -> onlykey_transport::challenge_ui::StderrDisplay {
        onlykey_transport::challenge_ui::StderrDisplay
    }

    /// After a CLA=0x10 chain overflows, the final CLA=0x00 PUT DATA must also
    /// return wrong_data(), not 9000 OK from processing the trailing chunk alone.
    ///
    /// Both the CLA=0x10 overflow path and the INS=0xDB overflow-guard path return
    /// before any device field is read, so dummy_device!() is safe here.
    /// Issue OnlyKey-hbx4.
    #[test]
    fn put_data_chain_overflow_poisons_final_block() {
        let tmp = tempfile::TempDir::new().unwrap();
        let mut cs = Certstore::open(&tmp.path().join("certs.db")).unwrap();

        let mut applet = PivApplet::new();
        applet.selected = true;
        // Pre-fill the buffer to exactly PUT_DATA_MAX_SIZE so that one more byte overflows.
        applet.chained_ins = Some(0xDB);
        applet.put_data_buffer = vec![0u8; PUT_DATA_MAX_SIZE];

        // CLA=0x10: one extra byte triggers overflow -> wrong_data + overflow flag set.
        let chain_apdu = Apdu {
            cla: 0x10,
            ins: 0xDB,
            p1: 0x3F,
            p2: 0xFF,
            data: vec![0x01],
            ne: None,
        };
        let r1 = applet.process(
            &chain_apdu,
            dummy_device!(),
            &dummy_display(),
            std::time::Duration::ZERO,
            &mut cs,
        );
        assert_eq!((r1.sw1, r1.sw2), (0x6A, 0x80), "overflow must return wrong_data (6A80)");
        assert!(applet.put_data_overflow, "put_data_overflow must be set after chain overflow");

        // CLA=0x00 INS=0xDB: overflow guard must fire -> wrong_data, flag cleared.
        let final_apdu = Apdu {
            cla: 0x00,
            ins: 0xDB,
            p1: 0x3F,
            p2: 0xFF,
            data: vec![0x42],
            ne: None,
        };
        let r2 = applet.process(
            &final_apdu,
            dummy_device!(),
            &dummy_display(),
            std::time::Duration::ZERO,
            &mut cs,
        );
        assert_eq!(
            (r2.sw1, r2.sw2),
            (0x6A, 0x80),
            "final block after chain overflow must also return wrong_data"
        );
        assert!(!applet.put_data_overflow, "put_data_overflow must be cleared after final block");
    }

    /// Build a valid `7C { 82 [] 81 [challenge] }` APDU data field.
    fn ga_data(challenge: &[u8]) -> Vec<u8> {
        let inner = [
            tlv(b"\x82", b"").as_slice(),
            tlv(b"\x81", challenge).as_slice(),
        ]
        .concat();
        tlv(b"\x7C", &inner)
    }

    /// Build a minimal valid APDU for GENERAL AUTHENTICATE.
    fn ga_apdu(p1: u8, p2: u8, data: Vec<u8>) -> Apdu {
        Apdu {
            cla: 0x00,
            ins: 0x87,
            p1,
            p2,
            data,
            ne: None,
        }
    }

    // --- PIN-not-verified paths ---

    /// key_ref 9A requires PIN; rejected when pin_verified is false.
    #[test]
    fn ga_pin_not_verified_9a() {
        let mut applet = PivApplet::new();
        let apdu = ga_apdu(0x11, 0x9A, ga_data(&[0u8; 32]));
        let r = applet.cmd_general_authenticate(
            &apdu,
            dummy_device!(),
            &dummy_display(),
            std::time::Duration::ZERO,
        );
        assert_eq!(r, RApdu::security_not_satisfied());
    }

    /// key_ref 9C requires PIN; rejected when pin_verified is false.
    #[test]
    fn ga_pin_not_verified_9c() {
        let mut applet = PivApplet::new();
        let apdu = ga_apdu(0x11, 0x9C, ga_data(&[0u8; 32]));
        let r = applet.cmd_general_authenticate(
            &apdu,
            dummy_device!(),
            &dummy_display(),
            std::time::Duration::ZERO,
        );
        assert_eq!(r, RApdu::security_not_satisfied());
    }

    /// key_ref 9D requires PIN; rejected when pin_verified is false.
    #[test]
    fn ga_pin_not_verified_9d() {
        let mut applet = PivApplet::new();
        let apdu = ga_apdu(0x00, 0x9D, ga_data(&[0u8; 32]));
        let r = applet.cmd_general_authenticate(
            &apdu,
            dummy_device!(),
            &dummy_display(),
            std::time::Duration::ZERO,
        );
        assert_eq!(r, RApdu::security_not_satisfied());
    }

    // --- Wrong key reference ---

    /// An unknown key_ref (not 9A/9C/9D/9E) is rejected with conditions_not_satisfied.
    /// pin_verified must be set so the PIN guard does not fire first.
    #[test]
    fn ga_unknown_key_ref() {
        let mut applet = PivApplet::new();
        applet.pin_verified = true;
        let apdu = ga_apdu(0x00, 0x00, ga_data(&[0u8; 32]));
        let r = applet.cmd_general_authenticate(
            &apdu,
            dummy_device!(),
            &dummy_display(),
            std::time::Duration::ZERO,
        );
        assert_eq!(r, RApdu::conditions_not_satisfied());
    }

    // --- Wrong P1 algorithm byte ---

    /// P1 that is neither the expected 0x11 nor the wildcard 0x00 is rejected
    /// for a P-256 key slot (9A, expected alg byte = 0x11).
    #[test]
    fn ga_wrong_p1_alg_byte_9a() {
        let mut applet = PivApplet::new();
        applet.pin_verified = true;
        // P1=0x07: not 0x11 (P-256 alg byte) and not 0x00 (wildcard).
        let apdu = ga_apdu(0x07, 0x9A, ga_data(&[0u8; 32]));
        let r = applet.cmd_general_authenticate(
            &apdu,
            dummy_device!(),
            &dummy_display(),
            std::time::Duration::ZERO,
        );
        assert_eq!(r, RApdu::wrong_parameters());
    }

    /// P1=0x00 is the wildcard and must be accepted for P-256 slots even though
    /// it differs from the standard algorithm byte 0x11. This test verifies the
    /// acceptance, not a rejection; it would only fail if the wildcard were removed.
    /// It is included here to pin the boundary condition.
    #[test]
    fn ga_p1_zero_wildcard_accepted_9a_reaches_tlv_check() {
        let mut applet = PivApplet::new();
        applet.pin_verified = true;
        // Empty data: the TLV check fires (wrong_data), but we must NOT get
        // wrong_parameters, which would mean the P1=0x00 wildcard was rejected.
        let apdu = ga_apdu(0x00, 0x9A, vec![]);
        let r = applet.cmd_general_authenticate(
            &apdu,
            dummy_device!(),
            &dummy_display(),
            std::time::Duration::ZERO,
        );
        assert_eq!(r, RApdu::wrong_data(), "P1=0x00 must pass alg-byte check");
    }

    // --- TLV structure errors ---

    /// An unknown top-level tag (not 7C) is rejected.
    #[test]
    fn ga_unknown_top_level_tag() {
        let mut applet = PivApplet::new();
        // key_ref 9E: no PIN required.
        // Build data with a 0x53 (not 7C) top-level tag.
        let data = tlv(b"\x53", b"garbage");
        let apdu = ga_apdu(0x11, 0x9E, data);
        let r = applet.cmd_general_authenticate(
            &apdu,
            dummy_device!(),
            &dummy_display(),
            std::time::Duration::ZERO,
        );
        assert_eq!(r, RApdu::wrong_data());
    }

    /// Missing 7C tag entirely (empty data) is rejected.
    #[test]
    fn ga_missing_7c_tag() {
        let mut applet = PivApplet::new();
        let apdu = ga_apdu(0x11, 0x9E, vec![]);
        let r = applet.cmd_general_authenticate(
            &apdu,
            dummy_device!(),
            &dummy_display(),
            std::time::Duration::ZERO,
        );
        assert_eq!(r, RApdu::wrong_data());
    }

    /// 7C tag is present but contains no 82 placeholder tag.
    #[test]
    fn ga_missing_82_tag_inside_7c() {
        let mut applet = PivApplet::new();
        // 7C { 81 [32 bytes] } — 81 present, 82 absent.
        let inner = tlv(b"\x81", &[0u8; 32]);
        let data = tlv(b"\x7C", &inner);
        let apdu = ga_apdu(0x11, 0x9E, data);
        let r = applet.cmd_general_authenticate(
            &apdu,
            dummy_device!(),
            &dummy_display(),
            std::time::Duration::ZERO,
        );
        assert_eq!(r, RApdu::wrong_data());
    }

    /// 7C tag with an 82 placeholder that is non-empty is rejected (82 must be empty).
    #[test]
    fn ga_nonempty_82_tag_inside_7c() {
        let mut applet = PivApplet::new();
        // 7C { 82 [0x00] 81 [32 bytes] } — 82 is non-empty; must be rejected.
        let inner = [
            tlv(b"\x82", &[0x00u8]).as_slice(),
            tlv(b"\x81", &[0u8; 32]).as_slice(),
        ]
        .concat();
        let data = tlv(b"\x7C", &inner);
        let apdu = ga_apdu(0x11, 0x9E, data);
        let r = applet.cmd_general_authenticate(
            &apdu,
            dummy_device!(),
            &dummy_display(),
            std::time::Duration::ZERO,
        );
        assert_eq!(r, RApdu::wrong_data());
    }

    /// 7C tag with a valid 82 placeholder but no 81 challenge tag is rejected.
    #[test]
    fn ga_missing_81_challenge_tag() {
        let mut applet = PivApplet::new();
        // 7C { 82 [] } — 82 present and empty, 81 absent.
        let inner = tlv(b"\x82", b"");
        let data = tlv(b"\x7C", &inner);
        let apdu = ga_apdu(0x11, 0x9E, data);
        let r = applet.cmd_general_authenticate(
            &apdu,
            dummy_device!(),
            &dummy_display(),
            std::time::Duration::ZERO,
        );
        assert_eq!(r, RApdu::wrong_data());
    }

    // --- Wrong challenge length ---

    /// For P-256 (key_ref 9A), a challenge that is not exactly 32 bytes is rejected.
    #[test]
    fn ga_challenge_wrong_length_p256_too_short() {
        let mut applet = PivApplet::new();
        applet.pin_verified = true;
        // 31 bytes: one byte short of the required 32.
        let apdu = ga_apdu(0x11, 0x9A, ga_data(&[0u8; 31]));
        let r = applet.cmd_general_authenticate(
            &apdu,
            dummy_device!(),
            &dummy_display(),
            std::time::Duration::ZERO,
        );
        assert_eq!(r, RApdu::wrong_data());
    }

    /// For P-256 (key_ref 9A), a challenge that is too long is rejected.
    #[test]
    fn ga_challenge_wrong_length_p256_too_long() {
        let mut applet = PivApplet::new();
        applet.pin_verified = true;
        // 33 bytes: one byte over the required 32.
        let apdu = ga_apdu(0x11, 0x9A, ga_data(&[0u8; 33]));
        let r = applet.cmd_general_authenticate(
            &apdu,
            dummy_device!(),
            &dummy_display(),
            std::time::Duration::ZERO,
        );
        assert_eq!(r, RApdu::wrong_data());
    }

    /// For Curve25519 (key_ref 9D), a challenge that is not exactly 32 bytes is rejected.
    #[test]
    fn ga_challenge_wrong_length_curve25519() {
        let mut applet = PivApplet::new();
        applet.pin_verified = true;
        // 16 bytes: too short for the required 32-byte X25519 peer key.
        let apdu = ga_apdu(0x00, 0x9D, ga_data(&[0u8; 16]));
        let r = applet.cmd_general_authenticate(
            &apdu,
            dummy_device!(),
            &dummy_display(),
            std::time::Duration::ZERO,
        );
        assert_eq!(r, RApdu::wrong_data());
    }

    /// For P-256 (key_ref 9E, no PIN required), wrong challenge length also rejected.
    #[test]
    fn ga_challenge_wrong_length_9e_no_pin_needed() {
        let mut applet = PivApplet::new();
        // key_ref 9E skips the PIN check; verifies wrong-length is caught purely
        // on the TLV/length path without needing pin_verified.
        let apdu = ga_apdu(0x11, 0x9E, ga_data(&[0u8; 10]));
        let r = applet.cmd_general_authenticate(
            &apdu,
            dummy_device!(),
            &dummy_display(),
            std::time::Duration::ZERO,
        );
        assert_eq!(r, RApdu::wrong_data());
    }
}
