//! Self-signed X.509 certificate generation for OnlyKey slots.
//!
//! Provides minimal DER encoding helpers and [`generate_self_signed`] for
//! creating self-signed X.509 v3 certificates signed directly by the device.

use std::time::Duration;

use onlykey_transport::challenge_ui::ChallengeDisplay;
use onlykey_transport::{EccAlgorithm, KeySlot, OnlyKeyDevice, SignOp, Signature};
use wolfcrypt::digest::{digest_trait::Digest, Sha256};

use crate::apdu::ber_len;

// ---------------------------------------------------------------------------
// OID constants
// ---------------------------------------------------------------------------

const OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];
const OID_EC_PUBLIC_KEY: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
const OID_P256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
const OID_ECDSA_SHA256: &[u8] = &[0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02];
const OID_CN: &[u8] = &[0x55, 0x04, 0x03];

// ---------------------------------------------------------------------------
// Public error type
// ---------------------------------------------------------------------------

/// Errors that can occur during certificate generation.
#[derive(Debug, thiserror::Error)]
pub enum CertError {
    /// A transport-level error communicating with the device.
    #[error("transport error: {0}")]
    Transport(#[from] onlykey_transport::TransportError),
    /// The device returned a signature of the wrong type for the requested algorithm.
    #[error("unexpected signature type from device")]
    WrongSignatureType,
    /// The device returned a public key of an unexpected size.
    #[error("unexpected public key size: {0} bytes")]
    WrongKeySize(usize),
    /// The given slot does not support X.509 certificate generation.
    #[error("slot {0} does not support X.509 certificate generation")]
    UnsupportedSlot(String),
}

// ---------------------------------------------------------------------------
// DER primitives
// ---------------------------------------------------------------------------

/// Wrap `content` in a DER SEQUENCE (tag `0x30`).
// Uses crate::apdu::ber_len -- do not duplicate the length encoding here.
fn der_seq(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 3 + content.len());
    out.push(0x30);
    out.extend_from_slice(&ber_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// Wrap `content` in a DER SET (tag `0x31`).
fn der_set(content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 3 + content.len());
    out.push(0x31);
    out.extend_from_slice(&ber_len(content.len()));
    out.extend_from_slice(content);
    out
}

/// Encode `bytes` as a DER OID (tag `0x06`).
fn der_oid(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 1 + bytes.len());
    out.push(0x06);
    out.extend_from_slice(&ber_len(bytes.len()));
    out.extend_from_slice(bytes);
    out
}

/// Encode a small non-negative integer as a DER INTEGER (tag `0x02`).
///
/// Strips leading zero bytes and prepends a sign byte (`0x00`) when the
/// most-significant bit of the value is set, per DER two's-complement rules.
/// Always encodes at least one value byte.
fn der_integer_u32(v: u32) -> Vec<u8> {
    let be = v.to_be_bytes();
    let trimmed = be
        .iter()
        .position(|&b| b != 0)
        .map(|i| &be[i..])
        .unwrap_or(&be[3..]);

    let mut out = Vec::new();
    out.push(0x02);
    if trimmed.first().is_some_and(|&b| b >= 0x80) {
        out.extend_from_slice(&ber_len(trimmed.len() + 1));
        out.push(0x00);
    } else {
        out.extend_from_slice(&ber_len(trimmed.len()));
    }
    out.extend_from_slice(trimmed);
    out
}

/// Encode `bits` as a DER BIT STRING (tag `0x03`) with zero unused bits.
fn der_bit_string(bits: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 3 + 1 + bits.len());
    out.push(0x03);
    out.extend_from_slice(&ber_len(bits.len() + 1));
    out.push(0x00); // unused bits = 0
    out.extend_from_slice(bits);
    out
}

/// Encode `s` as a DER UTF8String (tag `0x0C`).
fn der_utf8_string(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(1 + 3 + b.len());
    out.push(0x0C);
    out.extend_from_slice(&ber_len(b.len()));
    out.extend_from_slice(b);
    out
}

/// Encode `s` as a DER UTCTime (tag `0x17`). The bytes must already be
/// formatted as the ASCII UTCTime value (e.g. `b"250101000000Z"`).
fn der_utc_time(s: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 1 + s.len());
    out.push(0x17);
    out.extend_from_slice(&ber_len(s.len()));
    out.extend_from_slice(s);
    out
}

/// Wrap `content` in a context-specific EXPLICIT tag.
fn der_explicit(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(1 + 3 + content.len());
    out.push(tag);
    out.extend_from_slice(&ber_len(content.len()));
    out.extend_from_slice(content);
    out
}

// ---------------------------------------------------------------------------
// Higher-level helpers
// ---------------------------------------------------------------------------

/// Build an RDN SEQUENCE containing a single commonName attribute.
///
/// Produces: `SEQUENCE { SET { SEQUENCE { OID cn, UTF8String cn_value } } }`
fn rdn_sequence(cn: &str) -> Vec<u8> {
    let attr = der_seq(&[der_oid(OID_CN), der_utf8_string(cn)].concat());
    der_seq(&der_set(&attr))
}

/// Build a validity SEQUENCE from two UTCTime values.
///
/// Each argument must be a 13-byte YYMMDDHHMMSSZ string, e.g. `b"250101000000Z"`.
/// The caller owns the policy decision of what dates to use; this function only encodes them.
fn validity_der(not_before: &[u8; 13], not_after: &[u8; 13]) -> Vec<u8> {
    let nb = der_utc_time(not_before);
    let na = der_utc_time(not_after);
    der_seq(&[nb, na].concat())
}

/// Build the AlgorithmIdentifier for Ed25519.
///
/// RFC 8410 requires absent parameters for Ed25519, so this is simply
/// `SEQUENCE { OID 1.3.101.112 }`.
fn ed25519_alg_id() -> Vec<u8> {
    der_seq(&der_oid(OID_ED25519))
}

/// Build the AlgorithmIdentifier for ECDSA-SHA256.
///
/// Produces `SEQUENCE { OID 1.2.840.10045.4.3.2 }`.
fn ecdsa_sha256_alg_id() -> Vec<u8> {
    der_seq(&der_oid(OID_ECDSA_SHA256))
}

/// Build the SubjectPublicKeyInfo for an Ed25519 public key.
///
/// Produces `SEQUENCE { SEQUENCE { OID 1.3.101.112 }, BIT STRING { 0x00 || key } }`.
fn ed25519_spki(pub_key: &[u8; 32]) -> Vec<u8> {
    let alg_id = ed25519_alg_id();
    let key_bits = der_bit_string(pub_key);
    der_seq(&[alg_id, key_bits].concat())
}

/// Build the SubjectPublicKeyInfo for a NIST P-256 public key.
///
/// `pub_key` is the raw 64-byte uncompressed point (without the `0x04` prefix).
/// Produces `SEQUENCE { SEQUENCE { OID ecPublicKey, OID P-256 }, BIT STRING { 0x00, 0x04 || key } }`.
fn p256_spki(pub_key: &[u8; 64]) -> Vec<u8> {
    let alg_seq = der_seq(&[der_oid(OID_EC_PUBLIC_KEY), der_oid(OID_P256)].concat());
    let mut point = Vec::with_capacity(65);
    point.push(0x04);
    point.extend_from_slice(pub_key);
    let key_bits = der_bit_string(&point);
    der_seq(&[alg_seq, key_bits].concat())
}

// ---------------------------------------------------------------------------
// TBS Certificate builders
// ---------------------------------------------------------------------------

fn build_ed25519_tbs(
    serial: u32,
    cn: &str,
    pub_key: &[u8; 32],
    not_before: &[u8; 13],
    not_after: &[u8; 13],
) -> Vec<u8> {
    let version = der_explicit(0xA0, &der_integer_u32(2));
    let serial_num = der_integer_u32(serial);
    let sig_alg = ed25519_alg_id();
    let issuer = rdn_sequence(cn);
    let validity = validity_der(not_before, not_after);
    let subject = rdn_sequence(cn);
    let spki = ed25519_spki(pub_key);

    let content: Vec<u8> = [
        version.as_slice(),
        serial_num.as_slice(),
        sig_alg.as_slice(),
        issuer.as_slice(),
        validity.as_slice(),
        subject.as_slice(),
        spki.as_slice(),
    ]
    .concat();

    der_seq(&content)
}

fn build_p256_tbs(
    serial: u32,
    cn: &str,
    pub_key: &[u8; 64],
    not_before: &[u8; 13],
    not_after: &[u8; 13],
) -> Vec<u8> {
    let version = der_explicit(0xA0, &der_integer_u32(2));
    let serial_num = der_integer_u32(serial);
    let sig_alg = ecdsa_sha256_alg_id();
    let issuer = rdn_sequence(cn);
    let validity = validity_der(not_before, not_after);
    let subject = rdn_sequence(cn);
    let spki = p256_spki(pub_key);

    let content: Vec<u8> = [
        version.as_slice(),
        serial_num.as_slice(),
        sig_alg.as_slice(),
        issuer.as_slice(),
        validity.as_slice(),
        subject.as_slice(),
        spki.as_slice(),
    ]
    .concat();

    der_seq(&content)
}

// ---------------------------------------------------------------------------
// ECDSA signature DER encoding
// ---------------------------------------------------------------------------

/// Convert a raw 64-byte `r||s` ECDSA signature to DER `SEQUENCE { INTEGER r, INTEGER s }`.
fn der_ecdsa_sig(raw: &[u8; 64]) -> Vec<u8> {
    let r = &raw[..32];
    let s = &raw[32..];

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
    let inner_len = r_enc.len() + s_enc.len();

    let mut seq = Vec::with_capacity(2 + inner_len);
    seq.push(0x30);
    seq.extend_from_slice(&ber_len(inner_len));
    seq.extend_from_slice(&r_enc);
    seq.extend_from_slice(&s_enc);
    seq
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate a self-signed X.509 certificate for an OnlyKey slot.
///
/// The certificate is signed directly by the device using the key in `slot_num`.
/// Ed25519 signs the TBS bytes directly; NIST P-256 signs their SHA-256 digest.
///
/// # Parameters
///
/// - `slot_name`: human-readable slot identifier (e.g. `"piv-9A"`), used in error messages.
/// - `slot_num`: OnlyKey ECC slot number (104-107 for PIV).
/// - `algorithm`: `EccAlgorithm::Ed25519` or `EccAlgorithm::NistP256`.
/// - `subject_cn`: common name for both the subject and issuer (self-signed).
/// - `not_before`: 13-byte UTCTime string, e.g. `b"250101000000Z"`.
/// - `not_after`: 13-byte UTCTime string, e.g. `b"350101000000Z"`.
/// - `device`: open OnlyKey device used to retrieve the public key and sign.
/// - `display`: challenge display for the button-press prompt.
/// - `timeout`: button-press timeout.
///
/// Returns the DER-encoded certificate bytes, or a [`CertError`].
#[allow(clippy::too_many_arguments)]
pub fn generate_self_signed(
    slot_name: &str,
    slot_num: u8,
    algorithm: EccAlgorithm,
    subject_cn: &str,
    not_before: &[u8; 13],
    not_after: &[u8; 13],
    device: &OnlyKeyDevice,
    display: &dyn ChallengeDisplay,
    timeout: Duration,
) -> Result<Vec<u8>, CertError> {
    match algorithm {
        EccAlgorithm::Ed25519 => {
            let (_, raw_bytes) =
                device.get_ecc_pubkey_raw(KeySlot::EccStored(slot_num), algorithm)?;

            if raw_bytes.len() != 32 {
                return Err(CertError::WrongKeySize(raw_bytes.len()));
            }
            let pub_key: [u8; 32] = raw_bytes
                .as_slice()
                .try_into()
                .map_err(|_| CertError::WrongKeySize(raw_bytes.len()))?;

            let tbs = build_ed25519_tbs(1, subject_cn, &pub_key, not_before, not_after);

            let op = SignOp::Ed25519 {
                slot: slot_num,
                payload: tbs.clone(),
            };
            let sig = device.sign(op, display, timeout)?;

            let sig_bytes = match sig {
                Signature::Ed25519(b) => b,
                _ => return Err(CertError::WrongSignatureType),
            };

            let sig_bit_string = der_bit_string(&sig_bytes);
            let cert = der_seq(&[tbs, ed25519_alg_id(), sig_bit_string].concat());
            Ok(cert)
        }

        EccAlgorithm::NistP256 => {
            let (_, raw_bytes) =
                device.get_ecc_pubkey_raw(KeySlot::EccStored(slot_num), algorithm)?;

            if raw_bytes.len() != 64 {
                return Err(CertError::WrongKeySize(raw_bytes.len()));
            }
            let pub_key: [u8; 64] = raw_bytes
                .as_slice()
                .try_into()
                .map_err(|_| CertError::WrongKeySize(raw_bytes.len()))?;

            let tbs = build_p256_tbs(1, subject_cn, &pub_key, not_before, not_after);

            let digest: [u8; 32] = Sha256::digest(&tbs).into();

            let op = SignOp::EcdsaP256 {
                slot: slot_num,
                payload: digest.to_vec(),
            };
            let sig = device.sign(op, display, timeout)?;

            let sig_bytes = match sig {
                Signature::EcdsaRaw(b) => b,
                _ => return Err(CertError::WrongSignatureType),
            };

            let der_sig = der_ecdsa_sig(&sig_bytes);
            let sig_bit_string = der_bit_string(&der_sig);
            let cert = der_seq(&[tbs, ecdsa_sha256_alg_id(), sig_bit_string].concat());
            Ok(cert)
        }

        EccAlgorithm::Curve25519 | EccAlgorithm::Secp256k1 => {
            Err(CertError::UnsupportedSlot(slot_name.to_string()))
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ber_len_short() {
        assert_eq!(ber_len(0x7F), vec![0x7F]);
    }

    #[test]
    fn ber_len_long_one_byte() {
        assert_eq!(ber_len(0x80), vec![0x81, 0x80]);
    }

    #[test]
    fn ber_len_long_two_byte() {
        assert_eq!(ber_len(0x200), vec![0x82, 0x02, 0x00]);
    }

    #[test]
    fn der_seq_wraps_content() {
        let inner = b"hello";
        let seq = der_seq(inner);
        assert_eq!(seq[0], 0x30);
        assert_eq!(seq[1] as usize, inner.len());
        assert_eq!(&seq[2..], inner);
    }

    #[test]
    fn ed25519_alg_id_correct() {
        // SEQUENCE { OID 1.3.101.112 } -- must be 7 bytes
        // 30 05 06 03 2B 65 70
        let id = ed25519_alg_id();
        assert_eq!(id, &[0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70]);
    }

    #[test]
    fn ed25519_spki_length() {
        let key = [0x42u8; 32];
        let spki = ed25519_spki(&key);
        // AlgID: 30 05 06 03 2B 65 70 = 7 bytes
        // BIT STRING: 03 21 00 + 32 bytes = 36 bytes
        // SEQUENCE of 43 bytes -> 30 2B = 45 total
        assert_eq!(spki[0], 0x30); // SEQUENCE
        assert!(spki.len() > 30 && spki.len() < 60);
    }

    #[test]
    fn p256_spki_starts_with_sequence() {
        let key = [0x01u8; 64];
        let spki = p256_spki(&key);
        assert_eq!(spki[0], 0x30);
    }

    #[test]
    fn rdn_sequence_cn() {
        let rdn = rdn_sequence("Test");
        // Must start with SEQUENCE tag
        assert_eq!(rdn[0], 0x30);
        // UTF8String of "Test" should appear somewhere
        let test_bytes = b"Test";
        assert!(rdn.windows(test_bytes.len()).any(|w| w == test_bytes));
    }

    #[test]
    fn der_ecdsa_sig_wraps_correctly() {
        let mut raw = [0u8; 64];
        raw[0] = 0x01;
        raw[32] = 0x02;
        let sig = der_ecdsa_sig(&raw);
        assert_eq!(sig[0], 0x30); // SEQUENCE
        assert_eq!(sig[2], 0x02); // first INTEGER
    }

    #[test]
    fn der_integer_u32_small() {
        // INTEGER 1 -> 02 01 01
        assert_eq!(der_integer_u32(1), vec![0x02, 0x01, 0x01]);
    }

    #[test]
    fn der_integer_u32_high_bit() {
        // 0x80 -> 02 02 00 80 (needs sign byte)
        assert_eq!(der_integer_u32(0x80), vec![0x02, 0x02, 0x00, 0x80]);
    }
}
