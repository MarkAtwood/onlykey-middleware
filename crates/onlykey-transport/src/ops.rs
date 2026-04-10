use std::time::Instant;

use onlykey_hid::{derive_challenge, encode_large_message, Command, KeySlot};
use wolfcrypt::ecdsa::P256VerifyingKey;
use wolfcrypt::ed25519::Ed25519VerifyingKey;
use wolfcrypt::rsa::NativeRsaKey;

use crate::challenge_ui::ChallengeDisplay;
use crate::error::TransportError;
use crate::io::RawIo;
use crate::types::{DecryptOp, Decrypted, EccAlgorithm, PublicKey, SignOp, Signature};

// Big-endian encoding of 65537 = 0x010001.
const E_65537: [u8; 3] = [0x01, 0x00, 0x01];

/// Send OKGETPUBKEY for one slot and return the response.
///
/// Shared by `get_pubkey_with_bytes`, `get_ecc_pubkey_with_bytes`, and
/// `get_raw_pubkey_bytes` to eliminate three copies of the same I/O sequence.
/// Issue OnlyKey-ior1.
///
/// Uses a 200 ms inter-frame timeout: public-key reads are synchronous
/// device lookups with no user interaction; 200 ms avoids stalling callers
/// while comfortably handling firmware processing latency.
fn fetch_pubkey_response(
    io: &RawIo,
    wire_slot: u8,
) -> Result<onlykey_hid::Response, TransportError> {
    let frame = onlykey_hid::HidFrame::command(Command::GetPubkey.wire_byte(), wire_slot, &[])?;
    io.write(&frame)?;
    let response = io.read_until_idle(200)?;
    if response.is_error() {
        return Err(TransportError::Device(
            response.error_message().unwrap_or_default(),
        ));
    }
    Ok(response)
}

/// Retrieve and validate an RSA public key from the device.
///
/// Sends OKGETPUBKEY for the given RSA slot and constructs a wolfcrypt
/// `NativeRsaKey` from the returned modulus bytes (exponent = 65537).
///
/// Fails with `TransportError::Protocol` if the response length is not
/// 256 (RSA-2048) or 512 (RSA-4096) bytes.
///
/// Delegates to [`get_pubkey_with_bytes`] and discards the raw modulus.
/// Issue OnlyKey-w85: previously the two functions shared duplicated I/O logic.
pub fn get_pubkey(io: &RawIo, slot: KeySlot) -> Result<PublicKey, TransportError> {
    get_pubkey_with_bytes(io, slot).map(|(key, _)| key)
}

/// Like `get_pubkey` but also returns the raw modulus bytes.
///
/// Used by the PKCS#11 layer to populate `CKA_MODULUS` without re-querying.
pub fn get_pubkey_with_bytes(
    io: &RawIo,
    slot: KeySlot,
) -> Result<(PublicKey, Vec<u8>), TransportError> {
    if !slot.is_rsa() {
        return Err(TransportError::Protocol(
            "get_pubkey_with_bytes() is for RSA slots only".into(),
        ));
    }
    slot.validate()?;

    let response = fetch_pubkey_response(io, slot.wire_slot())?;
    let bytes = response.as_bytes();
    match bytes.len() {
        256 | 512 => {
            let raw = bytes.to_vec();
            let key = NativeRsaKey::from_raw_public(bytes, &E_65537).map_err(|e| {
                TransportError::Protocol(format!("RSA public key import failed: {:?}", e))
            })?;
            Ok((PublicKey::Rsa(Box::new(key)), raw))
        }
        n => Err(TransportError::Protocol(format!(
            "unexpected RSA public key length: {} (expected 256 or 512)",
            n
        ))),
    }
}

/// Retrieve and validate an ECC public key from the device.
///
/// The caller must provide the `algorithm` from `slots.toml` because the
/// 32-byte (Ed25519/Curve25519) and 64-byte (P-256/secp256k1) wire responses
/// are identical within each size class.
///
/// Delegates to [`get_ecc_pubkey_with_bytes`] and discards the raw wire bytes.
/// Issue OnlyKey-w85: previously the two functions shared duplicated I/O logic.
pub fn get_ecc_pubkey(
    io: &RawIo,
    slot: KeySlot,
    algorithm: EccAlgorithm,
) -> Result<PublicKey, TransportError> {
    get_ecc_pubkey_with_bytes(io, slot, algorithm).map(|(key, _)| key)
}

/// Like `get_ecc_pubkey` but also returns the raw wire bytes.
///
/// Used by the PKCS#11 layer to populate `CKA_EC_POINT` without re-querying.
pub fn get_ecc_pubkey_with_bytes(
    io: &RawIo,
    slot: KeySlot,
    algorithm: EccAlgorithm,
) -> Result<(PublicKey, Vec<u8>), TransportError> {
    if slot.is_rsa() {
        return Err(TransportError::Protocol(
            "get_ecc_pubkey_with_bytes() is for ECC slots only".into(),
        ));
    }
    slot.validate()?;

    let response = fetch_pubkey_response(io, slot.wire_slot())?;
    let bytes = response.as_bytes();
    let raw = bytes.to_vec();
    let slot_num = slot.wire_slot();

    let key = match algorithm {
        EccAlgorithm::Ed25519 => {
            if bytes.len() != 32 {
                return Err(TransportError::Protocol(format!(
                    "algorithm mismatch: slot {} declared {:?} but got {} bytes",
                    slot_num,
                    algorithm,
                    bytes.len()
                )));
            }
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| TransportError::Protocol("Ed25519 key length mismatch".into()))?;
            let mut key = Ed25519VerifyingKey::from_bytes(&arr)
                .map_err(|e| TransportError::Protocol(format!("Ed25519 import failed: {:?}", e)))?;
            key.check_key().map_err(|e| {
                TransportError::Protocol(format!("Ed25519 point validation failed: {:?}", e))
            })?;
            PublicKey::Ed25519(Box::new(key))
        }
        EccAlgorithm::Curve25519 => {
            if bytes.len() != 32 {
                return Err(TransportError::Protocol(format!(
                    "algorithm mismatch: slot {} declared {:?} but got {} bytes",
                    slot_num,
                    algorithm,
                    bytes.len()
                )));
            }
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| TransportError::Protocol("Curve25519 key length mismatch".into()))?;
            PublicKey::Curve25519Raw(arr)
        }
        EccAlgorithm::NistP256 => {
            if bytes.len() != 64 {
                return Err(TransportError::Protocol(format!(
                    "algorithm mismatch: slot {} declared {:?} but got {} bytes",
                    slot_num,
                    algorithm,
                    bytes.len()
                )));
            }
            let raw_arr: [u8; 64] = bytes
                .try_into()
                .map_err(|_| TransportError::Protocol("NistP256 key length mismatch".into()))?;
            let mut point = [0u8; 65];
            point[0] = 0x04;
            point[1..].copy_from_slice(&raw_arr);
            let key = P256VerifyingKey::from_uncompressed_point(&point).map_err(|e| {
                TransportError::Protocol(format!("NistP256 import failed: {:?}", e))
            })?;
            PublicKey::NistP256(Box::new(key))
        }
        EccAlgorithm::Secp256k1 => {
            if bytes.len() != 64 {
                return Err(TransportError::Protocol(format!(
                    "algorithm mismatch: slot {} declared {:?} but got {} bytes",
                    slot_num,
                    algorithm,
                    bytes.len()
                )));
            }
            let arr: [u8; 64] = bytes
                .try_into()
                .map_err(|_| TransportError::Protocol("Secp256k1 key length mismatch".into()))?;
            PublicKey::Secp256k1Raw(arr)
        }
    };
    Ok((key, raw))
}

/// Perform a signing operation on the device.
///
/// Displays the challenge code via `display` before blocking.
/// The device must be unlocked and the user must press the matching buttons.
pub fn sign(
    io: &RawIo,
    op: SignOp,
    display: &dyn ChallengeDisplay,
    challenge_timeout: std::time::Duration,
) -> Result<Signature, TransportError> {
    let (slot, payload, cmd) = match &op {
        SignOp::Ed25519 { slot, payload } => (*slot, payload.as_slice(), Command::Sign),
        SignOp::EcdsaP256 { slot, payload } => (*slot, payload.as_slice(), Command::Sign),
        SignOp::EcdsaK1 { slot, payload } => (*slot, payload.as_slice(), Command::Sign),
        SignOp::Rsa { slot, digest } => (*slot, digest.as_slice(), Command::Sign),
    };

    let challenge = derive_challenge(payload);
    // derive_challenge returns `hash_byte % 6 + 1`, which is mathematically
    // guaranteed to produce values in [1,6] for any input. The debug_assert
    // documents this invariant and will fire in test builds if the algorithm
    // ever changes. Issue OnlyKey-jle.
    debug_assert!(
        challenge.iter().all(|&d| (1..=6).contains(&d)),
        "challenge digit out of range [1,6]: {:?}",
        challenge
    );
    display.show(challenge);

    let frames = encode_large_message(cmd.wire_byte(), slot, payload)?;
    for frame in frames {
        io.write(&frame)?;
    }

    let deadline = Instant::now() + challenge_timeout;
    let response = io.wait_for_response(deadline)?;

    match op {
        SignOp::Ed25519 { .. } => {
            let sig = response.as_ed25519_sig()?;
            if let onlykey_hid::SignatureBytes::Ed25519(b) = sig {
                return Ok(Signature::Ed25519(b));
            }
            unreachable!("as_ed25519_sig returned wrong variant")
        }
        SignOp::EcdsaP256 { .. } | SignOp::EcdsaK1 { .. } => {
            let sig = response.as_ecdsa_p256_sig()?;
            if let onlykey_hid::SignatureBytes::EcdsaP256(b) = sig {
                return Ok(Signature::EcdsaRaw(b));
            }
            unreachable!("as_ecdsa_p256_sig returned wrong variant")
        }
        SignOp::Rsa { .. } => {
            let sig = response.as_rsa_sig()?;
            if let onlykey_hid::SignatureBytes::Rsa(b) = sig {
                return Ok(Signature::Rsa(b.to_vec()));
            }
            unreachable!("as_rsa_sig returned wrong variant")
        }
    }
}

/// Perform a decrypt / ECDH operation on the device.
pub fn decrypt(
    io: &RawIo,
    op: DecryptOp,
    display: &dyn ChallengeDisplay,
    challenge_timeout: std::time::Duration,
) -> Result<Decrypted, TransportError> {
    let (slot, payload): (u8, &[u8]) = match &op {
        DecryptOp::Curve25519 { slot, peer_key } => (*slot, peer_key.as_ref()),
        DecryptOp::NistP256 { slot, peer_key } => (*slot, peer_key.as_ref()),
        DecryptOp::Rsa { slot, ciphertext } => (*slot, ciphertext.as_slice()),
    };

    let challenge = derive_challenge(payload);
    // Same invariant as sign(): derive_challenge guarantees [1,6]. Issue OnlyKey-jle.
    debug_assert!(
        challenge.iter().all(|&d| (1..=6).contains(&d)),
        "challenge digit out of range [1,6]: {:?}",
        challenge
    );
    display.show(challenge);

    let frames = encode_large_message(Command::Decrypt.wire_byte(), slot, payload)?;
    for frame in frames {
        io.write(&frame)?;
    }

    let deadline = Instant::now() + challenge_timeout;
    let response = io.wait_for_response(deadline)?;

    match op {
        DecryptOp::Curve25519 { .. } | DecryptOp::NistP256 { .. } => {
            let secret = response.as_shared_secret32()?;
            let onlykey_hid::DecryptedBytes::SharedSecret32(b) = secret;
            Ok(Decrypted::SharedSecret32(b))
        }
        DecryptOp::Rsa { .. } => Ok(Decrypted::RsaPlaintext(response.as_bytes().to_vec())),
    }
}

/// Compute HMAC using the device's HMAC key slot.
///
/// HMAC does not require a button press -- uses a 3-second timeout.
/// Wire slot = 128 + slot_number (matching firmware HMAC addressing).
pub fn hmac(io: &RawIo, slot: u8, challenge_bytes: &[u8]) -> Result<Vec<u8>, TransportError> {
    // The OnlyKey firmware only supports two HMAC slots (1 and 2).
    // Any other value would silently address the wrong slot or produce a
    // firmware error with no actionable message. Issue OnlyKey-cyb.
    if slot != 1 && slot != 2 {
        return Err(TransportError::Protocol(format!(
            "invalid HMAC slot {}: must be 1 or 2",
            slot
        )));
    }
    let wire_slot = 128u8.checked_add(slot).ok_or_else(|| {
        TransportError::Protocol(format!("HMAC slot {} overflows wire byte", slot))
    })?;

    let frames = encode_large_message(Command::Hmac.wire_byte(), wire_slot, challenge_bytes)?;
    for frame in frames {
        io.write(&frame)?;
    }

    let deadline = Instant::now() + crate::io::HMAC_TIMEOUT_MS;
    let response = io.wait_for_response(deadline)?;
    Ok(response.as_bytes().to_vec())
}

/// Retrieve raw public key bytes from an ECC slot without algorithm interpretation.
///
/// Unlike `get_ecc_pubkey_with_bytes`, no wolfcrypt validation is performed.
/// This is used to derive the device pseudo-serial from a well-known slot.
/// Uses `fetch_pubkey_response` to avoid duplicating the I/O sequence.
/// Issue OnlyKey-ior1.
fn get_raw_pubkey_bytes(io: &RawIo, slot: u8) -> Result<Vec<u8>, TransportError> {
    let response = fetch_pubkey_response(io, slot)?;
    Ok(response.as_bytes().to_vec())
}

/// Derive a 4-byte pseudo-serial from raw public key bytes.
///
/// Computes `SHA-256("onlykey-serial-v1\0" || bytes)` and returns the first
/// 4 bytes. The domain prefix ensures the derivation is distinct from any
/// other use of the same key material.
pub fn derive_pseudo_serial(pubkey_bytes: &[u8]) -> [u8; 4] {
    use wolfcrypt::digest::digest_trait::Digest;
    use wolfcrypt::digest::Sha256;
    let hash = Sha256::new()
        .chain_update(b"onlykey-serial-v1\0")
        .chain_update(pubkey_bytes)
        .finalize();
    [hash[0], hash[1], hash[2], hash[3]]
}

/// Fallback pseudo-serial used when slot 101 cannot be read.
///
/// Matches the historical OpenPGP AID default (0x00000001). Multiple devices
/// that fall through to this value are **indistinguishable** to PKCS#11 and
/// OpenPGP Card consumers — callers that detect this value should warn the user.
///
/// # Known limitation — Issue OnlyKey-af4
///
/// Two OnlyKey devices that both have slot 101 empty (PIV-only setup) or both
/// fail to respond will both receive this fallback serial. PKCS#11 callers
/// (NSS, GnuPG, p11-kit) assume token serial uniqueness for key management;
/// two tokens sharing serial `00000001` appear identical and key selection
/// between them is undefined.
///
/// The permanent fix requires the OnlyKey firmware to expose a per-device
/// unique identifier over HID (see the firmware wishlist in README.md). Until
/// then, users with multiple devices should ensure at least one ECC key is
/// populated in slot 101 on each device.
pub const FALLBACK_PSEUDO_SERIAL: [u8; 4] = [0, 0, 0, 1];

/// Pure decision: given the raw result of reading slot 101, return the
/// derived pseudo-serial or the fallback.
///
/// Extracted from `get_device_pseudo_serial` so the fallback/derivation logic
/// can be tested without a real HID device. Callers that need to warn on
/// fallback should compare the return value against `FALLBACK_PSEUDO_SERIAL`.
pub(crate) fn serial_from_raw_bytes(result: Result<Vec<u8>, crate::error::TransportError>) -> [u8; 4] {
    match result {
        Ok(bytes) if !bytes.is_empty() => derive_pseudo_serial(&bytes),
        // Empty slot (PIV-only device with no key in slot 101) or read error.
        _ => FALLBACK_PSEUDO_SERIAL,
    }
}

/// Derive a stable pseudo-serial by reading ECC slot 101 from the device.
///
/// Slot 101 is the lowest-numbered ECC slot. Any device configured for
/// OpenPGP will have a key there. PIV-only devices may not. If the slot is
/// empty or the read fails, returns `FALLBACK_PSEUDO_SERIAL` (`[0, 0, 0, 1]`).
///
/// OKGETPUBKEY does not require a button press — the read takes ~200 ms.
pub fn get_device_pseudo_serial(io: &RawIo) -> [u8; 4] {
    serial_from_raw_bytes(get_raw_pubkey_bytes(io, 101))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Convenience: test bytes that are unlikely to hash to the fallback.
    fn test_key_bytes() -> Vec<u8> {
        vec![0x42u8; 32]
    }

    #[test]
    fn serial_from_raw_bytes_derives_hash_for_nonempty_slot() {
        // Non-empty slot → deterministic hash, never the fallback.
        let bytes = test_key_bytes();
        let serial = serial_from_raw_bytes(Ok(bytes.clone()));
        assert_eq!(serial, derive_pseudo_serial(&bytes));
        assert_ne!(serial, FALLBACK_PSEUDO_SERIAL);
    }

    #[test]
    fn serial_from_raw_bytes_fallback_when_slot_empty() {
        // PIV-only device: slot 101 returns Ok([]) because the slot is unset.
        let serial = serial_from_raw_bytes(Ok(vec![]));
        assert_eq!(serial, FALLBACK_PSEUDO_SERIAL);
    }

    #[test]
    fn serial_from_raw_bytes_fallback_on_transport_error() {
        // Unconfigured device: slot read returns an error.
        let serial = serial_from_raw_bytes(Err(crate::error::TransportError::Protocol(
            "slot 101 empty or unset".into(),
        )));
        assert_eq!(serial, FALLBACK_PSEUDO_SERIAL);
    }

    #[test]
    fn serial_from_raw_bytes_fallback_on_disconnected() {
        // Device disconnects mid-read (e.g. USB glitch): must not panic.
        let serial = serial_from_raw_bytes(Err(crate::error::TransportError::Disconnected));
        assert_eq!(serial, FALLBACK_PSEUDO_SERIAL);
    }

    #[test]
    fn derive_pseudo_serial_is_deterministic() {
        let bytes = b"deterministic test key material!";
        assert_eq!(derive_pseudo_serial(bytes), derive_pseudo_serial(bytes));
    }

    #[test]
    fn derive_pseudo_serial_differs_for_different_keys() {
        let a = derive_pseudo_serial(&[0x01u8; 32]);
        let b = derive_pseudo_serial(&[0x02u8; 32]);
        assert_ne!(a, b);
    }

    #[test]
    fn derive_pseudo_serial_all_zero_key_is_not_fallback() {
        // SHA-256("onlykey-serial-v1\0" || 0x00*32) must not collide with
        // the fallback [0,0,0,1], which would make a zeroed slot
        // indistinguishable from a missing slot.
        let serial = derive_pseudo_serial(&[0u8; 32]);
        assert_ne!(serial, FALLBACK_PSEUDO_SERIAL);
        assert_ne!(serial, [0, 0, 0, 0]);
    }

    // -----------------------------------------------------------------------
    // detect_ecc_algorithm tests
    // -----------------------------------------------------------------------

    /// RFC 8032 §6.4.3 Test Vector 1 public key.
    /// Independent oracle: the bytes are the known-good Ed25519 public key for
    /// the private key 9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae3d55.
    /// Any correct Ed25519 implementation must accept this as a valid point.
    #[rustfmt::skip]
    const RFC8032_ED25519_PUB: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
        0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
        0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
        0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a,
    ];

    /// y = p = 2^255 − 19 in little-endian.
    /// wolfcrypt's range check rejects any y ≥ p.  Detection must return
    /// Curve25519 (definitive failure path).
    #[rustfmt::skip]
    const OVER_P_32: [u8; 32] = [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
    ];

    #[test]
    fn detect_ecc_rfc8032_ed25519_vector_is_ed25519() {
        // A real Ed25519 public key must always pass check_key().
        assert_eq!(
            detect_ecc_algorithm(&RFC8032_ED25519_PUB),
            Some(EccAlgorithm::Ed25519)
        );
    }

    #[test]
    fn detect_ecc_over_p_is_curve25519() {
        // y ≥ p fails wolfcrypt's range check → definitive Curve25519 result.
        // This tests the reliable failure path documented in the function's
        // doc comment.
        assert_eq!(
            detect_ecc_algorithm(&OVER_P_32),
            Some(EccAlgorithm::Curve25519)
        );
    }

    #[test]
    fn detect_ecc_all_zeros_32_is_ed25519_false_positive() {
        // All-zero bytes represent the Edwards curve point (sqrt(−1), 0),
        // which is a valid low-order point. wolfcrypt accepts it because:
        //   y = 0 → u = y²−1 = −1, v = dy²+1 = 1 → x² = −1/1 = −1
        //   −1 is a QR mod p (p ≡ 1 mod 4) → check_key passes.
        //
        // No real device will produce all-zero as an Ed25519 public key, so
        // this is a false positive. It demonstrates the ~50% false-positive
        // rate for Curve25519 keys described in the doc comment for
        // detect_ecc_algorithm (OnlyKey-6o9 investigation).
        assert_eq!(
            detect_ecc_algorithm(&[0u8; 32]),
            Some(EccAlgorithm::Ed25519)
        );
    }

    #[test]
    fn detect_ecc_wrong_length_returns_none() {
        assert_eq!(detect_ecc_algorithm(&[]), None);
        assert_eq!(detect_ecc_algorithm(&[0u8; 1]), None);
        assert_eq!(detect_ecc_algorithm(&[0u8; 31]), None);
        assert_eq!(detect_ecc_algorithm(&[0u8; 33]), None);
        assert_eq!(detect_ecc_algorithm(&[0u8; 63]), None);
        assert_eq!(detect_ecc_algorithm(&[0u8; 65]), None);
    }

    #[test]
    fn detect_ecc_64_byte_returns_p256_or_secp256k1() {
        // 64-byte detection is reliable (unrelated curves). We don't assert
        // a specific result here since we don't have a known valid P-256 or
        // secp256k1 point without device access, but the function must return
        // Some (not None) for any 64-byte input.
        let result = detect_ecc_algorithm(&[0u8; 64]);
        assert!(
            result == Some(EccAlgorithm::NistP256) || result == Some(EccAlgorithm::Secp256k1),
            "expected NistP256 or Secp256k1 for 64-byte input, got {:?}",
            result
        );
    }
}

/// Heuristically detect the ECC algorithm for raw public key bytes returned
/// by `OKGETPUBKEY`.
///
/// The OnlyKey firmware returns raw key bytes with no algorithm tag:
/// 32-byte responses are either Ed25519 or Curve25519; 64-byte responses are
/// either NIST P-256 or secp256k1.
///
/// ## 64-byte keys — reliable
///
/// P-256 and secp256k1 are unrelated curves with different equations. A point
/// on one curve will not satisfy the other's equation except with negligible
/// probability. `wc_ecc_import_x963` validates the full curve equation, so
/// the 64-byte detection is reliable.
///
/// ## 32-byte keys — unreliable (~50% false-positive rate for Curve25519)
///
/// Ed25519 and Curve25519 share the same underlying prime field
/// (p = 2²⁵⁵ − 19) and are birationally equivalent curves in different
/// coordinate systems. `wc_ed25519_check_key` (public-key-only path) does:
///
/// 1. Range check: rejects y ≥ p (about 19 out of 2²⁵⁵ values).
/// 2. Curve check: tests whether `(y²−1)/(dy²+1)` is a quadratic residue
///    mod p, which recovers an x-coordinate on the Edwards curve.
///
/// Because p ≡ 1 (mod 4), −1 is a quadratic residue mod p. This means
/// that if `u/v` is a quadratic non-residue, `−u/v` is *also* a non-residue
/// (since (−1)(QNR) = QNR). Approximately half of all field elements are
/// non-residues, so **roughly half of all 32-byte inputs pass the curve
/// check**, including ~50% of valid Curve25519 u-coordinates.
///
/// Consequence:
/// - **Failure is definitive**: a Curve25519 u-coordinate that fails the
///   Ed25519 curve check is *never* an Ed25519 key. Return `Curve25519`.
/// - **Success is a best guess**: ~50% of Curve25519 u-coordinates pass
///   the Ed25519 curve check. Return `Ed25519` as the most likely answer,
///   but callers should warn users to verify when the slot could be Curve25519.
///
/// See `OnlyKey-6o9` for the full analysis and test vectors.
pub fn detect_ecc_algorithm(bytes: &[u8]) -> Option<EccAlgorithm> {
    match bytes.len() {
        32 => {
            let arr: [u8; 32] = bytes.try_into().ok()?;
            let ok = Ed25519VerifyingKey::from_bytes(&arr)
                .and_then(|mut k| k.check_key().map(|_| ()))
                .is_ok();
            if ok {
                // Passes the Ed25519 curve check — most likely Ed25519, but ~50% of
                // Curve25519 u-coordinates also pass (see doc comment for analysis).
                // Callers should warn users when the slot may be Curve25519.
                Some(EccAlgorithm::Ed25519)
            } else {
                // Failed the Edwards curve check — definitively not Ed25519.
                Some(EccAlgorithm::Curve25519)
            }
        }
        64 => {
            let mut point = [0u8; 65];
            point[0] = 0x04; // X9.62 uncompressed prefix
            point[1..].copy_from_slice(bytes);
            let ok = P256VerifyingKey::from_uncompressed_point(&point).is_ok();
            if ok {
                Some(EccAlgorithm::NistP256)
            } else {
                Some(EccAlgorithm::Secp256k1)
            }
        }
        _ => None,
    }
}
