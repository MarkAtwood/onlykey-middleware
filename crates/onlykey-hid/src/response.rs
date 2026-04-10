extern crate alloc;
use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::error::HidError;
use crate::types::{DecryptedBytes, PublicKeyBytes, SignatureBytes};

/// A response received from the OnlyKey device.
///
/// The device returns variable-length responses for public key queries,
/// sign operations, and decrypt operations. The raw bytes are stored
/// in full; typed accessors validate the minimum required lengths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Response {
    bytes: Vec<u8>,
}

impl Response {
    /// Construct a `Response` from raw bytes received from the device.
    pub fn new(bytes: Vec<u8>) -> Self {
        Response { bytes }
    }

    /// Returns `true` if the response is an error message from the device.
    ///
    /// An error response begins with the ASCII prefix `"Error"`.
    ///
    /// This check is less strict than `HidFrame::is_error_response()`, which
    /// additionally validates that all bytes after "Error" are printable ASCII
    /// or NUL. That is intentional: `HidFrame::is_error_response()` guards the
    /// frame-to-`Response` construction step; by the time `is_error()` is called
    /// the bytes are already known to have passed the stricter frame-level check.
    pub fn is_error(&self) -> bool {
        self.bytes.starts_with(b"Error")
    }

    /// Extract the human-readable error message, if this is an error response.
    ///
    /// Strips trailing NUL bytes and returns the printable portion.
    /// Returns `None` if the response is not an error.
    pub fn error_message(&self) -> Option<String> {
        if !self.is_error() {
            return None;
        }
        let end = self
            .bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.bytes.len());
        // Use lossy decoding so that non-UTF-8 device error payloads produce a
        // visible message (with replacement characters) rather than an empty string,
        // which made it impossible to diagnose what the device actually reported.
        Some(
            core::str::from_utf8(&self.bytes[..end])
                .map(String::from)
                .unwrap_or_else(|_| format!("<non-UTF-8 error: {} bytes>", end)),
        )
    }

    /// Parse response as a 32-byte ECC public key (Ed25519 or Curve25519).
    ///
    /// Fails with [`HidError::ResponseTooShort`] if `bytes.len() < 32`.
    pub fn as_ecc32(&self) -> Result<PublicKeyBytes, HidError> {
        if self.bytes.len() < 32 {
            return Err(HidError::ResponseTooShort);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&self.bytes[..32]);
        Ok(PublicKeyBytes::Bytes32(arr))
    }

    /// Parse response as a 64-byte ECC public key (NIST P-256 or secp256k1).
    ///
    /// Fails with [`HidError::ResponseTooShort`] if `bytes.len() < 64`.
    pub fn as_ecc64(&self) -> Result<PublicKeyBytes, HidError> {
        if self.bytes.len() < 64 {
            return Err(HidError::ResponseTooShort);
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&self.bytes[..64]);
        Ok(PublicKeyBytes::Bytes64(arr))
    }

    /// Parse response as an RSA-2048 public key modulus (256 bytes).
    ///
    /// Fails with [`HidError::ResponseTooShort`] if `bytes.len() < 256`.
    pub fn as_rsa2048(&self) -> Result<PublicKeyBytes, HidError> {
        if self.bytes.len() < 256 {
            return Err(HidError::ResponseTooShort);
        }
        let mut arr = Box::new([0u8; 256]);
        arr.copy_from_slice(&self.bytes[..256]);
        Ok(PublicKeyBytes::Rsa2048(arr))
    }

    /// Parse response as an RSA-4096 public key modulus (512 bytes).
    ///
    /// Fails with [`HidError::ResponseTooShort`] if `bytes.len() < 512`.
    pub fn as_rsa4096(&self) -> Result<PublicKeyBytes, HidError> {
        if self.bytes.len() < 512 {
            return Err(HidError::ResponseTooShort);
        }
        let mut arr = Box::new([0u8; 512]);
        arr.copy_from_slice(&self.bytes[..512]);
        Ok(PublicKeyBytes::Rsa4096(arr))
    }

    /// Parse response as an Ed25519 signature (64 bytes).
    ///
    /// Fails with [`HidError::ResponseTooShort`] if `bytes.len() < 64`.
    pub fn as_ed25519_sig(&self) -> Result<SignatureBytes, HidError> {
        if self.bytes.len() < 64 {
            return Err(HidError::ResponseTooShort);
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&self.bytes[..64]);
        Ok(SignatureBytes::Ed25519(arr))
    }

    /// Parse response as an ECDSA P-256 signature (64 bytes, raw `r || s`).
    ///
    /// Fails with [`HidError::ResponseTooShort`] if `bytes.len() < 64`.
    /// Fails with [`HidError::InvalidSignature`] if either `r` or `s` is all-zeros.
    pub fn as_ecdsa_p256_sig(&self) -> Result<SignatureBytes, HidError> {
        if self.bytes.len() < 64 {
            return Err(HidError::ResponseTooShort);
        }
        let mut arr = [0u8; 64];
        arr.copy_from_slice(&self.bytes[..64]);
        let r = &arr[..32];
        let s = &arr[32..];
        // Reject the all-zero case: r=0 or s=0 is always invalid for ECDSA
        // (the spec requires r, s in [1, group_order)). A full range check
        // (verifying r,s < order) is not performed here because it would require
        // embedding the P-256 order constant and is the firmware's responsibility.
        // The device is the trust boundary for producing valid (r, s) pairs;
        // we only guard against the catastrophic zero case that would silently
        // produce a structurally nonsensical signature.
        if r.iter().all(|&b| b == 0) || s.iter().all(|&b| b == 0) {
            return Err(HidError::InvalidSignature);
        }
        Ok(SignatureBytes::EcdsaP256(arr))
    }

    /// Parse response as an RSA PKCS#1 v1.5 signature.
    ///
    /// RSA signatures must be exactly as long as the key modulus:
    /// 256 bytes for RSA-2048, or 512 bytes for RSA-4096.
    ///
    /// Fails with [`HidError::ResponseWrongLength`] if the length is not
    /// exactly 256 or 512 bytes. Any other length indicates firmware
    /// misbehaviour or a truncated/corrupted response. Issue OnlyKey-uhd.
    ///
    /// `Box::from(&[u8])` copies the slice directly into a fresh heap allocation
    /// without an intermediate `Vec`. This avoids a superfluous clone compared
    /// to `self.bytes.clone().into_boxed_slice()`. Issue OnlyKey-biwo.
    pub fn as_rsa_sig(&self) -> Result<SignatureBytes, HidError> {
        match self.bytes.len() {
            256 | 512 => Ok(SignatureBytes::Rsa(Box::from(self.bytes.as_slice()))),
            n => Err(HidError::ResponseWrongLength(n)),
        }
    }

    /// Parse response as a 32-byte ECDH shared secret.
    ///
    /// Fails with [`HidError::ResponseTooShort`] if `bytes.len() < 32`.
    pub fn as_shared_secret32(&self) -> Result<DecryptedBytes, HidError> {
        if self.bytes.len() < 32 {
            return Err(HidError::ResponseTooShort);
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&self.bytes[..32]);
        Ok(DecryptedBytes::SharedSecret32(arr))
    }

    /// Raw bytes for inspection (e.g. when the caller knows the response type).
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn response_too_short_for_ecc32() {
        let r = Response::new(vec![0u8; 31]);
        assert_eq!(r.as_ecc32(), Err(HidError::ResponseTooShort));
    }

    #[test]
    fn ecc32_parses_correctly() {
        let mut data = vec![0u8; 32];
        data[0] = 0xAB;
        data[31] = 0xCD;
        let r = Response::new(data);
        if let Ok(PublicKeyBytes::Bytes32(b)) = r.as_ecc32() {
            assert_eq!(b[0], 0xAB);
            assert_eq!(b[31], 0xCD);
        } else {
            panic!("expected Bytes32");
        }
    }

    #[test]
    fn response_too_short_for_rsa2048() {
        let r = Response::new(vec![0u8; 255]);
        assert_eq!(r.as_rsa2048(), Err(HidError::ResponseTooShort));
    }

    #[test]
    fn rsa2048_parses_correctly() {
        let mut data = vec![0u8; 256];
        data[0] = 0x01;
        data[255] = 0xFF;
        let r = Response::new(data);
        if let Ok(PublicKeyBytes::Rsa2048(b)) = r.as_rsa2048() {
            assert_eq!(b[0], 0x01);
            assert_eq!(b[255], 0xFF);
        } else {
            panic!("expected Rsa2048");
        }
    }

    #[test]
    fn error_message_extraction() {
        let msg = b"Error invalid slot\0\0";
        let r = Response::new(msg.to_vec());
        assert!(r.is_error());
        assert_eq!(r.error_message(), Some("Error invalid slot".into()));
    }

    #[test]
    fn non_error_response_has_no_message() {
        let r = Response::new(vec![0xABu8; 32]);
        assert!(!r.is_error());
        assert_eq!(r.error_message(), None);
    }

    #[test]
    fn shared_secret32_too_short() {
        let r = Response::new(vec![0u8; 31]);
        assert_eq!(r.as_shared_secret32(), Err(HidError::ResponseTooShort));
    }

    #[test]
    fn shared_secret32_parses_correctly() {
        let mut data = vec![0u8; 32];
        data[0] = 0x42;
        let r = Response::new(data);
        if let Ok(DecryptedBytes::SharedSecret32(s)) = r.as_shared_secret32() {
            assert_eq!(s[0], 0x42);
        } else {
            panic!("expected SharedSecret32");
        }
    }

    #[test]
    fn rsa_sig_256_accepted() {
        let r = Response::new(vec![0x01u8; 256]);
        assert!(matches!(r.as_rsa_sig(), Ok(SignatureBytes::Rsa(_))));
    }

    #[test]
    fn rsa_sig_512_accepted() {
        let r = Response::new(vec![0x01u8; 512]);
        assert!(matches!(r.as_rsa_sig(), Ok(SignatureBytes::Rsa(_))));
    }

    #[test]
    fn rsa_sig_wrong_length_rejected() {
        // 255 bytes: too short for any valid RSA signature.
        let r = Response::new(vec![0x01u8; 255]);
        assert_eq!(r.as_rsa_sig(), Err(HidError::ResponseWrongLength(255)));
    }

    #[test]
    fn rsa_sig_empty_rejected() {
        let r = Response::new(vec![]);
        assert_eq!(r.as_rsa_sig(), Err(HidError::ResponseWrongLength(0)));
    }

    #[test]
    fn rsa_sig_257_rejected() {
        let r = Response::new(vec![0x01u8; 257]);
        assert_eq!(r.as_rsa_sig(), Err(HidError::ResponseWrongLength(257)));
    }
}
