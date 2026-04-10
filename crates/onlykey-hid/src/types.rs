extern crate alloc;
use alloc::boxed::Box;

/// Raw public key bytes returned by the OnlyKey device.
///
/// The variant determines the key size:
/// - `Bytes32`   -- Ed25519 or Curve25519 (32 bytes)
/// - `Bytes64`   -- NIST P-256 or secp256k1 (64-byte uncompressed point, no 0x04 prefix)
/// - `Rsa2048`   -- RSA-2048 modulus (256 bytes, exponent is always 65537)
/// - `Rsa4096`   -- RSA-4096 modulus (512 bytes, exponent is always 65537)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PublicKeyBytes {
    Bytes32([u8; 32]),
    Bytes64([u8; 64]),
    Rsa2048(Box<[u8; 256]>),
    Rsa4096(Box<[u8; 512]>),
}

/// Raw signature bytes returned by the OnlyKey device.
///
/// - `Ed25519`  -- 64-byte EdDSA signature (R || S)
/// - `EcdsaP256` -- 64-byte raw ECDSA signature (r || s, 32 bytes each)
/// - `Rsa`      -- Variable-length PKCS#1 v1.5 signature (256 or 512 bytes)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureBytes {
    Ed25519([u8; 64]),
    EcdsaP256([u8; 64]),
    Rsa(Box<[u8]>),
}

/// Raw decrypted/shared-secret bytes returned by the OnlyKey device.
///
/// - `SharedSecret32` -- 32-byte Curve25519 ECDH output
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecryptedBytes {
    SharedSecret32([u8; 32]),
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;

    #[test]
    fn bytes32_is_32_bytes() {
        assert_eq!(size_of::<[u8; 32]>(), 32);
        let k = PublicKeyBytes::Bytes32([0u8; 32]);
        if let PublicKeyBytes::Bytes32(b) = k {
            assert_eq!(b.len(), 32);
        }
    }

    #[test]
    fn bytes64_is_64_bytes() {
        let k = PublicKeyBytes::Bytes64([0u8; 64]);
        if let PublicKeyBytes::Bytes64(b) = k {
            assert_eq!(b.len(), 64);
        }
    }

    #[test]
    fn rsa2048_is_256_bytes() {
        let k = PublicKeyBytes::Rsa2048(Box::new([0u8; 256]));
        if let PublicKeyBytes::Rsa2048(b) = k {
            assert_eq!(b.len(), 256);
        }
    }

    #[test]
    fn rsa4096_is_512_bytes() {
        let k = PublicKeyBytes::Rsa4096(Box::new([0u8; 512]));
        if let PublicKeyBytes::Rsa4096(b) = k {
            assert_eq!(b.len(), 512);
        }
    }

    #[test]
    fn ed25519_sig_is_64_bytes() {
        let s = SignatureBytes::Ed25519([0u8; 64]);
        if let SignatureBytes::Ed25519(b) = s {
            assert_eq!(b.len(), 64);
        }
    }

    #[test]
    fn shared_secret32_is_32_bytes() {
        let DecryptedBytes::SharedSecret32(b) = DecryptedBytes::SharedSecret32([0u8; 32]);
        assert_eq!(b.len(), 32);
    }
}
