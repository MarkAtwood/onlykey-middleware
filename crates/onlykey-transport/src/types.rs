use wolfcrypt::ecdsa::P256VerifyingKey;
use wolfcrypt::ed25519::Ed25519VerifyingKey;
use wolfcrypt::rsa::NativeRsaKey;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// RSA public exponent. OnlyKey always uses e=65537; the modulus-only
/// response from OKGETPUBKEY must be combined with this constant.
pub const RSA_PUBLIC_EXPONENT: u32 = 65537;

/// Typed public key validated by wolfcrypt at construction time.
///
/// Every variant ensures the key material is well-formed for its algorithm:
/// - `Ed25519`: `wc_ed25519_import_public` + `wc_ed25519_check_key` validated
/// - `NistP256`: `wc_ecc_import_x963` validated
/// - `Curve25519Raw`: raw 32-byte Curve25519 public key (wolfcrypt Rust binding
///   does not yet expose X25519 point validation; stored raw)
/// - `Secp256k1Raw`: raw 64-byte secp256k1 public key (wolfcrypt Rust binding
///   does not yet expose secp256k1 via `EcdsaVerifyingKey<C>`; stored raw)
/// - `Rsa`: `NativeRsaKey::from_raw_public(modulus, e=65537)` validated
pub enum PublicKey {
    Ed25519(Box<Ed25519VerifyingKey>),
    NistP256(Box<P256VerifyingKey>),
    /// Curve25519 (X25519) key. Stored raw -- wolfcrypt Rust binding does not
    /// yet expose X25519 point validation. See openspec/AGENTS.md settled constraints.
    Curve25519Raw([u8; 32]),
    /// secp256k1 key. Stored raw -- wolfcrypt Rust binding does not yet expose
    /// secp256k1 via `EcdsaVerifyingKey<C>`. See openspec/AGENTS.md settled constraints.
    Secp256k1Raw([u8; 64]),
    Rsa(Box<NativeRsaKey>),
}

// wolfcrypt key types do not implement Debug; provide a minimal implementation.
//
// All variants use `(...)` rather than showing raw bytes. The wolfcrypt-managed
// variants (Ed25519, NistP256, Rsa) do not expose raw bytes at all; the raw
// variants (Curve25519Raw, Secp256k1Raw) could show bytes, but doing so would
// log key material in debug output. Consistent `(...)` across all variants
// avoids the inconsistency and keeps key material out of logs. Issue OnlyKey-q7n6.
impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PublicKey::Ed25519(_) => write!(f, "PublicKey::Ed25519(...)"),
            PublicKey::NistP256(_) => write!(f, "PublicKey::NistP256(...)"),
            PublicKey::Curve25519Raw(_) => write!(f, "PublicKey::Curve25519Raw(...)"),
            PublicKey::Secp256k1Raw(_) => write!(f, "PublicKey::Secp256k1Raw(...)"),
            PublicKey::Rsa(_) => write!(f, "PublicKey::Rsa(...)"),
        }
    }
}

/// Algorithm tag for ECC slot disambiguation.
///
/// Used by callers that know the algorithm from `slots.toml` and need to
/// route the `OKGETPUBKEY` response to the correct `PublicKey` variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EccAlgorithm {
    Ed25519,
    NistP256,
    Curve25519,
    Secp256k1,
}

/// A signing operation to be performed by the device.
#[derive(Debug, Clone)]
pub enum SignOp {
    /// Sign with Ed25519. Payload is the message (< 768 bytes).
    Ed25519 { slot: u8, payload: Vec<u8> },
    /// Sign with ECDSA-P256. Payload is the 32-byte pre-computed SHA-256 digest.
    EcdsaP256 { slot: u8, payload: Vec<u8> },
    /// Sign with ECDSA-K1. Payload is the 32-byte pre-computed hash.
    EcdsaK1 { slot: u8, payload: Vec<u8> },
    /// Sign with RSA (PKCS#1 v1.5). Digest is the DER-encoded DigestInfo.
    Rsa { slot: u8, digest: Vec<u8> },
}

/// A decryption operation to be performed by the device.
#[derive(Debug, Clone)]
pub enum DecryptOp {
    /// Curve25519 ECDH. peer_key is the 32-byte public key.
    Curve25519 { slot: u8, peer_key: [u8; 32] },
    /// NIST P-256 ECDH. peer_key is the 64-byte uncompressed point (no 0x04 prefix).
    NistP256 { slot: u8, peer_key: [u8; 64] },
    /// RSA OAEP decryption. ciphertext is the encrypted blob.
    Rsa { slot: u8, ciphertext: Vec<u8> },
}

/// Output of a sign operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Signature {
    /// 64-byte EdDSA signature (R || S).
    Ed25519([u8; 64]),
    /// 64-byte raw ECDSA signature (r || s, 32 bytes each, no DER wrapping).
    EcdsaRaw([u8; 64]),
    /// Variable-length RSA PKCS#1 v1.5 signature.
    Rsa(Vec<u8>),
}

/// Output of a decrypt operation.
///
/// Both variants contain key material (ECDH shared secret or RSA plaintext)
/// and are zeroized on drop. C_DeriveKey / C_Decrypt immediately wrap the
/// result in `Zeroizing<Vec<u8>>` after match, so the window is brief, but
/// we zeroize on drop here as a defence-in-depth measure. Issue OnlyKey-hey.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub enum Decrypted {
    /// 32-byte Curve25519 shared secret.
    SharedSecret32([u8; 32]),
    /// Variable-length RSA plaintext.
    RsaPlaintext(Vec<u8>),
}
