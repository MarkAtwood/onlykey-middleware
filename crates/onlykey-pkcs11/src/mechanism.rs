//! PKCS#11 mechanism table and resolution.
//!
//! Exactly 15 mechanisms are advertised per openspec/specs/pkcs11-module/spec.md.
//! `CKM_RSA_PKCS` is explicitly excluded -- wolfcrypt hashes internally, so
//! advertising it would cause double-hashing of pre-hashed DigestInfo blocks.
//! `CKM_SHA256_HMAC`, `CKM_SHA384_HMAC`, and `CKM_SHA512_HMAC` were removed
//! because the device HMAC path always produces HMAC-SHA1 (20-byte output);
//! advertising larger variants would silently return wrong MACs (OnlyKey-3b1).

use cryptoki_sys::{
    CKF_DECRYPT, CKF_DERIVE, CKF_DIGEST, CKF_SIGN, CKM_ECDH1_DERIVE, CKM_ECDSA, CKM_ECDSA_SHA1,
    CKM_ECDSA_SHA256, CKM_ECDSA_SHA384, CKM_ECDSA_SHA512, CKM_EDDSA, CKM_RSA_PKCS_OAEP, CKM_SHA256,
    CKM_SHA256_RSA_PKCS, CKM_SHA384, CKM_SHA384_RSA_PKCS, CKM_SHA512, CKM_SHA512_RSA_PKCS,
    CKM_SHA_1_HMAC, CK_MECHANISM_INFO, CK_MECHANISM_TYPE,
};

use crate::object::SlotAlgorithm;

/// The 15 mechanisms this token advertises.
///
/// Order matches the spec enumeration in openspec/specs/pkcs11-module/spec.md.
/// This list is exhaustive -- any mechanism not here returns `CKR_MECHANISM_INVALID`.
///
/// `CKM_SHA_1_HMAC` is wired through `C_SignInit`/`C_Sign` to the device hardware
/// HMAC slots (OnlyKey-3b1). The device always produces a 20-byte HMAC-SHA1 output.
/// `CKM_SHA256_HMAC`/`SHA384_HMAC`/`SHA512_HMAC` were removed: the device HMAC path
/// is always SHA-1 regardless of the requested algorithm.
pub const MECHANISMS: &[CK_MECHANISM_TYPE] = &[
    CKM_ECDSA,
    CKM_ECDSA_SHA1,
    CKM_ECDSA_SHA256,
    CKM_ECDSA_SHA384,
    CKM_ECDSA_SHA512,
    CKM_EDDSA,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA512_RSA_PKCS,
    CKM_RSA_PKCS_OAEP,
    CKM_ECDH1_DERIVE,
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512,
    CKM_SHA_1_HMAC,
];

/// Signing mechanisms -- the subset of `MECHANISMS` for which `C_SignInit` is valid.
pub const SIGN_MECHANISMS: &[CK_MECHANISM_TYPE] = &[
    CKM_ECDSA,
    CKM_ECDSA_SHA1,
    CKM_ECDSA_SHA256,
    CKM_ECDSA_SHA384,
    CKM_ECDSA_SHA512,
    CKM_EDDSA,
    CKM_SHA256_RSA_PKCS,
    CKM_SHA384_RSA_PKCS,
    CKM_SHA512_RSA_PKCS,
    CKM_SHA_1_HMAC,
];

/// A resolved signing mechanism including any pre-hash algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignMechanism {
    /// Raw ECDSA -- payload is the pre-computed hash (passed through unchanged).
    EcdsaRaw,
    /// ECDSA with SHA-1 pre-hash computed in software.
    EcdsaSha1,
    /// ECDSA with SHA-256 pre-hash computed in software.
    EcdsaSha256,
    /// ECDSA with SHA-384 pre-hash computed in software.
    EcdsaSha384,
    /// ECDSA with SHA-512 pre-hash computed in software.
    EcdsaSha512,
    /// Raw Ed25519 -- full message (<=768 bytes) passed to device.
    EdDsa,
    /// RSA PKCS#1 v1.5 with SHA-256: software hashes, device signs.
    RsaSha256,
    /// RSA PKCS#1 v1.5 with SHA-384.
    RsaSha384,
    /// RSA PKCS#1 v1.5 with SHA-512.
    RsaSha512,
    /// HMAC-SHA1 computed by device hardware HMAC slot.
    /// Data is passed directly as challenge bytes; output is always 20 bytes.
    HmacSha1,
}

/// Hash algorithm used in compound signing mechanisms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    Sha1,
    Sha256,
    Sha384,
    Sha512,
}

impl SignMechanism {
    /// Return the pre-hash algorithm, if any.
    ///
    /// `HmacSha1` returns `None` because HMAC data is not pre-hashed in software;
    /// the device applies HMAC-SHA1 internally to the raw challenge bytes.
    pub fn hash_alg(self) -> Option<HashAlg> {
        match self {
            SignMechanism::EcdsaSha1 => Some(HashAlg::Sha1),
            SignMechanism::EcdsaSha256 => Some(HashAlg::Sha256),
            SignMechanism::EcdsaSha384 => Some(HashAlg::Sha384),
            SignMechanism::EcdsaSha512 => Some(HashAlg::Sha512),
            SignMechanism::RsaSha256 => Some(HashAlg::Sha256),
            SignMechanism::RsaSha384 => Some(HashAlg::Sha384),
            SignMechanism::RsaSha512 => Some(HashAlg::Sha512),
            SignMechanism::EcdsaRaw | SignMechanism::EdDsa | SignMechanism::HmacSha1 => None,
        }
    }
}

/// Resolve a raw `CK_MECHANISM_TYPE` to a typed `SignMechanism`.
///
/// Returns `None` if the mechanism type is not a signing mechanism.
pub fn resolve_sign_mechanism(t: CK_MECHANISM_TYPE) -> Option<SignMechanism> {
    match t {
        CKM_ECDSA => Some(SignMechanism::EcdsaRaw),
        CKM_ECDSA_SHA1 => Some(SignMechanism::EcdsaSha1),
        CKM_ECDSA_SHA256 => Some(SignMechanism::EcdsaSha256),
        CKM_ECDSA_SHA384 => Some(SignMechanism::EcdsaSha384),
        CKM_ECDSA_SHA512 => Some(SignMechanism::EcdsaSha512),
        CKM_EDDSA => Some(SignMechanism::EdDsa),
        CKM_SHA256_RSA_PKCS => Some(SignMechanism::RsaSha256),
        CKM_SHA384_RSA_PKCS => Some(SignMechanism::RsaSha384),
        CKM_SHA512_RSA_PKCS => Some(SignMechanism::RsaSha512),
        CKM_SHA_1_HMAC => Some(SignMechanism::HmacSha1),
        _ => None,
    }
}

/// Check that a sign mechanism is compatible with the key algorithm.
///
/// Returns `false` if the mechanism would produce an incorrect result with
/// the given key type (e.g. ECDSA with an Ed25519 key).
pub fn check_mechanism_key_compat(mech: SignMechanism, alg: SlotAlgorithm) -> bool {
    match (mech, alg) {
        // ECDSA mechanisms require an ECDSA-capable key.
        (
            SignMechanism::EcdsaRaw
            | SignMechanism::EcdsaSha1
            | SignMechanism::EcdsaSha256
            | SignMechanism::EcdsaSha384
            | SignMechanism::EcdsaSha512,
            SlotAlgorithm::NistP256 | SlotAlgorithm::Secp256k1,
        ) => true,
        // EdDSA requires Ed25519.
        (SignMechanism::EdDsa, SlotAlgorithm::Ed25519) => true,
        // RSA mechanisms require an RSA key.
        (
            SignMechanism::RsaSha256 | SignMechanism::RsaSha384 | SignMechanism::RsaSha512,
            SlotAlgorithm::Rsa2048 | SlotAlgorithm::Rsa4096,
        ) => true,
        // HMAC-SHA1 requires an HMAC slot key.
        (SignMechanism::HmacSha1, SlotAlgorithm::HmacSha1) => true,
        _ => false,
    }
}

/// Build `CK_MECHANISM_INFO` for a mechanism type.
///
/// Returns `None` if the type is not in `MECHANISMS`.
pub fn mechanism_info(t: CK_MECHANISM_TYPE) -> Option<CK_MECHANISM_INFO> {
    if !MECHANISMS.contains(&t) {
        return None;
    }
    let (min_bits, max_bits, flags) = match t {
        CKM_ECDSA | CKM_ECDSA_SHA1 | CKM_ECDSA_SHA256 | CKM_ECDSA_SHA384 | CKM_ECDSA_SHA512 => {
            (256, 521, CKF_SIGN)
        }
        CKM_EDDSA => (255, 255, CKF_SIGN),
        CKM_SHA256_RSA_PKCS | CKM_SHA384_RSA_PKCS | CKM_SHA512_RSA_PKCS => (2048, 4096, CKF_SIGN),
        CKM_RSA_PKCS_OAEP => (2048, 4096, CKF_DECRYPT),
        CKM_ECDH1_DERIVE => (256, 521, CKF_DERIVE),
        CKM_SHA256 | CKM_SHA384 | CKM_SHA512 => (0, 0, CKF_DIGEST),
        // CKM_SHA_1_HMAC is backed by hardware HMAC slots 1 and 2 (OnlyKey-3b1).
        // The device HMAC key is entirely hardware-bound; key size 0/0 because
        // there is no meaningful host-side key size to advertise.
        CKM_SHA_1_HMAC => (0, 0, CKF_SIGN),
        _ => return None,
    };
    Some(CK_MECHANISM_INFO {
        ulMinKeySize: min_bits,
        ulMaxKeySize: max_bits,
        flags,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mechanisms_has_exactly_15_entries() {
        // 15 per openspec/specs/pkcs11-module/spec.md -- this is a settled constraint.
        // 5 ECDSA + EdDSA + 3 RSA-sign + RSA-OAEP + ECDH + 3 digest + 1 HMAC-SHA1.
        assert_eq!(MECHANISMS.len(), 15);
    }

    #[test]
    fn ckm_rsa_pkcs_not_in_mechanisms() {
        let ckm_rsa_pkcs: CK_MECHANISM_TYPE = 0x00000001;
        assert!(
            !MECHANISMS.contains(&ckm_rsa_pkcs),
            "CKM_RSA_PKCS must not be advertised"
        );
    }

    #[test]
    fn resolve_sign_mechanism_coverage() {
        for &m in SIGN_MECHANISMS {
            assert!(resolve_sign_mechanism(m).is_some(), "missing: 0x{:08x}", m);
        }
    }

    #[test]
    fn ecdsa_p256_compat() {
        assert!(check_mechanism_key_compat(
            SignMechanism::EcdsaSha256,
            SlotAlgorithm::NistP256
        ));
        assert!(!check_mechanism_key_compat(
            SignMechanism::EcdsaSha256,
            SlotAlgorithm::Ed25519
        ));
        assert!(!check_mechanism_key_compat(
            SignMechanism::EcdsaSha256,
            SlotAlgorithm::Rsa2048
        ));
    }

    #[test]
    fn eddsa_only_for_ed25519() {
        assert!(check_mechanism_key_compat(
            SignMechanism::EdDsa,
            SlotAlgorithm::Ed25519
        ));
        assert!(!check_mechanism_key_compat(
            SignMechanism::EdDsa,
            SlotAlgorithm::NistP256
        ));
    }

    #[test]
    fn rsa_mechanisms_for_rsa_keys() {
        assert!(check_mechanism_key_compat(
            SignMechanism::RsaSha256,
            SlotAlgorithm::Rsa2048
        ));
        assert!(check_mechanism_key_compat(
            SignMechanism::RsaSha512,
            SlotAlgorithm::Rsa4096
        ));
        assert!(!check_mechanism_key_compat(
            SignMechanism::RsaSha256,
            SlotAlgorithm::NistP256
        ));
    }

    #[test]
    fn hmac_sha1_only_for_hmac_key() {
        assert!(check_mechanism_key_compat(
            SignMechanism::HmacSha1,
            SlotAlgorithm::HmacSha1
        ));
        assert!(!check_mechanism_key_compat(
            SignMechanism::HmacSha1,
            SlotAlgorithm::Ed25519
        ));
        assert!(!check_mechanism_key_compat(
            SignMechanism::HmacSha1,
            SlotAlgorithm::NistP256
        ));
        assert!(!check_mechanism_key_compat(
            SignMechanism::HmacSha1,
            SlotAlgorithm::Rsa2048
        ));
    }

    #[test]
    fn hmac_sha1_resolves() {
        let ckm_sha1_hmac = cryptoki_sys::CKM_SHA_1_HMAC;
        assert_eq!(
            resolve_sign_mechanism(ckm_sha1_hmac),
            Some(SignMechanism::HmacSha1)
        );
    }
}
