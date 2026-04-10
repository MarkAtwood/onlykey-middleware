//! PKCS#11 object model: key types, attributes, and the object table.
//!
//! Each OnlyKey key slot exposes two objects: a `CKO_PUBLIC_KEY` and a
//! `CKO_PRIVATE_KEY`. Public keys carry full attribute sets (CKA_EC_PARAMS,
//! CKA_EC_POINT, CKA_MODULUS, etc.); private keys return the minimal set
//! required by callers plus the mandatory security attributes (CKA_SENSITIVE,
//! CKA_EXTRACTABLE) that every PKCS#11 private key object must expose.

use cryptoki_sys::{
    CKA_CLASS, CKA_DECRYPT, CKA_DERIVE, CKA_EC_PARAMS, CKA_EC_POINT, CKA_ENCRYPT, CKA_EXTRACTABLE,
    CKA_ID, CKA_KEY_TYPE, CKA_LABEL, CKA_MODULUS, CKA_MODULUS_BITS, CKA_PUBLIC_EXPONENT,
    CKA_SENSITIVE, CKA_SIGN, CKA_TOKEN, CKA_VALUE, CKA_VALUE_LEN, CKA_VERIFY, CKK_EC,
    CKK_GENERIC_SECRET, CKK_RSA, CKO_PRIVATE_KEY, CKO_PUBLIC_KEY, CKO_SECRET_KEY,
    CK_ATTRIBUTE_TYPE, CK_BBOOL, CK_OBJECT_CLASS, CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CK_ULONG,
};
use onlykey_transport::PublicKey;
use zeroize::Zeroizing;

/// DER OID constants for ECC curves and algorithms.
pub mod oids {
    /// P-256 (prime256v1): OID 1.2.840.10045.3.1.7
    pub const P256: &[u8] = &[0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
    /// secp256k1: OID 1.3.132.0.10
    pub const SECP256K1: &[u8] = &[0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A];
    /// Ed25519: OID 1.3.101.112
    pub const ED25519: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];
    /// X25519 (Curve25519): OID 1.3.101.110
    pub const X25519: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x6E];
}

// `der_integer` and `der_encode_rsa_public_key` were removed: both were dead
// code (zero callers) and encoded the DER length as a single u8, silently
// truncating for RSA-2048 moduli (256 bytes -> len byte = 0x00, not 0x82 0x01 0x00).
// Issue OnlyKey-8zp. The RSA modulus is exposed directly as CKA_MODULUS raw bytes;
// no DER INTEGER wrapping is needed at the PKCS#11 layer.

/// Build a DER OCTET STRING wrapper: `04 <len> <contents>`.
///
/// Encodes the length per X.690 sec.8.1.3:
/// - <= 127 bytes: single-byte length.
/// - 128-255 bytes: `0x81 <len>`.
/// - 256-65535 bytes: `0x82 <high> <low>`.
pub fn der_octet_string(contents: &[u8]) -> Vec<u8> {
    let len = contents.len();
    // Encode BER-DER length per X.690 sec.8.1.3.
    // Previously used `len as u8` (OnlyKey-0wf): silently wrong at >= 128 bytes
    // (0x80 is the BER indefinite-length sentinel; 129 wraps to 0x81 which looks
    // like a two-byte length prefix with no following length byte).
    let len_enc = match len {
        0..=0x7F => vec![len as u8],
        0x80..=0xFF => vec![0x81, len as u8],
        0x100..=0xFFFF => vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8],
        _ => unreachable!("DER OCTET STRING length {} exceeds 65535", len),
    };
    let mut out = Vec::with_capacity(1 + len_enc.len() + len);
    out.push(0x04);
    out.extend_from_slice(&len_enc);
    out.extend_from_slice(contents);
    out
}

/// Key algorithm for a slot, as loaded from `slots.toml`.
///
/// Used to disambiguate ECC wire responses (32-byte responses could be Ed25519
/// or Curve25519; 64-byte responses could be NistP256 or Secp256k1) and to
/// drive `CKA_KEY_TYPE` and `CKA_EC_PARAMS` population.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SlotAlgorithm {
    Ed25519,
    Curve25519,
    NistP256,
    Secp256k1,
    Rsa2048,
    Rsa4096,
    /// Hardware HMAC-SHA1 slot (OnlyKey HMAC slot 1 or 2).
    /// Exposed as `CKO_SECRET_KEY` / `CKK_GENERIC_SECRET`; produces 20-byte MACs.
    HmacSha1,
}

impl SlotAlgorithm {
    /// Parse an algorithm string from `slots.toml`.
    ///
    /// Accepts case-insensitive names and common aliases.
    pub fn from_name(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "ed25519" => Some(Self::Ed25519),
            "curve25519" | "x25519" => Some(Self::Curve25519),
            "nistp256" | "p-256" | "p256" | "prime256v1" => Some(Self::NistP256),
            "secp256k1" | "k1" => Some(Self::Secp256k1),
            "rsa2048" | "rsa-2048" => Some(Self::Rsa2048),
            "rsa4096" | "rsa-4096" => Some(Self::Rsa4096),
            "hmacsha1" | "hmac-sha1" | "hmac_sha1" => Some(Self::HmacSha1),
            _ => None,
        }
    }

    /// The PKCS#11 key type (`CKK_*`) for this algorithm.
    pub fn ck_key_type(self) -> u64 {
        match self {
            Self::Ed25519 | Self::Curve25519 | Self::NistP256 | Self::Secp256k1 => CKK_EC,
            Self::Rsa2048 | Self::Rsa4096 => CKK_RSA,
            // HMAC slots expose a hardware-bound symmetric key (CKK_GENERIC_SECRET).
            // The key material never leaves the device.
            Self::HmacSha1 => CKK_GENERIC_SECRET,
        }
    }

    /// The DER-encoded OID bytes for `CKA_EC_PARAMS`. Returns `None` for RSA and HMAC.
    pub fn ec_params(self) -> Option<&'static [u8]> {
        match self {
            Self::Ed25519 => Some(oids::ED25519),
            Self::Curve25519 => Some(oids::X25519),
            Self::NistP256 => Some(oids::P256),
            Self::Secp256k1 => Some(oids::SECP256K1),
            Self::Rsa2048 | Self::Rsa4096 | Self::HmacSha1 => None,
        }
    }

    /// RSA key size in bits, if applicable.
    pub fn rsa_bits(self) -> Option<u64> {
        match self {
            Self::Rsa2048 => Some(2048),
            Self::Rsa4096 => Some(4096),
            _ => None,
        }
    }
}

/// A key object (public or private) stored in the object table.
///
/// Public and private key objects always come in pairs with matching `slot`
/// and `id`. The public key carries the actual key material bytes; the private
/// key object is a logical placeholder (key material never leaves the device).
#[derive(Debug, Clone)]
pub struct KeyObject {
    /// PKCS#11 object handle (assigned by the object table).
    pub handle: CK_OBJECT_HANDLE,
    /// `CKO_PUBLIC_KEY` or `CKO_PRIVATE_KEY`.
    pub class: CK_OBJECT_CLASS,
    /// OnlyKey firmware slot number (1-4 for RSA, 101-116 for ECC).
    pub slot: u8,
    /// Key algorithm.
    pub algorithm: SlotAlgorithm,
    /// Human-readable label (from slots.toml, or auto-generated).
    pub label: String,
    /// `CKA_ID` value -- a single byte equal to the slot number.
    pub id: Vec<u8>,
    /// Encoded public key bytes for attribute construction.
    /// For ECC: raw uncompressed point (without 0x04 prefix for P-256, raw for others).
    /// For RSA: raw modulus bytes.
    /// `None` for private key objects.
    pub pubkey_bytes: Option<Vec<u8>>,
}

const CK_TRUE: CK_BBOOL = 1;
const CK_FALSE: CK_BBOOL = 0;

impl KeyObject {
    /// Return the value for a given attribute, or `None` if not supported.
    ///
    /// Returns `Vec<u8>` containing the binary attribute value per PKCS#11
    /// attribute encoding rules.
    pub fn attribute(&self, attr: CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
        match attr {
            CKA_CLASS => Some(self.class.to_ne_bytes().to_vec()),
            CKA_KEY_TYPE => Some(self.algorithm.ck_key_type().to_ne_bytes().to_vec()),
            CKA_ID => Some(self.id.clone()),
            CKA_LABEL => Some(self.label.as_bytes().to_vec()),
            CKA_TOKEN => Some(vec![CK_TRUE]),
            CKA_SIGN => {
                let can_sign = (self.class == CKO_PRIVATE_KEY
                    && !matches!(self.algorithm, SlotAlgorithm::Curve25519))
                    || (self.class == CKO_SECRET_KEY
                        && matches!(self.algorithm, SlotAlgorithm::HmacSha1));
                Some(vec![if can_sign { CK_TRUE } else { CK_FALSE }])
            }
            CKA_DECRYPT => {
                let can_decrypt = self.class == CKO_PRIVATE_KEY
                    && matches!(
                        self.algorithm,
                        SlotAlgorithm::Rsa2048 | SlotAlgorithm::Rsa4096 | SlotAlgorithm::Curve25519
                    );
                Some(vec![if can_decrypt { CK_TRUE } else { CK_FALSE }])
            }
            CKA_DERIVE => {
                let can_derive = self.class == CKO_PRIVATE_KEY
                    && matches!(
                        self.algorithm,
                        SlotAlgorithm::Curve25519 | SlotAlgorithm::NistP256
                    );
                Some(vec![if can_derive { CK_TRUE } else { CK_FALSE }])
            }
            CKA_ENCRYPT | CKA_VERIFY => Some(vec![CK_FALSE]),
            // Private key objects on a hardware token must expose CKA_SENSITIVE
            // and CKA_EXTRACTABLE. Key material never leaves the device, so
            // CKA_SENSITIVE=TRUE and CKA_EXTRACTABLE=FALSE. Tools like pkcs11-tool
            // and OpenSC query these on every key; returning CKR_ATTRIBUTE_TYPE_INVALID
            // (i.e. None) causes them to misclassify or reject the key object.
            // HMAC CKO_SECRET_KEY objects follow the same rule: the HMAC key is
            // hardware-bound and non-extractable.
            CKA_SENSITIVE => {
                if self.class == CKO_PRIVATE_KEY || self.class == CKO_SECRET_KEY {
                    Some(vec![CK_TRUE])
                } else {
                    None
                }
            }
            CKA_EXTRACTABLE => {
                if self.class == CKO_PRIVATE_KEY || self.class == CKO_SECRET_KEY {
                    Some(vec![CK_FALSE])
                } else {
                    None
                }
            }
            CKA_VALUE_LEN => {
                // HMAC-SHA1 output is always 20 bytes. Return the output length
                // so callers can size their MAC buffers without calling C_Sign first.
                if matches!(self.algorithm, SlotAlgorithm::HmacSha1) {
                    Some((20u64).to_ne_bytes().to_vec())
                } else {
                    None
                }
            }
            CKA_EC_PARAMS => self.algorithm.ec_params().map(|oid| oid.to_vec()),
            CKA_EC_POINT => {
                // Public key only; return DER OCTET STRING wrapping the point.
                if self.class != CKO_PUBLIC_KEY {
                    return None;
                }
                let bytes = self.pubkey_bytes.as_ref()?;
                match self.algorithm {
                    SlotAlgorithm::NistP256 => {
                        // Device returns 64 raw bytes (x || y); prepend 0x04.
                        let mut point = Vec::with_capacity(65);
                        point.push(0x04);
                        point.extend_from_slice(bytes);
                        Some(der_octet_string(&point))
                    }
                    SlotAlgorithm::Ed25519 | SlotAlgorithm::Curve25519 => {
                        // 32-byte raw key.
                        Some(der_octet_string(bytes))
                    }
                    SlotAlgorithm::Secp256k1 => {
                        // Device returns 64 raw bytes (x || y); prepend 0x04.
                        let mut point = Vec::with_capacity(65);
                        point.push(0x04);
                        point.extend_from_slice(bytes);
                        Some(der_octet_string(&point))
                    }
                    _ => None,
                }
            }
            CKA_MODULUS => {
                if self.class != CKO_PUBLIC_KEY {
                    return None;
                }
                if matches!(
                    self.algorithm,
                    SlotAlgorithm::Rsa2048 | SlotAlgorithm::Rsa4096
                ) {
                    self.pubkey_bytes.clone()
                } else {
                    None
                }
            }
            CKA_MODULUS_BITS => self.algorithm.rsa_bits().map(|b| b.to_ne_bytes().to_vec()),
            CKA_PUBLIC_EXPONENT => {
                if matches!(
                    self.algorithm,
                    SlotAlgorithm::Rsa2048 | SlotAlgorithm::Rsa4096
                ) {
                    // e = 65537 = 0x010001
                    Some(vec![0x01, 0x00, 0x01])
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// A transient `CKO_SECRET_KEY` object created by `C_DeriveKey`.
///
/// Lives in the object table only for the duration of the session that created it.
/// The secret value is zeroized on drop.
#[derive(Debug)]
pub struct SecretKeyObject {
    pub handle: CK_OBJECT_HANDLE,
    pub session_handle: CK_SESSION_HANDLE,
    value: Zeroizing<Vec<u8>>,
}

impl SecretKeyObject {
    pub fn new(session_handle: CK_SESSION_HANDLE, value: Zeroizing<Vec<u8>>) -> Self {
        SecretKeyObject {
            handle: 0,
            session_handle,
            value,
        }
    }

    /// Return the value for a given attribute, or `None` if not supported.
    pub fn attribute(&self, attr: CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>> {
        match attr {
            CKA_CLASS => Some(CKO_SECRET_KEY.to_ne_bytes().to_vec()),
            CKA_KEY_TYPE => Some((CKK_GENERIC_SECRET as CK_ULONG).to_ne_bytes().to_vec()),
            CKA_VALUE => Some(self.value.to_vec()),
            CKA_VALUE_LEN => Some((self.value.len() as CK_ULONG).to_ne_bytes().to_vec()),
            CKA_TOKEN => Some(vec![CK_FALSE]),
            CKA_SENSITIVE => Some(vec![CK_FALSE]),
            CKA_EXTRACTABLE => Some(vec![CK_TRUE]),
            _ => None,
        }
    }
}

/// The global object table populated at `C_Initialize`.
///
/// Objects are indexed by their `CK_OBJECT_HANDLE`. Handles are allocated
/// monotonically starting at 1 and shared across all object kinds.
#[derive(Debug, Default)]
pub struct ObjectTable {
    objects: Vec<KeyObject>,
    secrets: Vec<SecretKeyObject>,
    next_handle: CK_OBJECT_HANDLE,
}

impl ObjectTable {
    pub fn new() -> Self {
        Self {
            objects: Vec::new(),
            secrets: Vec::new(),
            next_handle: 1,
        }
    }

    /// Insert a key object, assigning a fresh handle. Returns the handle.
    pub fn insert(&mut self, mut obj: KeyObject) -> CK_OBJECT_HANDLE {
        let handle = self.next_handle;
        self.next_handle += 1;
        obj.handle = handle;
        self.objects.push(obj);
        handle
    }

    /// Insert a transient secret key object for the given session. Returns its handle.
    pub fn insert_secret(
        &mut self,
        session_handle: CK_SESSION_HANDLE,
        value: Zeroizing<Vec<u8>>,
    ) -> CK_OBJECT_HANDLE {
        let handle = self.next_handle;
        self.next_handle += 1;
        let mut obj = SecretKeyObject::new(session_handle, value);
        obj.handle = handle;
        self.secrets.push(obj);
        handle
    }

    /// Retrieve a key object by handle.
    pub fn get(&self, handle: CK_OBJECT_HANDLE) -> Option<&KeyObject> {
        self.objects.iter().find(|o| o.handle == handle)
    }

    /// Retrieve a secret key object by handle, enforcing session ownership.
    ///
    /// Returns `None` if the handle does not exist **or** if it was created by
    /// a different session. PKCS#11 spec sec.10.1: session objects are private
    /// to the session that created them. A caller presenting a handle from
    /// another session must receive `CKR_KEY_HANDLE_INVALID`, not the secret
    /// value. The `session_handle` field on `SecretKeyObject` is the
    /// enforcement point; it is set at `insert_secret` time and never changes.
    pub fn get_secret(
        &self,
        handle: CK_OBJECT_HANDLE,
        session: CK_SESSION_HANDLE,
    ) -> Option<&SecretKeyObject> {
        self.secrets
            .iter()
            .find(|s| s.handle == handle && s.session_handle == session)
    }

    /// Find objects matching all given (type, value) attribute filters.
    ///
    /// Returns handles for all matching `KeyObject`s (token objects, visible to
    /// every session) plus matching `SecretKeyObject`s that belong to
    /// `caller_session`. PKCS#11 spec sec.10.1 requires that session objects
    /// created by one session are invisible to all other sessions, so derived
    /// secrets from session A must not appear in C_FindObjects results for
    /// session B.
    ///
    /// An empty filter slice matches everything.
    pub fn find(
        &self,
        filters: &[(CK_ATTRIBUTE_TYPE, Vec<u8>)],
        caller_session: CK_SESSION_HANDLE,
    ) -> Vec<CK_OBJECT_HANDLE> {
        let key_handles = self
            .objects
            .iter()
            .filter(|obj| {
                filters
                    .iter()
                    .all(|(attr, want)| obj.attribute(*attr).as_deref() == Some(want.as_slice()))
            })
            .map(|o| o.handle);
        let secret_handles = self
            .secrets
            .iter()
            .filter(|s| {
                // Only the owning session sees its derived secrets.
                s.session_handle == caller_session
                    && filters
                        .iter()
                        .all(|(attr, want)| s.attribute(*attr).as_deref() == Some(want.as_slice()))
            })
            .map(|s| s.handle);
        key_handles.chain(secret_handles).collect()
    }

    /// Find the private key object for a given firmware slot, if any.
    pub fn find_private_for_slot(&self, slot: u8) -> Option<&KeyObject> {
        self.objects
            .iter()
            .find(|o| o.slot == slot && o.class == CKO_PRIVATE_KEY)
    }

    /// Remove all session-bound secret objects for the given session.
    pub fn remove_session_objects(&mut self, session_handle: CK_SESSION_HANDLE) {
        self.secrets.retain(|s| s.session_handle != session_handle);
    }

    /// Remove all session-bound secret objects (called on C_CloseAllSessions).
    pub fn clear_secrets(&mut self) {
        self.secrets.clear();
    }
}

/// Extract raw public key bytes from a `PublicKey` for storage in a `KeyObject`.
///
/// Returns `None` if the key type doesn't have extractable raw bytes (which
/// shouldn't happen since all variants are constructed from wire data).
pub fn pubkey_raw_bytes(key: &PublicKey) -> Option<Vec<u8>> {
    match key {
        // wolfcrypt types don't expose raw bytes directly through the Rust API;
        // we store the bytes obtained from the wire at construction time.
        // The transport layer does not yet expose a "get raw bytes" method on
        // Ed25519VerifyingKey or P256VerifyingKey. We fall back to the response
        // bytes stored by the caller.
        PublicKey::Curve25519Raw(b) => Some(b.to_vec()),
        PublicKey::Secp256k1Raw(b) => Some(b.to_vec()),
        // For Ed25519 and P256, the transport layer validated the key but we
        // need the raw bytes from the wire response -- those are passed separately
        // by enumerate_objects.
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_algorithm_from_str() {
        assert_eq!(
            SlotAlgorithm::from_name("ed25519"),
            Some(SlotAlgorithm::Ed25519)
        );
        assert_eq!(
            SlotAlgorithm::from_name("NistP256"),
            Some(SlotAlgorithm::NistP256)
        );
        assert_eq!(
            SlotAlgorithm::from_name("RSA2048"),
            Some(SlotAlgorithm::Rsa2048)
        ); // case-insensitive
        assert_eq!(
            SlotAlgorithm::from_name("rsa2048"),
            Some(SlotAlgorithm::Rsa2048)
        );
        assert_eq!(SlotAlgorithm::from_name("bogus"), None);
    }

    #[test]
    fn ec_params_oid_p256() {
        let oid = SlotAlgorithm::NistP256.ec_params().unwrap();
        assert_eq!(oid, oids::P256);
        assert_eq!(oid[0], 0x06); // OID tag
    }

    #[test]
    fn ec_params_oid_ed25519() {
        let oid = SlotAlgorithm::Ed25519.ec_params().unwrap();
        assert_eq!(oid, oids::ED25519);
    }

    #[test]
    fn key_object_attribute_class() {
        let obj = KeyObject {
            handle: 1,
            class: CKO_PUBLIC_KEY,
            slot: 101,
            algorithm: SlotAlgorithm::Ed25519,
            label: "test".into(),
            id: vec![101],
            pubkey_bytes: Some(vec![0u8; 32]),
        };
        let class_bytes = obj.attribute(CKA_CLASS).unwrap();
        let class = u64::from_ne_bytes(class_bytes.try_into().unwrap());
        assert_eq!(class, CKO_PUBLIC_KEY);
    }

    #[test]
    fn key_object_ec_point_p256_prepends_04() {
        let raw = vec![0xABu8; 64];
        let obj = KeyObject {
            handle: 2,
            class: CKO_PUBLIC_KEY,
            slot: 101,
            algorithm: SlotAlgorithm::NistP256,
            label: "p256".into(),
            id: vec![101],
            pubkey_bytes: Some(raw),
        };
        let point = obj.attribute(CKA_EC_POINT).unwrap();
        // DER OCTET STRING: 04 41 04 <64 bytes>
        assert_eq!(point[0], 0x04); // OCTET STRING tag
        assert_eq!(point[1], 65); // length = 1 (0x04) + 64
        assert_eq!(point[2], 0x04); // uncompressed point prefix
    }

    #[test]
    fn object_table_find_by_class() {
        let mut table = ObjectTable::new();
        let pub_obj = KeyObject {
            handle: 0,
            class: CKO_PUBLIC_KEY,
            slot: 101,
            algorithm: SlotAlgorithm::Ed25519,
            label: "key".into(),
            id: vec![101],
            pubkey_bytes: Some(vec![0u8; 32]),
        };
        let priv_obj = KeyObject {
            handle: 0,
            class: CKO_PRIVATE_KEY,
            slot: 101,
            algorithm: SlotAlgorithm::Ed25519,
            label: "key".into(),
            id: vec![101],
            pubkey_bytes: None,
        };
        let pub_h = table.insert(pub_obj);
        let priv_h = table.insert(priv_obj);

        // Key objects (token objects) are visible to any session; session 99
        // has no special meaning here -- there are no secrets in this table.
        let class_pub = (CKO_PUBLIC_KEY as u64).to_ne_bytes().to_vec();
        let found = table.find(&[(CKA_CLASS, class_pub)], 99);
        assert_eq!(found, vec![pub_h]);

        let class_priv = (CKO_PRIVATE_KEY as u64).to_ne_bytes().to_vec();
        let found = table.find(&[(CKA_CLASS, class_priv)], 99);
        assert_eq!(found, vec![priv_h]);
    }

    #[test]
    fn secret_objects_are_session_private() {
        // PKCS#11 spec sec.10.1: a CKO_SECRET_KEY object created by C_DeriveKey
        // (session A) must not be visible to any other session (session B).
        // This test covers both get_secret() and find().
        let mut table = ObjectTable::new();

        const SESSION_A: CK_SESSION_HANDLE = 10;
        const SESSION_B: CK_SESSION_HANDLE = 20;

        let secret = zeroize::Zeroizing::new(vec![0xAAu8; 32]);
        let handle = table.insert_secret(SESSION_A, secret);

        // Session A can retrieve the secret by handle.
        assert!(
            table.get_secret(handle, SESSION_A).is_some(),
            "owning session must be able to retrieve its own secret"
        );

        // Session B gets None — same handle, wrong session.
        assert!(
            table.get_secret(handle, SESSION_B).is_none(),
            "foreign session must not be able to retrieve another session's secret"
        );

        // Session A sees the secret in find() results.
        let found_a = table.find(&[], SESSION_A);
        assert!(
            found_a.contains(&handle),
            "owning session must see its secret in find() results"
        );

        // Session B does not see the secret in find() results.
        let found_b = table.find(&[], SESSION_B);
        assert!(
            !found_b.contains(&handle),
            "foreign session must not see another session's secret in find() results"
        );
    }

    #[test]
    fn der_octet_string_short_single_byte_length() {
        let enc = der_octet_string(&[0xAB; 65]);
        assert_eq!(enc[0], 0x04); // OCTET STRING tag
        assert_eq!(enc[1], 65); // single-byte length
        assert_eq!(enc[2], 0xAB); // first content byte
        assert_eq!(enc.len(), 2 + 65);
    }

    #[test]
    fn der_octet_string_128_uses_two_byte_length() {
        // 128-byte contents: was encoded as 0x80 (invalid BER indefinite-length)
        // before the OnlyKey-0wf fix. Must now be 0x81 0x80.
        let enc = der_octet_string(&[0xCC; 128]);
        assert_eq!(enc[0], 0x04); // OCTET STRING tag
        assert_eq!(enc[1], 0x81); // long-form marker: 1 length byte follows
        assert_eq!(enc[2], 128); // length = 128
        assert_eq!(enc[3], 0xCC); // first content byte
        assert_eq!(enc.len(), 3 + 128);
    }

    #[test]
    fn der_octet_string_256_uses_three_byte_length() {
        let enc = der_octet_string(&[0xDD; 256]);
        assert_eq!(enc[0], 0x04); // OCTET STRING tag
        assert_eq!(enc[1], 0x82); // long-form marker: 2 length bytes follow
        assert_eq!(enc[2], 0x01); // high byte of length
        assert_eq!(enc[3], 0x00); // low byte of length (256 = 0x0100)
        assert_eq!(enc[4], 0xDD); // first content byte
        assert_eq!(enc.len(), 4 + 256);
    }
}
