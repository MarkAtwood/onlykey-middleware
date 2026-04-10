### Requirement: Wolfcrypt-Only Constraint
All cryptographic operations in the middleware stack SHALL use wolfcrypt (`~/wolfssl-rs/wolfcrypt`). No `ring`, `RustCrypto` software primitives, or other crypto libraries SHALL be used for key operations.

#### Scenario: Compilation without ring
- **WHEN** the workspace is built
- **THEN** `ring` does not appear in `Cargo.lock`

#### Scenario: wolfcrypt feature inheritance
- **WHEN** any crate uses wolfcrypt
- **THEN** it declares `wolfcrypt = { workspace = true, features = [...] }` with only the features it actually needs

### Requirement: Crypto Backend Per Crate
Each crate SHALL use only the wolfcrypt features it directly needs.

#### Scenario: onlykey-hid wolfcrypt features
- **WHEN** onlykey-hid is compiled
- **THEN** it uses only the `digest` feature (SHA-256 for challenge derivation)

#### Scenario: onlykey-transport wolfcrypt features
- **WHEN** onlykey-transport is compiled
- **THEN** it uses features: `digest`, `ecdsa`, `ed25519`, `ecdh`, `rsa`, `signature`
- **AND** SHA-256/384/512 are used for RSA pre-hash operations

#### Scenario: onlykey-pkcs11 wolfcrypt features
- **WHEN** onlykey-pkcs11 is compiled
- **THEN** it uses features: `digest`, `sha256`, `sha384`, `sha512`
- **AND** wolfcrypt is used for mechanism pre-hash (CKM_ECDSA_SHA256, CKM_SHA256_RSA_PKCS, etc.) and software digest (CKM_SHA256, CKM_SHA384, CKM_SHA512)

#### Scenario: onlykey-vcard wolfcrypt features
- **WHEN** onlykey-vcard is compiled
- **THEN** it uses features: `digest`, `cipher`, `hmac`
- **AND** SHA-256 is used for certificate fingerprints and TBSCertificate digests
- **AND** AES-CBC is available for protocol-level symmetric crypto if needed

### Requirement: Software Crypto is Not Used for Key Operations
Private key operations (signing, decryption, ECDH) SHALL always happen on the OnlyKey hardware. wolfcrypt SHALL NOT be used to perform these operations in software.

#### Scenario: Sign operation
- **WHEN** `C_Sign` is called
- **THEN** the payload is sent to the device via `OKSIGN`
- **AND** wolfcrypt is NOT used to compute the signature

#### Scenario: ECDH operation
- **WHEN** `C_DeriveKey` (CKM_ECDH1_DERIVE) is called
- **THEN** the peer public key is sent to the device via `OKDECRYPT`
- **AND** wolfcrypt is NOT used to compute the shared secret

### Requirement: wolfcrypt Pre-Hash for PKCS#11 Mechanisms
For compound mechanisms (e.g. CKM_ECDSA_SHA256), wolfcrypt SHALL compute the hash before sending to the device.

#### Scenario: CKM_ECDSA_SHA256 pre-hash
- **WHEN** `C_SignInit(CKM_ECDSA_SHA256)` followed by `C_Sign(data)` is called
- **THEN** wolfcrypt SHA-256 is applied to `data` to produce a 32-byte digest
- **AND** the 32-byte digest is sent to the device as `SignOp::EcdsaP256 { digest }`

### Requirement: Secp256k1 Workaround
secp256k1 public keys SHALL be stored as raw `[u8; 64]` bytes because the wolfcrypt Rust binding does not expose secp256k1 through the `EcdsaVerifyingKey<C>` generic type.

#### Scenario: Secp256k1 key storage
- **WHEN** an secp256k1 public key is retrieved from the device (64-byte response)
- **THEN** it is stored as `PublicKey::Secp256k1Raw([u8; 64])` without wolfcrypt validation
- **AND** a `<!-- OPEN: revisit when wolfcrypt-rs exposes secp256k1 -->` comment is present in the source

### Requirement: RSA DER Encoding
For PKCS#11 `CKA_VALUE` on RSA public key objects, the module SHALL DER-encode the modulus and fixed exponent 65537 as a PKCS#1 `RSAPublicKey` SEQUENCE.

#### Scenario: RSA public key DER encoding
- **WHEN** `KeyObject::attribute(CKA_VALUE)` is called for an RSA object
- **THEN** the result is a DER SEQUENCE `{ INTEGER modulus, INTEGER 65537 }`
- **AND** the modulus is padded with 0x00 if its high bit is set (to keep it positive)
