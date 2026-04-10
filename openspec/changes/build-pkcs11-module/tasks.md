## 1. Crate Setup

- [ ] 1.1 Create `crates/onlykey-pkcs11/Cargo.toml` with crate-type = ["cdylib"], deps: onlykey-transport, wolfcrypt (digest/sha256/sha384/sha512), cryptoki-sys, toml, dirs, thiserror
- [ ] 1.2 Create `src/lib.rs` with global `OnceLock<Mutex<Option<ModuleState>>>` and module/session/object declarations

## 2. PKCS#11 3.2 Type Definitions

- [ ] 2.1 Create `src/ck32.rs`: define `CKR_PENDING = 0x00000200`, `CKF_ASYNC_SESSION`, `CKF_ASYNC_SESSION_SUPPORTED`
- [ ] 2.2 Define `CK_ASYNC_ID`, `CK_ASYNC_DATA { rv, output, output_len }` structs
- [ ] 2.3 Define `CK_FUNCTION_LIST_3_2` struct with async function slots: `C_AsyncComplete`, `C_AsyncGetID`, `C_AsyncJoin`
- [ ] 2.4 Define `CK_INTERFACE { name, pFunctionList, flags }` struct
- [ ] 2.5 Write unit test: verify `CKR_PENDING` value matches PKCS#11 3.2 spec (0x200)

## 3. Function Table

- [ ] 3.1 Implement `C_GetFunctionList`: return static `FUNCTION_LIST_V3` with version {3,1}
- [ ] 3.2 Implement `C_GetInterface`: return `INTERFACE_3_2` for version (3,2) or (0,0), `INTERFACE_BASE` for (3,x)/(2,x)
- [ ] 3.3 Populate all 70 slots of `FUNCTION_LIST_V3`: real implementations or `stub::not_supported`

## 4. Error Mapping

- [ ] 4.1 Implement `core/error.rs`: `transport_to_ckr(e: &TransportError) -> CK_RV` mapping
- [ ] 4.2 Map `TransportError::ChallengeTimeout` -> `CKR_FUNCTION_REJECTED` (NOT CKR_FUNCTION_CANCELED)
- [ ] 4.3 Implement `catch_panic(f: F) -> CK_RV` using `std::panic::catch_unwind`

## 5. Token and Slot Info

- [ ] 5.1 Implement `core/token.rs`: `slot_info()` and `token_info(firmware_version, unlocked)`
- [ ] 5.2 Token flags: `CKF_TOKEN_INITIALIZED | CKF_PROTECTED_AUTHENTICATION_PATH | CKF_LOGIN_REQUIRED | CKF_ASYNC_SESSION_SUPPORTED`
- [ ] 5.3 Implement `C_GetSlotList`, `C_GetSlotInfo`, `C_GetTokenInfo`, `C_GetInfo`

## 6. Mechanism Table

- [ ] 6.1 Implement `core/mechanism.rs`: `MECHANISMS` static slice of 17 mechanisms with min/max bits and flags
- [ ] 6.2 Implement `resolve_sign_mechanism(CK_MECHANISM_TYPE) -> Option<SignMechanism>`
- [ ] 6.3 Implement `check_mechanism_key_compat(mech, SlotAlgorithm) -> bool`
- [ ] 6.4 Implement `C_GetMechanismList`, `C_GetMechanismInfo`
- [ ] 6.5 Write unit tests: `resolve_sign_mechanism` coverage for all 17 entries, compat checks

## 7. Object Model

- [ ] 7.1 Implement `core/object.rs`: `SlotAlgorithm` enum (Ed25519, Curve25519, NistP256, Secp256k1, Rsa2048, Rsa4096)
- [ ] 7.2 Implement `SlotAlgorithm::ck_key_type()` and `ec_params()` with hardcoded DER OID bytes
- [ ] 7.3 Implement `SlotAlgorithm::from_str()` for slots.toml parsing
- [ ] 7.4 Implement `KeyObject { handle, class, slot, algorithm, label, id, pubkey_bytes }` with `attribute(CK_ATTRIBUTE_TYPE) -> Option<Vec<u8>>`
- [ ] 7.5 Implement DER OID constants: P256, secp256k1, Ed25519, X25519 (in `oids` module)
- [ ] 7.6 Implement `der_octet_string()` for `CKA_EC_POINT` encoding
- [ ] 7.7 Implement `der_encode_rsa_public_key(modulus)` and `der_integer()` helpers
- [ ] 7.8 Implement `ObjectTable`: `insert()`, `get()`, `find(filters)`, `find_private_for_slot()`
- [ ] 7.9 Write unit tests: `KeyObject::attribute` for all CKA_* types, OID byte correctness, `ObjectTable::find` filtering

## 8. Session Management

- [ ] 8.1 Implement `core/session.rs`: `Session { handle, session_type, pending, find_results, find_offset }`
- [ ] 8.2 Implement `SessionType` enum: `Sync` and `Async { next_async_id: u64 }`
- [ ] 8.3 Implement `PendingOp` enum: None, Sign { slot, mechanism, accumulator }, Async { id, handle, op }
- [ ] 8.4 Implement `AsyncResult` enum: Signature(Vec<u8>), Plaintext(Vec<u8>), Rejected, DeviceError(String)
- [ ] 8.5 Implement `SignMechanism` enum and `HashAlg` enum with `new_hasher()` using wolfcrypt
- [ ] 8.6 Implement `SessionTable`: `open(flags)`, `close(h)`, `close_all()`, `get_mut(h)`
- [ ] 8.7 Implement `C_OpenSession`, `C_CloseSession`, `C_CloseAllSessions`, `C_GetSessionInfo`
- [ ] 8.8 Write unit tests: `SessionTable` open/close/find, async ID incrementing

## 9. Initialization

- [ ] 9.1 Implement `enumerate_objects(device, slot_config)`: walk ECC 101-116 and RSA 1-4, query slots.toml, call get_ecc_pubkey/get_pubkey, insert KeyObject pairs
- [ ] 9.2 Implement `SlotConfig::load()` and `SlotConfig::get_ecc()` / `get_rsa()`
- [ ] 9.3 Implement `C_Initialize`: load Config, parse pReserved overrides, open device, enumerate objects, populate ModuleState
- [ ] 9.4 Implement `C_Finalize`: clear ModuleState, drop device

## 10. Signing

- [ ] 10.1 Implement `apply_prehash(mechanism, data) -> Result<Vec<u8>, CK_RV>` using wolfcrypt for SHA-256/384/512
- [ ] 10.2 Implement `build_sign_op(slot, alg, mechanism, payload) -> Result<SignOp, CK_RV>`
- [ ] 10.3 Implement `C_SignInit`: validate session, mechanism, key; set PendingOp::Sign
- [ ] 10.4 Implement `C_Sign` sync path: pre-hash, build_sign_op, drop module lock, call device.sign(), return CKR_FUNCTION_REJECTED on timeout
- [ ] 10.5 Implement `C_Sign` async path: spawn thread, return CKR_PENDING
- [ ] 10.6 Implement `C_SignUpdate`: accumulate data in session.pending.accumulator
- [ ] 10.7 Implement `C_SignFinal`: flush accumulator through C_Sign logic

## 11. Async Operations

- [ ] 11.1 Implement `C_AsyncComplete`: non-blocking `JoinHandle::is_finished()` check, copy signature bytes on success
- [ ] 11.2 Implement `C_AsyncGetID`: return the current async_id from PendingOp::Async
- [ ] 11.3 Implement `C_AsyncJoin`: blocking wait (join the thread), then write result
- [ ] 11.4 Write unit test: open async session, simulate completed async result, verify CKR_OK on poll

## 12. Decrypt and Derive

- [ ] 12.1 Implement `C_DecryptInit` / `C_Decrypt` for CKM_RSA_PKCS_OAEP (sync and async paths)
- [ ] 12.2 Implement `C_DeriveKey` for CKM_ECDH1_DERIVE: build DecryptOp::Curve25519, call device.decrypt()

## 13. Digest

- [ ] 13.1 Implement `C_DigestInit` / `C_Digest`: CKM_SHA256/384/512 via wolfcrypt (no device call)
- [ ] 13.2 Implement `C_DigestUpdate` / `C_DigestFinal`: accumulate and hash

## 14. Login / Logout

- [ ] 14.1 Implement `C_Login`: check device is unlocked; reject non-null PIN (CKF_PROTECTED_AUTHENTICATION_PATH)
- [ ] 14.2 Implement `C_Logout`: return CKR_OK without any device command

## 15. Object Enumeration

- [ ] 15.1 Implement `C_FindObjectsInit`: parse template into (type, value) filters; run ObjectTable::find()
- [ ] 15.2 Implement `C_FindObjects`: drain find_results vector up to ulMaxObjectCount
- [ ] 15.3 Implement `C_FindObjectsFinal`: clear find_results and find_offset
- [ ] 15.4 Implement `C_GetAttributeValue`: for each attribute in template, call KeyObject::attribute()

## 16. System Integration

- [ ] 16.1 Create `config/p11-kit/onlykey-pkcs11.module` with module path and managed=yes
- [ ] 16.2 Create `config/udev/60-onlykey.rules` for both VID/PID pairs with uaccess and plugdev
- [ ] 16.3 Smoke test: `pkcs11-tool --module ./target/release/libonlykey_pkcs11.so -I` (hardware-tests feature)
- [ ] 16.4 Smoke test: `pkcs11-tool ... -L` and `-O` -- list slots and objects (hardware-tests feature)
- [ ] 16.5 Smoke test: sign with `pkcs11-tool --sign --mechanism ECDSA --id 65` (hardware-tests feature)
- [ ] 16.6 Smoke test: async session with polling caller (custom test binary, hardware-tests feature)
