## Context

PKCS#11 is a C ABI: the loading application `dlopen`s the `.so` and calls function
pointers. Rust panics must not cross the FFI boundary. The module must maintain correct
global state across calls from multiple threads and multiple applications (via p11-kit).

## Goals / Non-Goals

**Goals:**
- PKCS#11 2.40 / 3.0 / 3.2 compliance for the subset of functions that OnlyKey supports
- System-wide p11-kit registration so no per-application config is needed
- Async sessions (CKR_PENDING) so GUI callers are not blocked during button wait

**Non-Goals:**
- Token initialization, PIN change, key generation on device (OnlyKey manages this separately)
- PKCS#11 Wrap/Unwrap mechanisms
- `C_EncryptInit` / `C_Encrypt` (no symmetric encryption exposed through PKCS#11)
- Windows native (no p11-kit on Windows; direct module path works for OpenVPN/Thunderbird)

## Decisions

**Global state: `OnceLock<Mutex<Option<ModuleState>>>`.**
PKCS#11 requires exactly one initialization. `OnceLock` gives us a lazily initialized
singleton; `Mutex<Option<_>>` lets `C_Finalize` clear state while `C_Initialize` can
re-populate it on subsequent calls (some applications call Initialize/Finalize in a loop).

**Device mutex is `Arc<Mutex<OnlyKeyDevice>>`.**
The device is single-threaded. Any code path needing the device (sign, decrypt, enumerate)
must hold this mutex. Async operations hold it for the duration of the button wait.
No concurrent device access is possible -- this is correct behavior, not a limitation.

**Core logic in `core/` module is `no_std + alloc`.**
The `ObjectTable`, `SessionTable`, `SlotAlgorithm`, and mechanism dispatch don't need std.
Keeping them `no_std` documents the design intent and makes the module's std surface
explicit. The std shell (`lib.rs`, `ffi.rs`) provides the global allocator.

**`catch_panic` wraps all C_* functions.**
`std::panic::catch_unwind` catches Rust panics at the FFI boundary and returns
`CKR_GENERAL_ERROR`. Without this, a panic causes undefined behavior (crossing the FFI
boundary with an unwinding Rust stack is UB in the C calling convention).

**PKCS#11 3.2 types defined in `ck32.rs`.**
No published crate exposes `CKR_PENDING`, `CK_FUNCTION_LIST_3_2`, `CK_INTERFACE`, or the
async function signatures as of early 2026. We define them from the OASIS PKCS#11 3.2
spec headers. `cryptoki-sys` provides 2.x/3.x base types.

**CKM_RSA_PKCS is not advertised.**
wolfcrypt's `sign_pkcs1v15_with_digest` hashes its input internally. PKCS#11 callers
pass a pre-hashed DigestInfo to `C_Sign(CKM_RSA_PKCS)`. Advertising the mechanism would
cause a double-hash (wolfcrypt hashes the already-hashed DigestInfo). The spec-compliant
mechanisms `CKM_SHA256_RSA_PKCS` etc. pre-hash in software (wolfcrypt) and pass the raw
hash to the device, which then applies PKCS#1 v1.5 padding without re-hashing.

**`slots.toml` for ECC algorithm disambiguation.**
`OKGETPUBKEY` does not return the key algorithm. A 32-byte response could be Ed25519 or
Curve25519; a 64-byte response could be P-256 or secp256k1. `slots.toml` is written by
`onlykey-tool` when keys are loaded. Absent entry -> warning + skip (not error), so a
partially configured device still exposes the slots it can.

**`C_Login` maps to device unlock state check.**
`CKF_PROTECTED_AUTHENTICATION_PATH` means PIN entry happens on the device. The PKCS#11
caller cannot provide a PIN. `C_Login` with a non-null PIN pointer is an error. With a
null PIN, we check `device.get_device_state()` and return `CKR_USER_ALREADY_LOGGED_IN`
if unlocked or `CKR_PIN_INCORRECT` if locked (prompting the caller to wait for device unlock).

**Async path: background thread holds device mutex.**
When `C_Sign` is called on an async session, a `std::thread` is spawned that takes
`Arc::clone(&state.device)` and then locks it. The module lock is released before the
thread acquires the device lock -- preventing deadlock. Only one async operation can run
at a time (serialized by the device mutex), which is correct for a single-device token.

**`apply_prehash` handles compound mechanisms.**
For `CKM_ECDSA_SHA256` etc., `apply_prehash` uses wolfcrypt SHA-256/384/512 to digest
the accumulated data before building the `SignOp`. Raw mechanisms (`CKM_ECDSA`,
`CKM_EDDSA`) pass data through unchanged.

## Open Questions

<!-- OPEN: C_SignUpdate/C_SignFinal for async sessions -- should intermediate data
     accumulate in the session accumulator and then spawn the thread on C_SignFinal?
     Current plan: yes. Verify this matches what callers expect (NSS, OpenSSL). -->

<!-- OPEN: p11-kit on macOS -- the .module file format is the same but the path
     differs. Should the macOS .dylib be a separate install target or same source
     with platform-conditional path? Decision deferred to macOS stretch goal phase. -->

<!-- OPEN: C_DeriveKey returns a CK_OBJECT_HANDLE for the derived key. For
     CKM_ECDH1_DERIVE (Curve25519 shared secret), the output is 32 bytes. How do
     we represent this as a PKCS#11 secret key object? Need to decide whether to
     create a transient CKO_SECRET_KEY object in the session or return the raw bytes
     via CKA_VALUE. Most callers use the derived bytes immediately and discard them. -->
