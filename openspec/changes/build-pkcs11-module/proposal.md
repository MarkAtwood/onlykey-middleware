## Why

The highest-leverage deliverable: once `onlykey-pkcs11.so` exists, OnlyKey keys appear
as hardware-backed tokens to OpenVPN, OpenConnect, Thunderbird, Firefox, ssh-agent via
p11-kit, `pkcs11-tool`, and any OpenSSL application using `pkcs11:` URIs. This closes
the compatibility gap that has blocked enterprise OnlyKey adoption.

PKCS#11 3.2 async sessions are included here (not a stretch goal) because they allow
callers to display "waiting for touch..." in their own UI rather than blocking their event
loop. This is critical for GUI applications that would otherwise hang while waiting for
button press.

## What Changes

- New crate `crates/onlykey-pkcs11` (cdylib) added to the workspace
- Exports `C_GetFunctionList` (2.x/3.x base) and `C_GetInterface` (3.0+ for 3.2 access)
- Core logic (`core/`) is `no_std + alloc`; thin std shell provides global allocator
- Implements all 70 PKCS#11 functions (real or `CKR_FUNCTION_NOT_SUPPORTED` stubs)
- Object enumeration driven by `slots.toml` algorithm metadata
- Sync sessions: `C_Sign`/`C_Decrypt` block and return `CKR_FUNCTION_REJECTED` on timeout
- Async sessions (CKF_ASYNC_SESSION): `C_Sign`/`C_Decrypt` return `CKR_PENDING`, background thread
- p11-kit `.module` registration file
- udev rules for non-root HID access

## Capabilities

### New Capabilities
- `pkcs11-module`: PKCS#11 ABI, token/slot info, mechanism dispatch, object model, session management, sync and async signing, p11-kit integration, udev rules

## Impact

- Depends on: `build-transport-layer` must be complete
- Unblocks: user can authenticate to OpenVPN, sign emails in Thunderbird, use `pkcs11-tool`
- PKCS#11 3.2 types (`CKR_PENDING`, `CK_FUNCTION_LIST_3_2`, etc.) are not in any published Rust crate and must be defined manually in `src/ck32.rs`
