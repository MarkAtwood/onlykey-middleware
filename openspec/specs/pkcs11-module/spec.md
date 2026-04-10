### Requirement: PKCS#11 ABI Entry Points
The shared library SHALL export `C_GetFunctionList` (PKCS#11 2.x/3.x base) and `C_GetInterface` (PKCS#11 3.0+).

#### Scenario: C_GetFunctionList
- **WHEN** a caller invokes `C_GetFunctionList(&pp_function_list)`
- **THEN** `*pp_function_list` is set to a static `CK_FUNCTION_LIST` with version `{3, 1}`
- **AND** all 70 function slots are populated (real implementations or `CKR_FUNCTION_NOT_SUPPORTED` stubs)
- **AND** `CKR_OK` is returned

#### Scenario: C_GetInterface for PKCS#11 3.2
- **WHEN** `C_GetInterface("PKCS 11", {3, 2}, &pp_interface, 0)` is called
- **THEN** `*pp_interface` points to a `CK_INTERFACE` containing a `CK_FUNCTION_LIST_3_2`
- **AND** `CKR_OK` is returned

#### Scenario: C_GetInterface for base version
- **WHEN** `C_GetInterface("PKCS 11", {3, 0}, &pp_interface, 0)` is called
- **THEN** the classic `CK_FUNCTION_LIST` is returned

### Requirement: Token Flags
The token SHALL advertise `CKF_TOKEN_INITIALIZED | CKF_PROTECTED_AUTHENTICATION_PATH | CKF_LOGIN_REQUIRED | CKF_ASYNC_SESSION_SUPPORTED`.

#### Scenario: Token info flags
- **WHEN** `C_GetTokenInfo` is called
- **THEN** the returned `CK_TOKEN_INFO.flags` includes all four flags
- **AND** `CKF_PROTECTED_AUTHENTICATION_PATH` indicates PIN entry is on the device, not in software

### Requirement: Single Token Slot
The module SHALL present exactly one slot with slot ID 0.

#### Scenario: Slot enumeration
- **WHEN** `C_GetSlotList(CK_TRUE, slots, &count)` is called
- **THEN** count = 1 and slots[0] = 0

### Requirement: Mechanism Table
The module SHALL advertise exactly the mechanisms listed below and no others.
`CKM_SHA256_HMAC`, `CKM_SHA384_HMAC`, and `CKM_SHA512_HMAC` were removed because
the device HMAC path always produces HMAC-SHA1 (20-byte output) regardless of the
requested algorithm -- advertising the larger variants would silently return wrong MACs.

#### Scenario: Advertised mechanisms
- **WHEN** `C_GetMechanismList(0, list, &count)` is called
- **THEN** the list contains exactly these 15 mechanisms:
  - `CKM_ECDSA` (raw, no pre-hash)
  - `CKM_ECDSA_SHA1`, `CKM_ECDSA_SHA256`, `CKM_ECDSA_SHA384`, `CKM_ECDSA_SHA512`
  - `CKM_EDDSA` (Ed25519)
  - `CKM_SHA256_RSA_PKCS`, `CKM_SHA384_RSA_PKCS`, `CKM_SHA512_RSA_PKCS`
  - `CKM_RSA_PKCS_OAEP` (decrypt)
  - `CKM_ECDH1_DERIVE` (ECDH key derivation)
  - `CKM_SHA256`, `CKM_SHA384`, `CKM_SHA512` (software digest via wolfcrypt)
  - `CKM_SHA_1_HMAC` (device HMAC-SHA1 via hardware HMAC slot; 20-byte output)

#### Scenario: CKM_RSA_PKCS is not advertised
- **WHEN** `C_GetMechanismList` is called
- **THEN** `CKM_RSA_PKCS` is NOT in the returned list
- **AND** reason: wolfcrypt's sign_pkcs1v15_with_digest hashes internally; advertising CKM_RSA_PKCS causes double-hashing of caller-pre-hashed DigestInfo

### Requirement: Object Enumeration at Initialization
`C_Initialize` SHALL enumerate all key objects by querying the device for each slot listed in `slots.toml`.

#### Scenario: Successful enumeration
- **WHEN** `C_Initialize` succeeds
- **THEN** `CKO_PUBLIC_KEY` and `CKO_PRIVATE_KEY` objects are created for each slot present in `slots.toml`
- **AND** each pair has matching `CKA_ID` (the slot number as a single byte)

#### Scenario: Missing slots.toml entry for ECC slot
- **WHEN** an ECC slot has no entry in `slots.toml`
- **THEN** a warning is printed to stderr: `"onlykey-pkcs11: slot N: no algorithm in slots.toml, skipping"`
- **AND** that slot is not included in the object table

### Requirement: Key Object Attributes
Every key object SHALL return correct values for `CKA_CLASS`, `CKA_KEY_TYPE`, `CKA_ID`, `CKA_LABEL`, and curve-specific attributes.

#### Scenario: ECC public key attributes
- **WHEN** `C_GetAttributeValue` is called for a P-256 public key object
- **THEN** `CKA_CLASS` = `CKO_PUBLIC_KEY`
- **AND** `CKA_KEY_TYPE` = `CKK_EC`
- **AND** `CKA_EC_PARAMS` = DER-encoded P-256 OID `{0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07}`
- **AND** `CKA_EC_POINT` = DER OCTET STRING wrapping uncompressed point (04 || x || y)

#### Scenario: Ed25519 public key attributes
- **WHEN** `C_GetAttributeValue` is called for an Ed25519 public key object
- **THEN** `CKA_EC_PARAMS` = DER-encoded Ed25519 OID `{0x06,0x03,0x2B,0x65,0x70}`

### Requirement: Sync Session Signing
On a synchronous session, `C_Sign` SHALL block until the device returns a signature or the challenge timeout elapses.

#### Scenario: Successful sync sign
- **WHEN** `C_SignInit` + `C_Sign` is called on a sync session
- **THEN** the call blocks (holding the device mutex)
- **AND** returns the signature bytes on success with `CKR_OK`

#### Scenario: Sync timeout
- **WHEN** the user does not press buttons within the challenge timeout
- **THEN** `C_Sign` returns `CKR_FUNCTION_REJECTED`
- **AND** NOT `CKR_FUNCTION_CANCELED`

### Requirement: Async Session Returns CKR_PENDING
On a session opened with `CKF_ASYNC_SESSION`, `C_Sign` SHALL return `CKR_PENDING` immediately and launch a background thread.

#### Scenario: Async sign start
- **WHEN** `C_SignInit` + `C_Sign` is called on an async session
- **THEN** a background thread is spawned holding the device mutex
- **AND** `CKR_PENDING` is returned to the caller immediately

#### Scenario: C_AsyncComplete -- still running
- **WHEN** `C_AsyncComplete` is called before the background thread finishes
- **THEN** `CKR_PENDING` is returned (non-blocking poll)

#### Scenario: C_AsyncComplete -- finished
- **WHEN** `C_AsyncComplete` is called after the background thread finishes
- **THEN** the signature bytes are written to the caller's buffer
- **AND** `CKR_OK` is returned

#### Scenario: Async timeout
- **WHEN** the background thread finishes with `TransportError::ChallengeTimeout`
- **THEN** `C_AsyncComplete` returns `CKR_FUNCTION_REJECTED`

### Requirement: C_Login Behavior
`C_Login` with `CKU_USER` SHALL check the device unlocked state. PIN is entered on the device, not passed in software.

#### Scenario: Login with null PIN
- **GIVEN** `CKF_PROTECTED_AUTHENTICATION_PATH` is set
- **WHEN** `C_Login(session, CKU_USER, NULL, 0)` is called and the device is unlocked
- **THEN** `CKR_OK` is returned

#### Scenario: Login rejected if device is locked
- **WHEN** `C_Login` is called and the device reports itself locked
- **THEN** `CKR_PIN_INCORRECT` is returned (caller should prompt user to enter PIN on device)

### Requirement: C_Logout is a No-Op
`C_Logout` SHALL return `CKR_OK` without sending any command to the device.

#### Scenario: Logout
- **WHEN** `C_Logout` is called
- **THEN** `CKR_OK` is returned
- **AND** no HID frames are written to the device

### Requirement: Global State Singleton
The module SHALL maintain a single `OnceLock<Mutex<Option<ModuleState>>>`. Only one device is supported per process.

#### Scenario: C_Initialize / C_Finalize lifecycle
- **WHEN** `C_Initialize` is called
- **THEN** `ModuleState` is created and placed in the lock
- **WHEN** `C_Finalize` is called
- **THEN** `ModuleState` is dropped, device connection is closed

#### Scenario: Concurrent device access
- **WHEN** two threads each call `C_Sign`
- **THEN** the second call blocks until the first releases the device mutex
- **AND** they do not interleave

### Requirement: p11-kit Registration
The module SHALL install a `.module` file readable by p11-kit.

#### Scenario: p11-kit module file
- **WHEN** `config/p11-kit/onlykey-pkcs11.module` is installed to `/usr/share/p11-kit/modules/`
- **THEN** p11-kit discovers onlykey-pkcs11.so system-wide
- **AND** the file contains `module: onlykey-pkcs11.so` and `managed: yes`

### Requirement: udev Rules for Non-Root Access
The installed udev rules SHALL grant the session user access to OnlyKey HID devices without requiring root.

#### Scenario: udev rule format
- **WHEN** `60-onlykey.rules` is installed to `/etc/udev/rules.d/`
- **THEN** both VID/PID pairs (16C0:0486 and 1D50:60FC) are matched
- **AND** `TAG+="uaccess"` grants access on systemd systems
- **AND** `GROUP="plugdev" MODE="0660"` serves as fallback on non-systemd systems

### Requirement: Panic Safety
All `C_*` functions SHALL be wrapped in `catch_panic` to prevent Rust panics from crossing the FFI boundary.

#### Scenario: Panic in C_Sign
- **WHEN** code inside `C_Sign` panics
- **THEN** `catch_panic` catches the unwind
- **AND** `CKR_GENERAL_ERROR` is returned to the caller
- **AND** the process does not abort
