### Requirement: Device Discovery
`OnlyKeyDevice::open` SHALL try both known VID/PID pairs and return the first unlocked device found.

#### Scenario: Both VID/PID pairs tried
- **WHEN** `OnlyKeyDevice::open(config)` is called
- **THEN** it enumerates HID devices matching `(0x16C0, 0x0486)` (classic OnlyKey) and `(0x1D50, 0x60FC)` (OnlyKey DUO)
- **AND** returns the first device that responds to OKCONNECT with `DeviceState::Unlocked`

#### Scenario: No device found
- **WHEN** no matching HID device is present or all are locked
- **THEN** `TransportError::NotFound` is returned

#### Scenario: Device is locked
- **WHEN** a matching device responds to OKCONNECT with `DeviceState::Locked`
- **THEN** `TransportError::Locked` is returned

#### Scenario: Device is uninitialized
- **WHEN** a matching device responds with `DeviceState::Uninitialized`
- **THEN** `TransportError::Uninitialized` is returned

### Requirement: OKCONNECT Timestamp
`OnlyKeyDevice::open` SHALL send the current Unix timestamp in big-endian bytes as the OKCONNECT payload.

#### Scenario: Timestamp format
- **WHEN** OKCONNECT is issued
- **THEN** the 8-byte big-endian representation of the current Unix timestamp is placed in frame bytes [7..15]

### Requirement: Blocking Signing
`OnlyKeyDevice::sign` SHALL block until the device responds with a signature or the challenge timeout elapses.

#### Scenario: Successful ECC sign
- **GIVEN** the device is unlocked and slot 101 holds an Ed25519 key
- **WHEN** `device.sign(SignOp::Ed25519 { slot: EccStored(101), data }, display)` is called
- **THEN** the challenge code is displayed via `display.show([a, b, c])`
- **AND** the call blocks until the user presses buttons
- **AND** `Signature::Ed25519([u8; 64])` is returned on success

#### Scenario: Challenge timeout
- **WHEN** the user does not press buttons within `config.challenge_timeout` (default 60 s)
- **THEN** `TransportError::ChallengeTimeout` is returned

#### Scenario: Device error during sign
- **WHEN** the device responds with an ASCII error string (begins with "Error")
- **THEN** `TransportError::Device(message)` is returned

### Requirement: Typed Public Key API
`OnlyKeyDevice::get_ecc_pubkey` SHALL require an explicit `EccAlgorithm` hint and return a wolfcrypt-validated `PublicKey`.

#### Scenario: Ed25519 key retrieval
- **WHEN** `get_ecc_pubkey(slot, EccAlgorithm::Ed25519)` is called
- **THEN** the 32-byte device response is passed to `Ed25519VerifyingKey::from_bytes`
- **AND** `PublicKey::Ed25519(vk)` is returned on success

#### Scenario: RSA key retrieval
- **WHEN** `get_pubkey(KeySlot::RsaStored(n))` is called
- **THEN** the modulus is combined with the fixed exponent 65537 to construct `RsaPublicKey`
- **AND** `PublicKey::Rsa(pk)` is returned

### Requirement: EccAlgorithm Enum
`get_ecc_pubkey` SHALL require an explicit `EccAlgorithm` hint because the device response length alone cannot distinguish Ed25519 from Curve25519 (both 32 bytes) or NistP256 from Secp256k1 (both 64 bytes).

#### Scenario: EccAlgorithm variants
- **WHEN** an ECC public key is retrieved
- **THEN** the caller provides one of: `EccAlgorithm::Ed25519`, `EccAlgorithm::NistP256`, `EccAlgorithm::Curve25519`, `EccAlgorithm::Secp256k1`
- **AND** this hint determines how the raw bytes are interpreted and validated

#### Scenario: Algorithm disambiguation from slots.toml
- **WHEN** `enumerate_objects` is called during PKCS#11 initialization
- **THEN** the algorithm for each slot is read from `slots.toml`
- **AND** a slot with no entry in `slots.toml` generates a warning and is skipped (not an error)

### Requirement: HMAC-SHA1 Challenge-Response
`OnlyKeyDevice::hmac` SHALL address HMAC slots via wire bytes 129 (slot 1) and 130 (slot 2) and NOT require a button press.

#### Scenario: HMAC slot wire encoding
- **WHEN** `hmac(1, challenge)` is called
- **THEN** the frame is sent with slot byte = 129

#### Scenario: HMAC response without user interaction
- **WHEN** `hmac` is called
- **THEN** no `ChallengeDisplay::show` call is made
- **AND** the call waits up to 3 seconds for the 20-byte response

### Requirement: Challenge Display Trait
`ChallengeDisplay` SHALL be a Send + Sync trait with a single `show(&self, digits: [u8; 3])` method.

#### Scenario: TtyDisplay writes to /dev/tty
- **WHEN** `TtyDisplay::show([a, b, c])` is called
- **THEN** the message is written to `/dev/tty` if available
- **AND** falls back to stderr if `/dev/tty` cannot be opened

#### Scenario: ExecDisplay substitutes digits
- **WHEN** `ExecDisplay("/usr/bin/notify %d %d %d").show([3, 4, 1])` is called
- **THEN** `/usr/bin/notify 3 4 1` is executed via `sh -c`

### Requirement: Transport Error Types
`TransportError` SHALL include `ChallengeTimeout` as a distinct variant that maps to `CKR_FUNCTION_REJECTED` in the PKCS#11 layer.

#### Scenario: ChallengeTimeout -> CKR_FUNCTION_REJECTED
- **WHEN** `TransportError::ChallengeTimeout` reaches the PKCS#11 ffi layer
- **THEN** `CKR_FUNCTION_REJECTED` (not `CKR_FUNCTION_CANCELED`) is returned to the caller

### Requirement: Windows HID Write Prefix
On Windows, `RawIo::write` SHALL prepend a 0x00 report-ID byte before the 64-byte frame.

#### Scenario: Windows prefix at runtime
- **WHEN** compiled for `target_os = "windows"`
- **THEN** `hid.write` receives 65 bytes with byte[0] = 0x00

### Requirement: RSA Public Exponent Constant
The RSA public exponent SHALL always be 65537, declared as `RSA_PUBLIC_EXPONENT: u32 = 65537`.

#### Scenario: RSA key construction
- **WHEN** an RSA public key is constructed from device-supplied modulus bytes
- **THEN** the exponent used is always 65537, never read from the device
