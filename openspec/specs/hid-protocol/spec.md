### Requirement: Frame Format
Every HID frame SHALL be exactly 64 bytes, beginning with the 4-byte header `[0xFF, 0xFF, 0xFF, 0xFF]`.

#### Scenario: Single-packet command frame layout
- **WHEN** a command with payload <= 57 bytes is encoded
- **THEN** bytes [0..3] = `0xFF 0xFF 0xFF 0xFF`
- **AND** byte [4] = command byte
- **AND** byte [5] = slot byte
- **AND** byte [6] = field byte
- **AND** bytes [7..7+payload.len()] = payload
- **AND** remaining bytes are zero-padded

#### Scenario: Payload exceeds single-frame limit
- **WHEN** a payload larger than 57 bytes is passed to `HidFrame::command`
- **THEN** `HidError::PayloadTooLarge` is returned

### Requirement: Multi-Packet Chunking
Payloads larger than 57 bytes SHALL be split into 57-byte chunks. The last chunk is marked with its actual byte count in frame[6]; all non-last chunks use `0xFF` as the sentinel in frame[6].

#### Scenario: Two-chunk payload encoding
- **GIVEN** a payload of 58 bytes
- **WHEN** `encode_large_message` is called
- **THEN** 2 frames are produced
- **AND** frame[0] has byte[6] = 0xFF (non-last sentinel)
- **AND** frame[1] has byte[6] = 1 (last chunk, 1 byte payload)

#### Scenario: Maximum payload
- **WHEN** a payload of exactly 768 bytes is encoded
- **THEN** encoding succeeds, producing ceil(768/57) = 14 frames
- **AND** a payload of 769 bytes returns `HidError::PayloadTooLarge`

### Requirement: Key Slot Ranges
`KeySlot::RsaStored` SHALL accept only values 1-4. `KeySlot::EccStored` SHALL accept only values 101-116. All other values SHALL return `HidError::InvalidSlot`.

#### Scenario: Valid ECC slot
- **WHEN** `KeySlot::EccStored(101).validate()` is called
- **THEN** `Ok(())` is returned

#### Scenario: Invalid slot number
- **WHEN** `KeySlot::EccStored(200).validate()` is called
- **THEN** `HidError::InvalidSlot(200)` is returned

### Requirement: Derived Key Slot Constants
Derived key slot wire values (201-204) SHALL be exposed only as constants (`DerivedKeySlot`), not as variants of `KeySlot`. They SHALL NOT be constructible via the PKCS#11 object model.

#### Scenario: Derived slots are constants
- **WHEN** an agent needs to address the derived Ed25519 slot
- **THEN** it uses `DerivedKeySlot::Ed25519 as u8` (= 201) directly
- **AND** no `KeySlot` variant accepts values 201-204

### Requirement: Challenge Derivation
The 3-button challenge code SHALL be derived as: `SHA-256(payload)[i] % 6 + 1` for indices `i in {0, 15, 31}`, yielding three values each in the range [1, 6].

#### Scenario: Known test vector -- empty payload
- **GIVEN** SHA-256("") = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
- **WHEN** `derive_challenge(b"")` is called
- **THEN** the result is `[6, 1, 2]`
  - byte[0]  = 0xe3 = 227; 227 % 6 = 5; 5 + 1 = 6
  - byte[15] = 0x24 = 36;   36 % 6 = 0; 0 + 1 = 1
  - byte[31] = 0x55 = 85;   85 % 6 = 1; 1 + 1 = 2

#### Scenario: Known test vector -- "hello"
- **GIVEN** SHA-256("hello") = `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824`
- **WHEN** `derive_challenge(b"hello")` is called
- **THEN** the result is `[3, 3, 1]`
  - byte[0]  = 0x2c = 44;  44 % 6 = 2; 2 + 1 = 3
  - byte[15] = 0x9e = 158; 158 % 6 = 2; 2 + 1 = 3
  - byte[31] = 0x24 = 36;   36 % 6 = 0; 0 + 1 = 1

#### Scenario: All output values in [1, 6]
- **WHEN** `derive_challenge` is called for any payload
- **THEN** each of the three returned bytes is in the inclusive range [1, 6]

### Requirement: Command Byte Values
Command wire bytes SHALL match the firmware's `okcore.h` TYPE_INIT offsets exactly.

#### Scenario: Command byte encoding
- **WHEN** commands are serialized
- **THEN** their wire values are:
  - `Connect`     = 0xE4
  - `GetLabels`   = 0xE5
  - `GetPubkey`   = 0xEC
  - `Sign`        = 0xED
  - `Decrypt`     = 0xF0
  - `Hmac`        = 0xF5

### Requirement: Device State Detection
`HidFrame::device_state()` SHALL detect device state from OKCONNECT response strings.

#### Scenario: Device state from response
- **WHEN** a frame beginning with `"UNLOCKEDv"` is parsed
- **THEN** `DeviceState::Unlocked` is returned and `firmware_version()` returns the version suffix

- **WHEN** a frame beginning with `"INITIALIZED"` is parsed
- **THEN** `DeviceState::Locked` is returned

- **WHEN** a frame beginning with `"UNINITIALIZED"` is parsed
- **THEN** `DeviceState::Uninitialized` is returned

### Requirement: Error Response Detection
`HidFrame::is_error_response()` SHALL return true if and only if the frame begins with the ASCII bytes `"Error"` and all bytes are printable ASCII or NUL.

#### Scenario: Error response identification
- **WHEN** a frame beginning with `b"Error invalid slot"` is received
- **THEN** `is_error_response()` returns true

- **WHEN** a frame contains binary data (e.g. all 0xAB bytes)
- **THEN** `is_error_response()` returns false

### Requirement: KeyType Flags
The `KeyType` enum SHALL encode both the algorithm (bits 0-2) and capability flags (bits 5-7) in a single wire byte.

#### Scenario: KeyType wire byte encoding
- **WHEN** a key type byte is constructed via `KeyType::with_flags(sign, decrypt, backup)`
- **THEN** bits 0-2 encode the algorithm: Ed25519=1, NistP256=2, Secp256k1=3, Curve25519=4
- **AND** bit 6 (0x40) is set if `sign = true`
- **AND** bit 5 (0x20) is set if `decrypt = true`
- **AND** bit 7 (0x80) is set if `backup = true`

#### Scenario: Typical key type bytes
- Ed25519 signing key:    `0x41` (0x01 | 0x40)
- Curve25519 ECDH key:   `0x24` (0x04 | 0x20)
- NistP256 signing key:  `0x42` (0x02 | 0x40)

### Requirement: Response Public Key Parsing
`Response` SHALL provide typed parsing accessors that validate minimum byte lengths.

#### Scenario: ECC-32 public key
- **WHEN** `Response::as_ecc32()` is called on a response with >= 32 bytes
- **THEN** `PublicKeyBytes::Bytes32([u8; 32])` is returned

- **WHEN** `Response::as_ecc32()` is called on a response with < 32 bytes
- **THEN** `HidError::ResponseTooShort` is returned

#### Scenario: RSA-2048 public key
- **WHEN** `Response::as_rsa2048()` is called on a response with >= 256 bytes
- **THEN** `PublicKeyBytes::Rsa2048(Box<[u8; 256]>)` is returned
