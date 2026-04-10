### Requirement: vpcd TCP Protocol
onlykey-vcard SHALL listen for ifd-vpcd TCP connections on a configurable port (default 35963 for OpenPGP Card, 35964 for PIV) and communicate using the vpcd framing protocol.

#### Scenario: vpcd frame format
- **WHEN** ifd-vpcd sends a frame
- **THEN** the first 2 bytes are a big-endian u16 length N
- **AND** the following N bytes are the payload

#### Scenario: Control messages
- **WHEN** a frame with length 1 is received
- **THEN** the single payload byte is interpreted as: 0x00=off, 0x01=on, 0x02=reset, 0x04=ATR request
- **AND** an ATR request is answered by sending the applet's ATR bytes as a frame

#### Scenario: APDU messages
- **WHEN** a frame with length > 1 is received
- **THEN** the payload is treated as a C-APDU
- **AND** the R-APDU is sent back as a frame with 2-byte big-endian length prefix

### Requirement: Applet Trait
Each smartcard protocol (OpenPGP Card, PIV) SHALL implement the `Applet` trait.

#### Scenario: Applet interface
- **WHEN** an applet is dispatched
- **THEN** it provides: `aid() -> &[u8]`, `atr() -> &[u8]`, `reset()`, and `process(apdu, device, certstore) -> RApdu`

### Requirement: Multiple Applets on Separate Ports
onlykey-vcard SHALL optionally run both OpenPGP Card and PIV applets simultaneously on separate TCP ports.

#### Scenario: Both applets active
- **WHEN** `onlykey-vcard --applet both` is run
- **THEN** two listener threads are started, one per port
- **AND** both share the same `Arc<Mutex<OnlyKeyDevice>>`

### Requirement: OpenPGP Card 3.4 AID
The OpenPGP Card applet SHALL respond to SELECT by AID `D2 76 00 01 24 01 03 04 ...`.

#### Scenario: SELECT accepted
- **WHEN** `00 A4 04 00 [len] [AID]` is received with the OpenPGP Card AID
- **THEN** SW = 90 00 and an FCI template is returned

### Requirement: OpenPGP Card APDU Commands
The OpenPGP Card applet SHALL implement the following commands.

#### Scenario: COMPUTE DIGITAL SIGNATURE (00 2A 9E 9A)
- **GIVEN** PIN1 (0x81) has been verified (device is unlocked)
- **WHEN** the COMPUTE DIGITAL SIGNATURE APDU is received with hash/message data
- **THEN** `OKSIGN` is called on the Sig slot (ECC stored 101)
- **AND** the raw signature bytes are returned with SW = 90 00
- **AND** the signature counter is incremented

#### Scenario: DECIPHER (00 2A 80 86) -- Curve25519
- **GIVEN** PIN2 (0x82) has been verified
- **WHEN** the DECIPHER APDU is received with A6/7F49/86 wrapper containing a 32-byte peer X25519 key
- **THEN** `OKDECRYPT` is called on the Dec slot (ECC stored 102)
- **AND** `[0x00] || shared_secret` is returned with SW = 90 00

#### Scenario: VERIFY PIN (00 20 00 81)
- **WHEN** the VERIFY APDU is received
- **AND** the device is unlocked
- **THEN** the corresponding PIN is marked verified and SW = 90 00 is returned
- **WHEN** the device is locked
- **THEN** SW = 69 82 (Security condition not satisfied) is returned

#### Scenario: GENERATE ASYMMETRIC KEY (00 47)
- **WHEN** the GENERATE KEY APDU is received
- **THEN** `OKGETPUBKEY` is called on the appropriate slot
- **AND** the public key is returned wrapped in `7F 49 [len] 86 [len] [key_bytes]`

#### Scenario: GET DATA (00 CA)
- **WHEN** GET DATA is called for DO 0x6E (Application Related Data)
- **THEN** a composite response including AID, algorithm attributes (C1/C2/C3), fingerprints (C5), and PW status (C4) is returned

### Requirement: OpenPGP Card Key Slot Mapping
OpenPGP Card slots SHALL map to OnlyKey ECC stored slots as follows.

#### Scenario: Default slot mapping
- **WHEN** the OpenPGP Card applet is initialized with default config
- **THEN**: Sig -> ECC stored 101 (Ed25519), Dec -> ECC stored 102 (Curve25519), Aut -> ECC stored 103 (Ed25519)

### Requirement: OpenPGP Card Algorithm Attribute Bytes
Algorithm attributes (DOs C1/C2/C3) SHALL be encoded as the following byte sequences.

#### Scenario: Algorithm attribute byte encoding
- **WHEN** `algorithm_attributes(alg)` is called
- **THEN** the first byte identifies the algorithm type:
  - `0x16` = EdDSA (Ed25519); followed by OID bytes for `1.3.101.112`
  - `0x12` = ECDH (Curve25519); followed by OID bytes for `1.3.101.110`
  - `0x13` = ECDSA (NistP256); followed by OID bytes for P-256 (`1.2.840.10045.3.1.7`)
  - `0x01` = RSA; followed by key size and exponent format bytes

### Requirement: PIV AID
The PIV applet SHALL respond to SELECT by AID `A0 00 00 03 08 00 00 10 00 01`.

#### Scenario: PIV SELECT accepted
- **WHEN** `00 A4 04 00` with the PIV AID is received
- **THEN** SW = 90 00 and FCI template are returned

### Requirement: PIV GENERAL AUTHENTICATE
The PIV applet SHALL implement GENERAL AUTHENTICATE (00 87) for both signing and ECDH key agreement.

#### Scenario: Sign with P-256 key (slot 9C)
- **GIVEN** PIN has been verified (device is unlocked) and key ref = 0x9C
- **WHEN** GENERAL AUTHENTICATE is received with a 7C DO containing an 81 challenge (32-byte digest)
- **THEN** `OKSIGN` is called on ECC stored 105 with the digest
- **AND** response is `7C [len] 82 [sig_len] [signature]` with SW = 90 00

#### Scenario: ECDH with Curve25519 (slot 9D)
- **GIVEN** key ref = 0x9D (Key Management)
- **WHEN** GENERAL AUTHENTICATE is received with a 32-byte peer public key in the challenge
- **THEN** `OKDECRYPT` (Curve25519 ECDH) is called on ECC stored 106
- **AND** shared secret is returned in the 82 response DO

### Requirement: PIV Key Slot Mapping
PIV key references SHALL map to OnlyKey ECC stored slots as follows.

#### Scenario: PIV slot mapping
- **WHEN** PIV applet is initialized with default config
- **THEN**: 9A -> ECC 104 (NistP256), 9C -> ECC 105 (NistP256), 9D -> ECC 106 (Curve25519), 9E -> ECC 107 (NistP256, no PIN required)

### Requirement: PIV Certificate Data Object Tags
PIV certificate data objects SHALL use the following 3-byte tag values in GET DATA and PUT DATA requests.

#### Scenario: PIV cert tag table
- **WHEN** GET DATA is received with a 3-byte tag in the 5C DO
- **THEN** the tag maps to the following slot:
  - `5F C1 05` -> PIV Authentication (key ref 9A, certstore slot `"piv-9A"`)
  - `5F C1 0A` -> Digital Signature (key ref 9C, certstore slot `"piv-9C"`)
  - `5F C1 0B` -> Key Management (key ref 9D, certstore slot `"piv-9D"`)
  - `5F C1 01` -> Card Authentication (key ref 9E, certstore slot `"piv-9E"`)
- **AND** any other tag value returns SW = 6A 82 (File not found)

### Requirement: PIV GET DATA Returns Certstore Certificate
`C_GetData` for a certificate tag SHALL retrieve the DER certificate from the certstore and return it wrapped in the PIV `53/70/71/FE` format.

#### Scenario: Certificate retrieval
- **WHEN** GET DATA with tag `5C 03 5F C1 05` (slot 9A) is received
- **AND** a certificate exists in the certstore for slot `"piv-9A"`
- **THEN** the response is `53 [len] 70 [cert_len] [der] 71 01 00 FE 00` with SW = 90 00

- **WHEN** no certificate exists for the slot
- **THEN** SW = 6A 82 (File not found) is returned

### Requirement: Certstore SQLite Schema
The companion certificate store SHALL be a SQLite database at `$XDG_DATA_HOME/onlykey/certs.db`.

#### Scenario: Schema
- **WHEN** the certstore is opened for the first time
- **THEN** two tables are created:
  - `certs (slot TEXT PRIMARY KEY, der BLOB NOT NULL, label TEXT, created INTEGER)`
  - `metadata (slot TEXT, key TEXT, value BLOB, PRIMARY KEY (slot, key))`

### Requirement: Self-Signed Certificate Generation
`Certstore::generate_self_signed` SHALL fetch the slot's public key from the device, construct a minimal X.509 TBSCertificate, sign it on-device, and store the resulting DER Certificate.

#### Scenario: Ed25519 self-signed cert
- **WHEN** `generate-cert --slot openpgp-sig` is run
- **THEN** the Ed25519 public key for slot 101 is retrieved via OKGETPUBKEY
- **AND** a TBSCertificate is DER-encoded with the given subject CN
- **AND** `OKSIGN` signs the TBSCertificate (raw bytes, Ed25519)
- **AND** the DER Certificate is stored in the `certs` table

### Requirement: APDU Extended Length Support
`Apdu::parse` SHALL support all ISO 7816-4 APDU cases including extended Lc/Le encoding.

#### Scenario: Extended Lc
- **WHEN** an APDU begins with `00 [CLA INS P1 P2] 00 [Lc_hi] [Lc_lo] [data...]`
- **THEN** `Apdu.data` contains exactly `Lc` bytes of data

### Requirement: Response Chaining for Large Responses
When a GET DATA response exceeds 256 bytes, the applet SHALL use GET RESPONSE chaining.

#### Scenario: Long response
- **WHEN** a GET DATA response body is 400 bytes
- **THEN** the first 256 bytes are returned with SW = 61 [remaining_capped]
- **AND** subsequent GET RESPONSE (00 C0 00 00) calls drain the buffer until SW = 90 00
