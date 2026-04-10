## 1. Crate Setup

- [ ] 1.1 Create `crates/onlykey-transport/Cargo.toml` with deps: onlykey-hid, wolfcrypt (digest/ecdsa/ed25519/ecdh/rsa/signature), hidapi, thiserror, toml, dirs
- [ ] 1.2 Create `src/lib.rs` with module declarations and public re-exports

## 2. Error Types

- [ ] 2.1 Implement `error.rs`: `TransportError` with variants: Hid, NotFound, Locked, Uninitialized, ChallengeTimeout, Device, Protocol, Config
- [ ] 2.2 Verify that `TransportError::ChallengeTimeout` maps to `CKR_FUNCTION_REJECTED` (document in code comment, not just here)

## 3. Configuration

- [ ] 3.1 Implement `config.rs`: `Config { challenge_timeout: Duration, challenge_display: ChallengeDisplayKind }` with `Default` (60s, Tty)
- [ ] 3.2 Implement `Config::load()`: read from XDG config path, ignore missing file, parse TOML [device] section
- [ ] 3.3 Implement environment variable override: `ONLYKEY_DEVICE_CHALLENGE_TIMEOUT_SECS`
- [ ] 3.4 Write unit tests: `Config::parse()` for known TOML, env var override, missing file returns default

## 4. Typed Public Key API

- [ ] 4.1 Implement `types.rs`: `PublicKey` enum (Ed25519, NistP256, Secp256k1Raw, Curve25519, Rsa)
- [ ] 4.2 Declare `RSA_PUBLIC_EXPONENT: u32 = 65537`
- [ ] 4.3 Implement `SignOp` enum: Ed25519, EcdsaP256, EcdsaK1, Rsa (each with slot + payload)
- [ ] 4.4 Implement `DecryptOp` enum: Curve25519, NistP256, Rsa (each with slot + peer key / ciphertext)
- [ ] 4.5 Implement `Signature` enum and `Decrypted` enum with corresponding output types
- [ ] 4.6 Implement `EccAlgorithm` enum: Ed25519, NistP256, Curve25519, Secp256k1

## 5. Raw I/O

- [ ] 5.1 Implement `io.rs`: `RawIo { hid: HidDevice, windows_prefix: bool }`
- [ ] 5.2 Implement `write(&frame)`: prepend 0x00 on Windows, write 64 bytes, check short write
- [ ] 5.3 Implement `read_frame(timeout)`: `hid.read_timeout`, return `ChallengeTimeout` on 0 bytes
- [ ] 5.4 Implement `read_until_idle(inter_frame_timeout)`: collect frames until idle gap, return `Response`

## 6. Device Enumeration and Connection

- [ ] 6.1 Implement `device.rs`: `OnlyKeyDevice { io, firmware_version, config }`
- [ ] 6.2 Implement `OnlyKeyDevice::open(config)`: try both VID/PID pairs, call `connect()` on each, return first unlocked
- [ ] 6.3 Implement `connect()`: send OKCONNECT with Unix timestamp, parse UNLOCKED/INITIALIZED/UNINITIALIZED response
- [ ] 6.4 Implement `get_device_state()` method for re-checking state without reconnecting

## 7. Operations

- [ ] 7.1 Implement `ops.rs`: `get_pubkey(slot)` for RSA slots (256/512 byte modulus -> wolfcrypt RsaPublicKey)
- [ ] 7.2 Implement `get_ecc_pubkey(slot, algorithm)`: dispatch by EccAlgorithm, validate with wolfcrypt
- [ ] 7.3 Implement `sign(SignOp, display)` for Ed25519, EcdsaP256, EcdsaK1 (single 64-byte response)
- [ ] 7.4 Implement `sign_rsa(slot, digest, display)` (variable-length response)
- [ ] 7.5 Implement `decrypt(DecryptOp, display)` for Curve25519 (32 bytes), NistP256 (64 bytes), Rsa (variable)
- [ ] 7.6 Implement `hmac(slot, challenge)`: wire slot = 128 + slot; no display call; 3-second read timeout
- [ ] 7.7 Implement `wait_for_response()`: deadline-based 60-second polling with 500ms read intervals and immediate-error detection

## 8. Challenge Display

- [ ] 8.1 Implement `challenge_ui.rs`: `ChallengeDisplay` trait (Send + Sync, `show(&self, [u8; 3])`)
- [ ] 8.2 Implement `StderrDisplay`: write to stderr
- [ ] 8.3 Implement `TtyDisplay`: open `/dev/tty`, fall back to stderr
- [ ] 8.4 Implement `ExecDisplay(String)`: replace `%d` occurrences in order, execute via `sh -c`
- [ ] 8.5 Implement `ChallengeDisplayKind::parse(s)` for "stderr", "tty", "exec:..."
- [ ] 8.6 Write unit tests: `ChallengeDisplayKind::parse` for all variants, ExecDisplay interpolation

## 9. Hardware Integration Tests (hardware-tests feature)

- [ ] 9.1 Open device and verify firmware version starts with "2." or "3."
- [ ] 9.2 Get RSA public key from slot 1 and verify it is `PublicKey::Rsa(_)` (hardware-tests feature)
- [ ] 9.3 Get Ed25519 public key from slot 101 and verify it is `PublicKey::Ed25519(_)` (hardware-tests feature)
