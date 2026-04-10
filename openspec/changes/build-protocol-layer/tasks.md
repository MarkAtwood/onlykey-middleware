## 1. Workspace Scaffold

- [ ] 1.1 Create `onlykey-middleware/Cargo.toml` with workspace members and shared dependencies (wolfcrypt, thiserror)
- [ ] 1.2 Create `.github/workflows/ci.yml` with: cargo test, cargo clippy, cargo fmt, wasm32 no_std check
- [ ] 1.3 Create `crates/onlykey-hid/Cargo.toml` with wolfcrypt digest feature and hex-literal dev-dep

## 2. Core Types

- [ ] 2.1 Implement `error.rs`: `HidError` enum with `InvalidSlot`, `PayloadTooLarge`, `ResponseTooShort`
- [ ] 2.2 Implement `types.rs`: `PublicKeyBytes`, `SignatureBytes`, `DecryptedBytes` enums with exact byte sizes
- [ ] 2.3 Write unit tests for `types.rs` byte size assertions (Bytes32 = 32, Rsa2048 = 256, etc.)

## 3. Packet Layer

- [ ] 3.1 Implement `packet.rs`: `HidFrame([u8; 64])` with `command()`, `from_bytes()`, `as_bytes()`
- [ ] 3.2 Implement `HidFrame::is_error_response()` and `device_state()` parsing
- [ ] 3.3 Implement `HidFrame::firmware_version()` extraction from UNLOCKED response
- [ ] 3.4 Implement `DeviceState` enum (Unlocked, Locked, Uninitialized)
- [ ] 3.5 Write `packet.rs` unit tests: command_frame_layout, payload_too_large, device_state_unlocked, device_state_locked, is_error_response, binary_not_error

## 4. Command and Key Slot Encoding

- [ ] 4.1 Implement `command.rs`: `Command` enum with correct hex values (Connect=0xE4, GetPubkey=0xEC, Sign=0xED, Decrypt=0xF0, Hmac=0xF5, etc.)
- [ ] 4.2 Implement `KeySlot` enum (RsaStored 1-4, EccStored 101-116) with `validate()`, `wire_slot()`, `is_rsa()`
- [ ] 4.3 Implement `DerivedKeySlot` enum (Ed25519=201, NistP256=202, Secp256k1=203, Curve25519=204) as constants only
- [ ] 4.4 Implement `KeyType` enum with `with_flags(sign, decrypt, backup)` capability bit encoding
- [ ] 4.5 Write unit tests: valid/invalid slot ranges, wire_slot values, key_type flag encoding

## 5. Multi-Packet Chunking

- [ ] 5.1 Implement `large_message.rs`: `encode_large_message(cmd, slot_byte, payload)` with MAX_PAYLOAD=768, CHUNK_SIZE=57
- [ ] 5.2 Implement non-last frame 0xFF sentinel and last-frame actual-length encoding
- [ ] 5.3 Implement `LargeMessageFrames` wrapper with iterator
- [ ] 5.4 Write tests: single_chunk_payload (57 bytes -> 1 frame), two_chunk_payload (58 bytes -> 2 frames), max_payload_succeeds (768 bytes), over_max_fails (769 bytes), frame_count (768 bytes -> 14 frames), all_frames_correct_header

## 6. Challenge Derivation

- [ ] 6.1 Implement `challenge.rs`: `derive_challenge(payload: &[u8]) -> [u8; 3]` using wolfcrypt SHA-256
- [ ] 6.2 Use bytes [0], [15], [31] of SHA-256(payload), each `% 6 + 1`
- [ ] 6.3 Write tests: challenge_empty_payload -> [4,4,2], challenge_hello -> [3,4,1], challenge_range (all values in [1,6] for all seed bytes)

## 7. Response Parsing

- [ ] 7.1 Implement `response.rs`: `Response { bytes: Vec<u8> }` with `is_error()`, `error_message()`
- [ ] 7.2 Implement typed accessors: `as_ecc32()`, `as_ecc64()`, `as_rsa2048()`, `as_rsa4096()`
- [ ] 7.3 Implement signature accessors: `as_ed25519_sig()`, `as_ecdsa_p256_sig()`, `as_rsa_sig()`
- [ ] 7.4 Implement `as_shared_secret32()` for ECDH responses
- [ ] 7.5 Write tests: response_too_short returns HidError, error_message extraction, correct byte copying

## 8. CI Verification

- [ ] 8.1 Verify `cargo test -p onlykey-hid` passes
- [ ] 8.2 Verify `cargo check -p onlykey-hid --target wasm32-unknown-unknown` passes (no_std guard)
- [ ] 8.3 Verify `cargo clippy -p onlykey-hid -- -D warnings` passes
