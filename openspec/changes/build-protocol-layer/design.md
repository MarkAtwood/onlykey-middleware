## Context

OnlyKey uses raw USB HID rather than the CCID smartcard USB class. The firmware expects
64-byte frames with a 4-byte `[0xFF*4]` header. Large payloads are split into 57-byte
chunks across multiple frames.

## Goals / Non-Goals

**Goals:**
- Pure Rust protocol implementation, no I/O, no OS dependency
- Compilable as `no_std + alloc` for potential embedded future targets
- All frame serialization and response parsing in one crate with no std leakage

**Non-Goals:**
- HID device enumeration or USB I/O (that is `onlykey-transport`)
- Key type interpretation (the transport layer constructs typed wolfcrypt keys)

## Decisions

**no_std + alloc, not heapless.** We have alloc available and frame sizes are fixed.
heapless adds complexity and only pays off in fully allocator-free embedded contexts,
which is not our target.

**wolfcrypt SHA-256 for challenge derivation.** The challenge must be computed identically
by both the firmware and the host. Firmware uses SHA-256. We must match it. wolfcrypt is
the only crypto library we are allowed to use.

**Challenge derivation uses bytes [0, 15, 31] % 6 + 1.** This formula is taken directly
from the OnlyKey firmware source (`okcore.ino`). The offsets and modulo produce values
in [1,6], matching the 6-button OnlyKey interface.

**DerivedKeySlot is constants-only, not a KeySlot variant.** Derived key slots (201-204)
are for the SSH/GPG agent, not for PKCS#11. Making them `KeySlot` variants would
accidentally expose them through object enumeration. They remain as `#[repr(u8)]` enum
constants that callers must cast explicitly.

**HidError is no_std compatible.** `fmt::Display` is implemented without std. No
`std::error::Error` impl in this crate; `onlykey-transport` wraps these via `From`.

**Multi-packet chunking uses 0xFF as non-last sentinel.** This is the firmware protocol:
byte[6] = 0xFF means "more frames follow"; byte[6] = actual length means "this is the
last frame". The last frame length allows the firmware to distinguish between a 57-byte
last chunk and a non-last chunk.

**MAX_PAYLOAD = 768 bytes.** The firmware's `packet_buffer` is 768 bytes. Payloads
larger than 768 bytes are rejected before any I/O.

## Test Strategy

All tests use known test vectors from independent sources:
- SHA-256("") and SHA-256("hello") are NIST/RFC-published constants
- Frame layout tests check individual byte positions, not round-trip through the same code

CI runs on every commit:
- `cargo test -p onlykey-hid`
- `cargo check -p onlykey-hid --target wasm32-unknown-unknown` (no_std guard)
- `cargo clippy -p onlykey-hid -- -D warnings`

## Open Questions

<!-- OPEN: The firmware challenge formula uses the pre-encryption plaintext payload.
     For operations where the firmware encrypts the buffer before computing the challenge
     (AES-GCM path), do we also hash pre-encryption? Currently assumed yes -- verify
     against a live device capture. -->
