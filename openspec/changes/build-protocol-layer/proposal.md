## Why

All other middleware crates depend on a correct, tested HID protocol implementation.
Without `onlykey-hid`, nothing else can talk to the device. This is the foundation layer
and must ship first.

## What Changes

- New crate `crates/onlykey-hid` added to the workspace
- Implements the OnlyKey USB HID wire protocol: 64-byte frames, multi-packet chunking, challenge derivation, response parsing
- No I/O -- pure serialization/deserialization, compilable as `no_std + alloc`
- Workspace Cargo.toml and CI are created as part of this change

## Capabilities

### New Capabilities
- `hid-protocol`: frame construction and parsing, command encoding, key slot validation, multi-packet chunking, challenge derivation, response parsing

## Impact

- Workspace scaffold is created here; all subsequent changes build on it
- CI must include a `wasm32-unknown-unknown` compile check to guard no_std compliance
- No other crates exist yet; no breaking changes possible
