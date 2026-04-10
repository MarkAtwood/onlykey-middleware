## Why

`onlykey-hid` defines the protocol but has no I/O. `onlykey-transport` wraps hidapi
to provide the actual device connection, configuration loading, typed public keys, and
all blocking operations (sign, decrypt, HMAC). Both the PKCS#11 module and the virtual
smartcard daemon depend on this layer.

## What Changes

- New crate `crates/onlykey-transport` added to the workspace
- Implements hidapi-based device discovery for both VID/PID pairs
- Typed public key API: `PublicKey` enum backed by wolfcrypt-validated types
- Blocking sign and decrypt operations with challenge display and timeout
- `Config` struct with XDG loading and environment variable override
- `ChallengeDisplay` trait: `TtyDisplay`, `StderrDisplay`, `ExecDisplay`
- HMAC-SHA1 challenge-response (no button press)
- Hardware test gating via `[features] hardware-tests = []`

## Capabilities

### New Capabilities
- `transport-layer`: device enumeration, config loading, challenge timeout, sign/decrypt/HMAC operations
- `configuration`: XDG path resolution, config.toml parsing, env var override (partial -- shared with PKCS#11 config needs)

## Impact

- Depends on: `build-protocol-layer` must be complete
- Unblocks: `build-pkcs11-module` and `build-virtual-smartcard`
- Integration tests require a physical OnlyKey device; gated behind `hardware-tests` feature
