## Context

`onlykey-hid` provides frame encoding/decoding with no I/O. This crate adds everything
that requires an OS: hidapi enumeration, blocking reads, config file loading, and
wolfcrypt-validated public key construction.

## Goals / Non-Goals

**Goals:**
- Single stable API surface for all device operations
- Timeout and challenge display are configurable without code changes
- wolfcrypt validates public keys at retrieval time (point-on-curve check)

**Non-Goals:**
- PKCS#11 object model, session management, or mechanism dispatch
- Virtual smartcard APDU protocol

## Decisions

**`PublicKey` is a rich wolfcrypt typed enum, not raw bytes.**
Alternatives considered:
- Option B: `PublicKeyBytes` (raw) with delayed validation -- rejected because callers
  could silently misinterpret key material as the wrong curve. Validation at retrieval
  time catches device bugs or protocol mismatches immediately.
- Option C: separate typed constructors per algorithm -- rejected as unnecessary complexity.

The chosen enum (`PublicKey::Ed25519(Ed25519VerifyingKey)`, etc.) prevents misuse at the
type level and makes algorithm mismatches a compile error in the PKCS#11 layer.

**secp256k1 is `Secp256k1Raw([u8; 64])` temporarily.**
The wolfcrypt Rust wrapper at `~/wolfssl-rs/wolfcrypt` does not yet expose secp256k1
through the `EcdsaVerifyingKey<C>` generic. Raw bytes are stored until the binding is
extended. The `CKA_EC_PARAMS` for secp256k1 objects is still returned correctly from
the `SlotAlgorithm::ec_params()` function using the hardcoded OID bytes.

**`get_pubkey(slot)` on ECC slots returns an error directing callers to `get_ecc_pubkey()`.**
This forces the algorithm hint to be explicit. The transport layer cannot infer Ed25519 vs
Curve25519 from the 32-byte response alone -- both look identical on the wire. The PKCS#11
layer knows the algorithm from `slots.toml`; the vcard daemon knows it from its config.

**`wait_for_response()` uses deadline-based polling at 500ms intervals.**
Alternative: single blocking read with `challenge_timeout` ms timeout. Rejected because
some hidapi backends do not support timeouts longer than 2-4 seconds reliably. The
polling loop is more portable.

**RSA public exponent is hardcoded as 65537.**
The OnlyKey firmware always generates RSA keys with e=65537 and does not return the
exponent in `OKGETPUBKEY` responses. This is documented as a constant.

**`read_until_idle` uses 200ms inter-frame gap.**
For ECC keys (1 frame), this adds 200ms latency to the public key read. This is an
acceptable one-time cost at `C_Initialize`. RSA responses (4-8 frames) arrive back-to-back
in well under 200ms; the gap exits cleanly. The 200ms value may be made configurable later.

**HMAC wire slot = 128 + slot_number.**
Wire bytes 129 (slot 1) and 130 (slot 2) match the firmware's HMAC slot addressing.
HMAC does not require a button press -- 3-second read timeout is used.

## Open Questions

<!-- OPEN: The wolfcrypt Rust API for `RsaPublicKey::from_modulus_exponent` -- confirm
     the exact function signature in ~/wolfssl-rs/wolfcrypt. The plan assumes this method
     exists; verify before implementing 7.1. -->

<!-- OPEN: Does wolfcrypt's Ed25519VerifyingKey::from_bytes perform point validation?
     If not, we need an additional check to catch malformed device responses. -->
