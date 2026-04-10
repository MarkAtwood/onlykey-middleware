# AGENTS.md -- OnlyKey Middleware Suite

## How to read the spec tree

`openspec/specs/` contains settled architectural and interface decisions. Read the
relevant spec before writing code that implements a capability. Specs use SHALL/MUST
for normative constraints and SHOULD/MAY for advisory ones.

`openspec/changes/` contains in-progress implementation work. Each subdirectory has:
- `proposal.md` -- why the work exists and what it produces
- `design.md`   -- technical decisions and rationale
- `tasks.md`    -- concrete implementation checklist

**Before starting any task:** read the relevant `design.md`. Before changing behavior
that a spec describes: read the spec and propose a change rather than diverging silently.

## Task tracking with bd (beads)

This project uses **bd** for all task tracking. Do NOT use TodoWrite, TaskCreate,
or markdown TODO lists.

```bash
bd ready              # Show available (unblocked) work
bd show <id>          # Full issue details
bd update <id> --claim  # Claim before starting
bd close <id>         # Mark complete when done
```

When you begin a task from `tasks.md`, create a `bd` issue referencing the change name
and task number (e.g. "build-protocol-layer task 1.2"). Mark in_progress when you start,
closed when the checklist item is done and its tests pass.

## When to proceed vs. ask for judgment

**Proceed autonomously when:**
- Implementing a task whose `design.md` fully specifies the approach
- Writing tests with independent oracles (published test vectors, cross-validation between two implementations)
- Adding CI checks, udev rules, p11-kit config, or Cargo.toml dependencies
- Fixing compilation errors without changing externally observable behavior

**Stop and ask when:**
- A wolfcrypt API you need is not exposed by the Rust bindings at `~/wolfssl-rs/wolfcrypt`
- A task's design.md has an `<!-- OPEN:` annotation
- Your implementation would change something a spec marks as SHALL (externally observable)
- Any destructive operation (wipe key slot, drop certstore table, force-push)
- The `Secp256k1Raw([u8; 64])` workaround needs revisiting (wolfcrypt binding gap)
- You need to add a wolfcrypt feature flag not already listed in the relevant Cargo.toml

## Settled constraints -- do not change without a formal change proposal

| Constraint | Value / Rule |
|---|---|
| Firmware changes | None in scope. All middleware uses existing HID protocol. |
| Crypto backend | wolfcrypt only (`~/wolfssl-rs/wolfcrypt`). No ring. No RustCrypto software primitives. |
| no_std | onlykey-hid must pass `cargo check --target wasm32-unknown-unknown` |
| Challenge timeout | Default 60 seconds, configurable. |
| Timeout error code | `CKR_FUNCTION_REJECTED` -- NOT `CKR_FUNCTION_CANCELED` |
| Derived key slots | Slots 201-204 are agent-only. Never exposed as PKCS#11 objects. |
| RSA public exponent | Always 65537. Device returns modulus only. |
| PublicKey type | Rich wolfcrypt typed enum (validated at construction). Not raw bytes. |
| PKCS#11 async | CKR_PENDING / 3.2 async sessions are required, not a stretch goal. |
| CKM_RSA_PKCS | NOT advertised. wolfcrypt hashes internally; advertising causes double-hash. |
| License | Apache 2.0. No GPL (PKCS#11 modules load into GPL-incompatible apps). |
| slots.toml | Required for ECC algorithm disambiguation. Missing entry -> stderr warning + slot skipped. |
| secp256k1 public key | Stored as `Secp256k1Raw([u8; 64])` -- wolfcrypt Rust binding does not yet expose this curve via `EcdsaVerifyingKey<C>`. |

## Key slot ranges

| Type | Range | Notes |
|------|-------|-------|
| RSA stored | 1-4 | wire byte = slot number |
| ECC stored | 101-116 | wire byte = slot number |
| Derived Ed25519 | 201 | agent-only, never in PKCS#11 |
| Derived NistP256 | 202 | agent-only |
| Derived secp256k1 | 203 | agent-only |
| Derived Curve25519 | 204 | agent-only |
| HMAC slot 1 | 129 (wire) | hmac() uses slot 1 or 2 |
| HMAC slot 2 | 130 (wire) | |

## OpenPGP Card <-> OnlyKey slot mapping (default)

| OpenPGP role | OnlyKey ECC slot | Algorithm |
|---|---|---|
| Sig (signing) | 101 | Ed25519 |
| Dec (decryption) | 102 | Curve25519 |
| Aut (authentication) | 103 | Ed25519 |

## PIV <-> OnlyKey slot mapping (default)

| PIV slot | Key ref | OnlyKey ECC slot | Algorithm |
|---|---|---|---|
| PIV Authentication | 9A | 104 | NistP256 |
| Digital Signature | 9C | 105 | NistP256 |
| Key Management | 9D | 106 | Curve25519 |
| Card Authentication | 9E | 107 | NistP256 (no PIN required) |
