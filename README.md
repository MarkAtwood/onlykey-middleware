# OnlyKey Middleware

Unofficial, community-written middleware for the [OnlyKey](https://onlykey.io) hardware security key.
This project is **not affiliated with, endorsed by, or supported by CryptoTrust LLC** (the OnlyKey
hardware manufacturer). OnlyKey(R) is a trademark of CryptoTrust LLC.

**License: GPL-3.0-or-later**

---

## Why This Exists

The OnlyKey hardware is a capable security key, but the official software does not expose
its cryptographic keys through PKCS#11 or scdaemon. That means it cannot be used with
standard tooling: OpenSSL, OpenVPN, Thunderbird, SSH via p11-kit, or GnuPG's smartcard
interface all expect one of those two interfaces. This project fills that gap without
requiring any firmware changes.

## What This Is

OnlyKey Middleware exposes the OnlyKey's hardware-backed cryptographic keys through standard software
interfaces: PKCS#11 (for OpenSSL, OpenVPN, Thunderbird, SSH via p11-kit) and a virtual smart card
daemon (for GnuPG `scdaemon` and PIV tooling).

No firmware changes are required. The middleware speaks the existing OnlyKey HID wire protocol.

## Crates

```
onlykey-hid          no_std HID wire protocol: frame encoding, challenge derivation,
                     response parsing. Compilable for embedded targets and wasm32.

onlykey-transport    std device layer: USB I/O via hidapi, device open/connect,
                     sign/decrypt/HMAC/get_pubkey operations, challenge display.

onlykey-pkcs11       PKCS#11 3.2 shared library (cdylib). Drop into any PKCS#11-aware
                     application. Supports async sessions, Ed25519, ECDSA P-256/K1,
                     RSA-OAEP, ECDH key derivation, SHA-256/384/512 digest.

onlykey-vcard        Virtual smart card daemon. Presents OnlyKey as an OpenPGP
                     Card 3.4 and PIV token to pcscd / scdaemon via ifd-vpcd.

onlykey-tool         Admin CLI. Bootstraps slots.toml from the device,
                     imports/generates certificates for PIV slots.
```

## Status

| Component | Status |
|-----------|--------|
| `onlykey-hid` | Working. |
| `onlykey-transport` | Working. |
| `onlykey-pkcs11` | Working. Hardware tests require a physical device. |
| `onlykey-vcard` | Working. OpenPGP Card 3.4 and PIV applets; vpcd TCP bridge for pcscd. Hardware tests require a physical device. |
| `onlykey-tool` | Working. |

## Requirements

- Rust 1.75 or later
- hidapi (for USB access)
- A connected, unlocked OnlyKey

## Build

```sh
cargo build --release -p onlykey-pkcs11
```

The shared library lands at `target/release/libonlykey_pkcs11.so` (Linux) or
`target/release/libonlykey_pkcs11.dylib` (macOS).

## Configuration

### udev (Linux)

Copy the udev rules so the current user can access the device without root:

```sh
sudo cp config/udev/70-onlykey.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules && sudo udevadm trigger
```

Add yourself to the `plugdev` group if you are not already a member:

```sh
sudo usermod -aG plugdev "$USER"   # log out and back in to take effect
```

### slots.toml

The PKCS#11 module needs to know which algorithm is stored in each OnlyKey slot.
Create `~/.config/onlykey/slots.toml`:

```toml
[ecc]
# Slot numbers 101-116. Values: Ed25519, Curve25519, NistP256, Secp256k1.
101 = "Ed25519"
102 = "Curve25519"
103 = "NistP256"

[rsa]
# Slot numbers 1-4. Values: Rsa2048, Rsa4096.
1 = "Rsa2048"

[labels]
# Optional human-readable labels shown by pkcs11-tool --list-objects.
101 = "My signing key"
102 = "My encryption key"
```

`onlykey-tool generate-config` probes the device and writes this file automatically.

### p11-kit (optional)

To make the module available system-wide via p11-kit:

```sh
sudo cp config/p11-kit/onlykey-pkcs11.module /usr/share/p11-kit/modules/
```

Then verify with:

```sh
p11-kit list-modules
```

## Usage

### pkcs11-tool

```sh
pkcs11-tool --module target/release/libonlykey_pkcs11.so --list-objects
pkcs11-tool --module target/release/libonlykey_pkcs11.so --sign \
    --mechanism ECDSA-SHA256 --id 65 --input-file data.bin --output-file sig.bin
```

### OpenSSH (via p11-kit)

```sh
ssh-add -s "pkcs11:token=OnlyKey"
```

### OpenSSL

```sh
openssl s_client -connect example.com:443 \
    -engine pkcs11 -keyform engine -key "pkcs11:token=OnlyKey;id=%65"
```

## Running Tests

```sh
cargo test --workspace
```

Hardware integration tests (require a physical, unlocked OnlyKey) are gated behind
the `hardware-tests` feature:

```sh
cargo test -p onlykey-pkcs11 --features hardware-tests
```

## Key Slot Reference

| Slot range | Type | Max count |
|------------|------|-----------|
| 1-4 | RSA (2048 or 4096 bit) | 4 |
| 101-116 | ECC (Ed25519, Curve25519, P-256, secp256k1) | 16 |

The OnlyKey firmware does not report which algorithm is stored in a slot; it only
performs operations. The `slots.toml` file is the host-side record of what each
slot holds.

## Firmware Wishlist

These are capabilities the middleware cannot provide without firmware support.
If you have influence over the OnlyKey firmware roadmap, these are the changes
that would have the most impact on this stack.

**1. Unique device serial number.**
Every device currently reports the same serial number (`0.0.0.1` in the
OpenPGP AID, firmware version string in the PKCS#11 token serial). Two
OnlyKeys plugged into the same machine are indistinguishable. NSS, GnuPG, and
p11-kit all assume serial number uniqueness for key management.

**2. Algorithm tag in key responses.**
`OKGETPUBKEY` returns raw key bytes but no algorithm identifier. A 32-byte
response could be Ed25519 or Curve25519 -- there is no way to tell from the
wire. This is why `slots.toml` exists. A single algorithm byte in the response
would let the middleware auto-discover slot configuration and eliminate the
need for manual configuration entirely.

**3. On-device key generation.**
The OpenPGP `GENERATE ASYMMETRIC KEY PAIR` command is unsupported because the
firmware has no key generation capability. Users must generate keys externally
and load them in, which means the private key touches the host machine before
it reaches the device. This undermines the core security guarantee of a
hardware key.

**4. Persistent signature counter.**
The OpenPGP specification requires a monotonically increasing, persistent
signature counter. The current implementation tracks it in RAM and resets to
zero every time the daemon restarts. The firmware maintaining this counter
(and returning it via `OKGETPUBKEY` or a dedicated command) would make the
OpenPGP card interface fully spec-compliant.

**5. Key generation timestamp or fingerprint.**
`gpg --card-status` displays all-zero fingerprints because the device stores
no metadata about loaded keys. If the firmware returned the key fingerprint or
generation timestamp alongside the public key bytes, the OpenPGP applet could
populate these fields correctly and key ownership would be verifiable without
an external trust anchor.

## Contributing

This is a personal project. Issues and pull requests are welcome. Please open an
issue before writing a large patch so we can agree on the approach.

## Disclaimer

This software communicates with OnlyKey hardware over USB using the publicly
documented HID protocol. It does not modify device firmware. It is provided
as-is with no warranty. Use at your own risk.

The OnlyKey firmware source is available at
https://github.com/trustcrypto/OnlyKey-Firmware under its own license.

## License

Copyright (C) 2024 OnlyKey Middleware Contributors

This program is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 3 of the License, or (at your option) any later
version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with
this program. If not, see https://www.gnu.org/licenses/.
