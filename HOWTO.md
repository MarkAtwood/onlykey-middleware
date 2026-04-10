# OnlyKey Middleware -- Installation and Usage Guide

This guide covers building and using the full middleware suite: the PKCS#11
module (`onlykey-pkcs11`), the virtual smart card daemon (`onlykey-vcard`),
and the admin tool (`onlykey-tool`).

---

## Table of Contents

1. [Prerequisites](#1-prerequisites)
2. [Build from Source](#2-build-from-source)
3. [Device Access (udev)](#3-device-access-udev)
4. [Configuration](#4-configuration)
   - [slots.toml -- key slot layout](#slotstoml--key-slot-layout)
   - [config.toml -- timeouts and display](#configtoml--timeouts-and-display)
5. [System-wide Registration via p11-kit](#5-system-wide-registration-via-p11-kit)
6. [Verifying the Module](#6-verifying-the-module)
7. [Using with Applications](#7-using-with-applications)
   - [OpenSSH](#openssh)
   - [GnuPG](#gnupg)
   - [OpenVPN](#openvpn)
   - [Thunderbird / Firefox](#thunderbird--firefox)
   - [OpenSSL command line](#openssl-command-line)
8. [Mechanism Reference](#8-mechanism-reference)
9. [Challenge Codes](#9-challenge-codes)
10. [Troubleshooting](#10-troubleshooting)

---

## 1. Prerequisites

### Rust toolchain

Install Rust 1.75 or later via [rustup](https://rustup.rs):

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

### hidapi (system library)

The transport layer uses [hidapi](https://github.com/libusb/hidapi) to talk to
the USB device.

**Debian / Ubuntu:**
```sh
sudo apt install libhidapi-dev pkg-config
```

**Fedora / RHEL:**
```sh
sudo dnf install hidapi-devel pkg-config
```

**Arch:**
```sh
sudo pacman -S hidapi pkg-config
```

**macOS (Homebrew):**
```sh
brew install hidapi pkg-config
```

### wolfSSL / wolfcrypt

The digest code uses wolfcrypt for SHA-256/384/512. The workspace expects the
wolfssl-rs repository checked out as a sibling of this repository:

```
parent-directory/
    OnlyKey/          <- this repository
    wolfssl-rs/       <- https://github.com/wolfSSL/wolfssl-rs
```

Clone wolfssl-rs if you have not already:

```sh
cd ..
git clone https://github.com/wolfSSL/wolfssl-rs.git
cd OnlyKey
```

---

## 2. Build from Source

```sh
cargo build --release -p onlykey-pkcs11
```

The shared library is produced at:

| Platform | Path |
|----------|------|
| Linux | `target/release/libonlykey_pkcs11.so` |
| macOS | `target/release/libonlykey_pkcs11.dylib` |
| Windows | `target/release/onlykey_pkcs11.dll` |

To install it system-wide (adjust the prefix as needed):

```sh
sudo install -Dm755 target/release/libonlykey_pkcs11.so \
    /usr/lib/onlykey/libonlykey_pkcs11.so
```

---

## 3. Device Access (udev)

On Linux, the kernel's HID driver claims OnlyKey by default and the device
node is owned by root. The udev rules grant access to the `plugdev` group and
add the systemd `uaccess` tag so seat-local users receive automatic access.

```sh
sudo cp config/udev/70-onlykey.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

Add your user to `plugdev` if not already a member, then log out and back in:

```sh
sudo usermod -aG plugdev "$USER"
```

Verify access by checking that the device node is readable after re-plugging:

```sh
ls -l /dev/hidraw*   # one of these should be group plugdev, mode 660
```

---

## 4. Configuration

All configuration files live under `$XDG_CONFIG_HOME/onlykey/`, which defaults
to `~/.config/onlykey/`. Create the directory if it does not exist:

```sh
mkdir -p ~/.config/onlykey
```

### slots.toml -- key slot layout

The OnlyKey firmware does not report which algorithm is stored in a slot. The
PKCS#11 module reads `~/.config/onlykey/slots.toml` to learn the layout.
**Without this file, no keys are exposed.**

Key slot numbers:

| Range | Type | Capacity |
|-------|------|----------|
| 1-4 | RSA (2048 or 4096 bit) | 4 slots |
| 101-116 | ECC (Ed25519, Curve25519, P-256, secp256k1) | 16 slots |

Example `~/.config/onlykey/slots.toml`:

```toml
[ecc]
# Slot number = algorithm name (case-insensitive)
# Algorithms: Ed25519, Curve25519 (X25519), NistP256, Secp256k1
101 = "Ed25519"
102 = "Curve25519"
103 = "NistP256"
104 = "Secp256k1"

[rsa]
# Slot number = "Rsa2048" or "Rsa4096"
1 = "Rsa2048"
2 = "Rsa4096"

[labels]
# Optional human-readable labels shown by pkcs11-tool --list-objects
101 = "SSH signing key"
102 = "Encryption key"
103 = "TLS client key"
1   = "Code signing key"
```

Only list slots that actually have keys loaded on your device. Slots not
listed are silently skipped -- they will not appear as token objects.

**Algorithm name aliases accepted (all case-insensitive):**

| Aliases | Stored as |
|---------|-----------|
| `Ed25519` | Ed25519 |
| `Curve25519`, `X25519` | Curve25519 (ECDH only) |
| `NistP256`, `P-256`, `P256`, `prime256v1` | NIST P-256 |
| `Secp256k1`, `K1` | secp256k1 |
| `Rsa2048`, `rsa-2048` | RSA 2048-bit |
| `Rsa4096`, `rsa-4096` | RSA 4096-bit |

### config.toml -- timeouts and display

`~/.config/onlykey/config.toml` controls how long the module waits for a button
press and how the challenge code is shown.

```toml
[device]
# How long to wait for the user to press the OnlyKey button (seconds).
# Default: 60
challenge_timeout_secs = 60

# How the 3-digit challenge code is displayed.
# Options:
#   "tty"          -- write to /dev/tty (default; falls back to stderr)
#   "stderr"       -- write to stderr
#   "exec:<cmd>"   -- run a shell command via sh -c; %d is replaced with each digit
#
# Security note: exec: passes the template to sh -c, so it can contain
# arbitrary shell syntax. This file should be mode 0600 (user-readable only)
# so other local users cannot inject commands through it.
challenge_display = "tty"

# Timeout (milliseconds) for receiving continuation frames after the first
# frame of a multi-frame response. Wireless OnlyKey adapters may have
# ~300 ms inter-frame gaps; the default 500 ms covers these.
# Increase if you see truncated responses with a wireless adapter.
# Default: 500
inter_frame_timeout_ms = 500
```

**Challenge display examples:**

Show a desktop notification (requires `notify-send`):
```toml
challenge_display = "exec:notify-send 'OnlyKey' 'Press: %d %d %d'"
```

Print on stderr (useful in scripts):
```toml
challenge_display = "stderr"
```

**Environment variable overrides:**

These take priority over the config file:

```sh
export ONLYKEY_DEVICE_CHALLENGE_TIMEOUT_SECS=120
export ONLYKEY_DEVICE_INTER_FRAME_TIMEOUT_MS=750
```

---

## 5. System-wide Registration via p11-kit

[p11-kit](https://p11-glue.github.io/p11-glue/p11-kit.html) provides a
single PKCS#11 multiplexer that all applications can use. Registering
`onlykey-pkcs11` with p11-kit means you do not need to configure each
application separately.

**Install p11-kit:**
```sh
sudo apt install p11-kit        # Debian/Ubuntu
sudo dnf install p11-kit        # Fedora/RHEL
sudo pacman -S p11-kit          # Arch
```

**Register the module:**

First, edit `config/p11-kit/onlykey-pkcs11.module` and set the `module:` line
to the absolute path where the library is installed:

```
module: /usr/lib/onlykey/libonlykey_pkcs11.so
```

Then install it:

```sh
# System-wide (all users):
sudo cp config/p11-kit/onlykey-pkcs11.module /etc/pkcs11/modules/

# Or per-user only:
cp config/p11-kit/onlykey-pkcs11.module ~/.config/pkcs11/modules/
```

Verify the module is visible:

```sh
p11-kit list-modules
```

You should see `onlykey-pkcs11` in the output with a token named `OnlyKey`.

---

## 6. Verifying the Module

`pkcs11-tool` (from the `opensc` package) is the standard command-line
interface for any PKCS#11 token.

**Install:**
```sh
sudo apt install opensc        # Debian/Ubuntu
sudo dnf install opensc        # Fedora/RHEL
sudo pacman -S opensc          # Arch
```

**List the token and its objects:**
```sh
pkcs11-tool --module /usr/lib/onlykey/libonlykey_pkcs11.so \
    --list-token-slots
```

```sh
pkcs11-tool --module /usr/lib/onlykey/libonlykey_pkcs11.so \
    --list-objects
```

If p11-kit is configured, you can use the p11-kit proxy instead:
```sh
pkcs11-tool --module /usr/lib/p11-kit-proxy.so --list-objects
```

**Sign a test file:**
```sh
echo "test" > /tmp/test.txt

pkcs11-tool --module /usr/lib/onlykey/libonlykey_pkcs11.so \
    --sign \
    --mechanism ECDSA-SHA256 \
    --id 67 \
    --input-file /tmp/test.txt \
    --output-file /tmp/test.sig
```

The `--id` value is the slot number in decimal (e.g. slot 103 -> `--id 103`,
slot 1 -> `--id 1`). When the OnlyKey prompts, press the three numbered buttons
shown on its display.

---

## 7. Using with Applications

### OpenSSH

The simplest way to use OnlyKey for SSH with p11-kit:

```sh
ssh-add -s /usr/lib/p11-kit-proxy.so
```

Or directly, specifying the module:
```sh
ssh-add -s /usr/lib/onlykey/libonlykey_pkcs11.so
```

Verify the key was added:
```sh
ssh-add -L
```

For a permanent setup, add to `~/.ssh/config`:

```
Host *
    PKCS11Provider /usr/lib/onlykey/libonlykey_pkcs11.so
```

Or use the p11-kit URI form (OpenSSH 8.3+):
```
Host *
    PKCS11Provider /usr/lib/p11-kit-proxy.so
```

**Ed25519 keys only.** OpenSSH will only use `CKO_PRIVATE_KEY` objects whose
algorithm is Ed25519 or ECDSA. RSA keys work if the server accepts them.

### GnuPG

GnuPG uses `scdaemon`, which requires a PC/SC-compatible smart card or a
virtual card. The `onlykey-vcard` virtual smart card daemon provides this
interface via ifd-vpcd. See the onlykey-vcard section of this guide for setup
instructions. Direct PKCS#11 use is not supported by GnuPG's standard toolchain.

### OpenVPN

Add to your OpenVPN client configuration:

```
pkcs11-providers /usr/lib/onlykey/libonlykey_pkcs11.so
pkcs11-id 'pkcs11:token=OnlyKey;id=%67'
```

Replace `%67` with the percent-encoded hex of your slot number (e.g. slot
103 decimal = 0x67 hex = `%67`; slot 1 = `%01`).

Find the exact PKCS#11 URI for your key:
```sh
p11tool --list-privkeys 'pkcs11:token=OnlyKey'
```

### Thunderbird / Firefox

These applications use the NSS PKCS#11 interface. Load the module via the
Security Devices dialog:

1. Open **Settings -> Privacy & Security -> Security Devices** (Thunderbird)
   or **about:preferences#privacy -> Security Devices** (Firefox)
2. Click **Load**
3. Enter module name: `OnlyKey PKCS#11`
4. Enter path: `/usr/lib/onlykey/libonlykey_pkcs11.so`
5. Click **OK**

The OnlyKey's certificates (if any are loaded) and keys will appear in the
certificate manager.

### OpenSSL command line

Using the OpenSSL `pkcs11` engine (requires `libp11`):

```sh
# Install libp11:
sudo apt install libengine-pkcs11-openssl   # Debian/Ubuntu

# Sign:
openssl dgst -engine pkcs11 -keyform engine \
    -sign 'pkcs11:token=OnlyKey;id=%65' \
    -sha256 document.txt

# TLS client authentication:
openssl s_client -connect server:443 \
    -engine pkcs11 \
    -keyform engine -key 'pkcs11:token=OnlyKey;id=%65'
```

For OpenSSL 3.x with the `pkcs11-provider` (preferred over the legacy engine):

```sh
openssl dgst -provider pkcs11 \
    -key 'pkcs11:token=OnlyKey;id=%65' \
    -sha256 document.txt
```

---

## 8. Mechanism Reference

The following mechanisms are advertised by the token. Pass these names to
`pkcs11-tool --mechanism` or the equivalent in your application.

**Signing:**

| Mechanism | Key types | Notes |
|-----------|-----------|-------|
| `ECDSA` | P-256, secp256k1 | Raw: caller supplies the pre-computed hash |
| `ECDSA-SHA1` | P-256, secp256k1 | SHA-1 computed in software (avoid for new uses) |
| `ECDSA-SHA256` | P-256, secp256k1 | SHA-256 computed in software |
| `ECDSA-SHA384` | P-256, secp256k1 | SHA-384 computed in software |
| `ECDSA-SHA512` | P-256, secp256k1 | SHA-512 computed in software |
| `EDDSA` | Ed25519 | Full message passed to device (<= 768 bytes) |
| `SHA256-RSA-PKCS` | RSA 2048/4096 | PKCS#1 v1.5, SHA-256 |
| `SHA384-RSA-PKCS` | RSA 2048/4096 | PKCS#1 v1.5, SHA-384 |
| `SHA512-RSA-PKCS` | RSA 2048/4096 | PKCS#1 v1.5, SHA-512 |

**Decryption:**

| Mechanism | Key types | Notes |
|-----------|-----------|-------|
| `RSA-PKCS-OAEP` | RSA 2048/4096 | OAEP decryption |

**Key derivation:**

| Mechanism | Key types | Notes |
|-----------|-----------|-------|
| `ECDH1-DERIVE` | Curve25519, P-256 | Produces a transient `CKO_SECRET_KEY` |

**Digest (software, no device interaction):**

| Mechanism | Output |
|-----------|--------|
| `SHA256` | 32 bytes |
| `SHA384` | 48 bytes |
| `SHA512` | 64 bytes |

**Note:** `CKM_RSA_PKCS` (raw PKCS#1 v1.5 without pre-hashing) is intentionally
not advertised. The device hashes internally, and advertising this mechanism
would produce incorrect signatures for callers who pre-hash their data.

---

## 9. Challenge Codes

Every cryptographic operation requires physical confirmation on the OnlyKey.
When an application calls `C_Sign`, `C_Decrypt`, or `C_DeriveKey`, the
middleware derives a 3-digit challenge code from the payload using SHA-256.
The same calculation runs on the device firmware.

1. The middleware displays the three digits (via `tty`, `stderr`, or your
   configured command).
2. Press the corresponding numbered buttons on the OnlyKey **in order**.
3. If the correct buttons are pressed, the device performs the operation and
   returns the result.
4. If no button is pressed within the timeout (default: 60 seconds), the
   operation fails with `CKR_FUNCTION_REJECTED`.

Each digit is in the range 1-6, corresponding to the six physical buttons.

---

## 10. Troubleshooting

### "No token found" / module loads but lists no objects

- Check that `~/.config/onlykey/slots.toml` exists and lists at least one slot.
- Verify the device is connected and unlocked (enter your PIN on the device
  first).
- Confirm udev rules are installed and you are in the `plugdev` group:
  ```sh
  groups | grep plugdev
  ls -l /dev/hidraw*
  ```

### "CKR_DEVICE_REMOVED" / module initialises then fails

The module could not open the device at `C_Initialize` time. Check:
- The device is plugged in.
- The udev rules are installed and applied (re-plug after installing them).
- You have read/write permission on the `/dev/hidraw*` node.

### Button press not detected / "CKR_FUNCTION_REJECTED"

The operation timed out. Increase the timeout in `config.toml`:
```toml
[device]
challenge_timeout_secs = 120
```

Or set the environment variable:
```sh
export ONLYKEY_DEVICE_CHALLENGE_TIMEOUT_SECS=120
```

### Challenge digits not visible

The default display mode (`tty`) writes to `/dev/tty`. In headless or piped
contexts there is no controlling terminal, so the digits are silently discarded.
Switch to `stderr` or `exec`:

```toml
[device]
challenge_display = "stderr"
```

### "CKR_KEY_HANDLE_INVALID" when signing

The key handle passed to `C_SignInit` is not a valid private key object. Common
causes:
- The slot is listed in `slots.toml` as an ECC type but the device has an RSA
  key loaded there, or vice versa.
- The algorithm in `slots.toml` does not match the mechanism requested.

### Building fails: `wolfcrypt` not found

Ensure `wolfssl-rs` is cloned as a sibling of this repository:
```sh
ls ../wolfssl-rs/wolfcrypt/Cargo.toml   # should exist
```

### Shared library not found at runtime

On Linux, either install to a directory in the dynamic linker search path or
set `LD_LIBRARY_PATH`:
```sh
export LD_LIBRARY_PATH="$PWD/target/release:$LD_LIBRARY_PATH"
```

For a permanent install, run `ldconfig` after copying the library:
```sh
sudo cp target/release/libonlykey_pkcs11.so /usr/lib/onlykey/
sudo ldconfig
```
