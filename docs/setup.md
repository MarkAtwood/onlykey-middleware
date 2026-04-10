# onlykey-vcard Setup

`onlykey-vcard` is a virtual smartcard daemon that bridges an OnlyKey device to
software that expects a PC/SC smartcard reader. It exposes an OpenPGP Card 3.4
applet (for `gpg --card-*`) and a PIV applet (for `piv-tool`, enterprise PKI, and
macOS/Windows built-in smartcard drivers).

## Prerequisites

### ifd-vpcd

`onlykey-vcard` speaks the vpcd wire protocol over TCP. The PC/SC daemon (`pcscd`)
connects to it through the `ifd-vpcd` reader driver.

Install `ifd-vpcd` for your distribution:

| Distribution | Command |
|---|---|
| Debian / Ubuntu | `sudo apt install ifd-vpcd` |
| Fedora | `sudo dnf install ifd-vpcd` |
| Arch Linux | `paru -S ifd-vpcd` (AUR) |

Verify the shared library is present:

```
ls /usr/lib/pcsc/drivers/ifd-vpcd.so
```

### pcscd reader configuration

Copy the bundled reader config into the pcscd drop-in directory:

```bash
sudo cp config/pcscd/onlykey-vcard.conf /etc/reader.conf.d/
sudo systemctl restart pcscd
```

This registers two virtual readers -- one for each applet -- that ifd-vpcd connects
to `onlykey-vcard` over loopback TCP.

### OnlyKey udev rules

Ensure the OnlyKey udev rules are installed so the daemon can open the HID device
without root. See `config/udev/`.

## Installing the daemon

Build and install the binary:

```bash
cargo build --release -p onlykey-vcard
install -Dm755 target/release/onlykey-vcard ~/.local/bin/onlykey-vcard
```

Install the systemd user unit:

```bash
mkdir -p ~/.config/systemd/user
cp config/systemd/onlykey-vcard.service ~/.config/systemd/user/
systemctl --user daemon-reload
systemctl --user enable --now onlykey-vcard
```

## slots.toml

`onlykey-vcard` requires a `slots.toml` to know which algorithm each OnlyKey ECC
slot holds. See [slots-toml.md](slots-toml.md) for the format.

The daemon reads `slots.toml` through `onlykey-transport`, which searches:
1. `$ONLYKEY_SLOTS_TOML`
2. `$XDG_CONFIG_HOME/onlykey/slots.toml` (default `~/.config/onlykey/slots.toml`)

The OpenPGP and PIV slot defaults are:

| Slot name | OnlyKey slot | Algorithm | Purpose |
|---|---|---|---|
| `openpgp-sig` | 101 (ECC1) | Ed25519 | OpenPGP signing key |
| `openpgp-dec` | 102 (ECC2) | Curve25519 | OpenPGP decryption (ECDH) |
| `openpgp-aut` | 103 (ECC3) | Ed25519 | OpenPGP authentication key |
| `piv-9A` | 104 (ECC4) | NIST P-256 | PIV authentication |
| `piv-9C` | 105 (ECC5) | NIST P-256 | PIV digital signature |
| `piv-9D` | 106 (ECC6) | Curve25519 | PIV key management |
| `piv-9E` | 107 (ECC7) | NIST P-256 | PIV card authentication |

## OpenPGP serial number

The OpenPGP Card AID embeds a 4-byte serial number. By default `onlykey-vcard`
derives it from the last 4 bytes of the SHA-256 hash of the device's identifier.
Override it in `~/.config/onlykey/config.toml`:

```toml
[openpgp]
serial = 0x12345678
```

## PIV certificates

PIV relies on X.509 certificates stored alongside the private keys. Use the
built-in subcommands to manage the cert store (`~/.local/share/onlykey/certs.db`):

```bash
# Generate a self-signed certificate for a slot (requires OnlyKey connected)
onlykey-vcard generate-cert --slot piv-9A --cn "My Name"

# Import an existing DER or PEM certificate
onlykey-vcard import-cert --slot piv-9A path/to/cert.pem

# List stored certificates
onlykey-vcard list-certs
```

## Verifying the setup

With `onlykey-vcard` running and pcscd restarted:

```bash
# OpenPGP
gpg --card-status

# PIV
piv-tool -a
```

Both commands should show the virtual card without errors.
