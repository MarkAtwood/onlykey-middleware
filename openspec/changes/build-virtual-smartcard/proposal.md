## Why

OnlyKey cannot appear as a smartcard to pcscd without a bridge layer. `onlykey-vcard`
implements that bridge: it listens for ifd-vpcd TCP connections and presents OnlyKey as
either an OpenPGP Card 3.4 or a PIV smartcard. This enables:
- `gpg --card-status` and GnuPG signing without a custom agent replacement
- Enterprise PKI tooling (pam_pkcs11, sssd, OpenSC) via PIV
- macOS CryptoTokenKit smartcard login via PIV
- Certificate storage and management via the certstore

The OpenPGP Card applet is implemented first (more immediately useful to typical OnlyKey
users). PIV ships in the same change.

## What Changes

- New crate `crates/onlykey-vcard` (std binary) added to the workspace
- Listens for ifd-vpcd TCP connections on configurable ports (default 35963 OpenPGP, 35964 PIV)
- Implements the vpcd wire protocol (u16 length-prefixed frames, control messages)
- Implements ISO 7816-4 APDU parser and R-APDU builder
- `OpenPgpApplet`: SELECT, VERIFY, COMPUTE DIGITAL SIGNATURE, DECIPHER, INTERNAL AUTHENTICATE, GENERATE KEY, GET DATA, GET RESPONSE chaining
- `PivApplet`: SELECT, VERIFY, GENERAL AUTHENTICATE (sign + ECDH), GET DATA, PUT DATA
- `Certstore`: SQLite via rusqlite (bundled), self-signed cert generation with on-device signing
- CLI subcommands: `import-cert`, `list-certs`, `generate-cert`
- `--applet both` mode: two listener threads sharing `Arc<Mutex<OnlyKeyDevice>>`

## Capabilities

### New Capabilities
- `virtual-smartcard`: vpcd TCP bridge, APDU framing, OpenPGP Card 3.4 applet, PIV applet, certstore

## Impact

- Depends on: `build-transport-layer` must be complete
- Requires external prerequisite: `ifd-vpcd.so` installed (from distro `vsmartcard` / `libifd-vpcd` package)
- Requires pcscd reader config file (delivered as `config/pcscd/onlykey-vcard.conf`)
- SQLite is statically linked via `rusqlite` `bundled` feature -- no distro SQLite version dependency
