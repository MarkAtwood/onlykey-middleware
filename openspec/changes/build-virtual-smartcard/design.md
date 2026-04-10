## Context

pcscd expects a hardware smartcard reader. `ifd-vpcd.so` creates a virtual reader slot
in pcscd and tunnels APDUs over TCP. `onlykey-vcard` is the TCP server that receives
those APDUs, dispatches them to applet state machines, calls the OnlyKey device, and
returns R-APDUs.

## Goals / Non-Goals

**Goals:**
- `gpg --card-status` works -- GnuPG scdaemon detects the card and reads key fingerprints
- `gpg --sign` works via the OpenPGP Card applet
- PIV slot signing and ECDH work for pam_pkcs11 / SSSD / enterprise tooling
- CLI for certificate management without requiring a full PIV toolkit

**Non-Goals:**
- SCP03 (Secure Channel Protocol) -- not required by scdaemon or most PIV tools
- Full PIV with all 25 key slots -- implement the 4 core slots (9A/9C/9D/9E)
- OpenPGP Card secure messaging encryption
- Windows (pcscd is not available; this is out of scope for this revision)

## Decisions

**Two TCP ports, two listener threads, shared device mutex.**
OpenPGP Card and PIV are independent applets that callers access through separate pcscd
reader slots. Running them on separate ports lets both be active simultaneously. They
share `Arc<Mutex<OnlyKeyDevice>>` -- only one crypto operation at a time, which is correct
for a single-device token.

**Applet trait includes `certstore: &mut Certstore`.**
Both OpenPGP Card (GET DATA for fingerprints, PUT DATA for name/URL) and PIV (GET DATA
for certificates, PUT DATA for cert import) need read/write access to the certstore.
Including it in `process()` avoids threading a separate certstore reference through every
call path.

**Self-signed cert generation uses on-device signing.**
Private keys never leave the device. The TBSCertificate DER is constructed in software,
signed by `OKSIGN`, and the Certificate is assembled from the result. This is ~120 lines
of hand-rolled DER encoding -- no external cert-generation crate.

Why no `rcgen`? `rcgen` requires RustCrypto signing traits, which conflicts with the
wolfcrypt-only constraint. The DER encoding for a minimal self-signed cert is not complex
enough to justify pulling in a dependency that breaks the crypto backend constraint.

**rusqlite with `bundled` feature.**
SQLite is statically linked to avoid distro version issues. The certstore is small
(typically < 50 rows) and does not require advanced SQLite features. Bundled adds build
time but eliminates runtime dependency.

**APDU parser supports all 7 ISO 7816-4 cases.**
scdaemon and piv-tool use extended length APDUs for large certificate transfers. The
parser handles short (Lc/Le < 255) and extended (Lc/Le up to 65535) forms. This is
necessary for `PUT DATA` cert imports of certificates larger than 255 bytes.

**Response chaining for large GET DATA.**
OpenPGP Card Application Related Data (DO 6E) and PIV certificates often exceed 256 bytes.
The applet buffers the full response in `chained_response` and returns `SW=61xx` (61 +
remaining bytes capped at 0xFF). `GET RESPONSE (00 C0 00 00)` drains the buffer.
scdaemon and piv-tool both support this chaining protocol.

**OpenPGP Card: PIN maps to device unlock check.**
Physical PIN entry on the OnlyKey replaces the card's software PIN. `VERIFY(PW1)`
checks `device.get_device_state() == Unlocked`. `CKF_PROTECTED_AUTHENTICATION_PATH`
semantics -- the host cannot supply the PIN.

**OpenPGP Card: signature counter (`DO 0x93`) is in-memory.**
The counter increments on each `COMPUTE DIGITAL SIGNATURE`. It is not persisted across
daemon restarts. scdaemon uses this counter for display purposes only, not for
security. If persistence is needed, it can be added to the certstore metadata table later.

**PIV GENERAL AUTHENTICATE parses dynamic auth template (7C wrapper).**
The format is: `7C [len] 82 00 81 [len] [challenge]`. The `82 00` (empty Response)
signals "fill this in". We parse the `81` (Challenge) field and return our result in the
`82` (Response) field of the response `7C` wrapper. This is the PIV GENERAL AUTHENTICATE
spec (SP 800-73-4 Part 3, sec.3.2.4).

**ECDSA signature format.**
The OnlyKey device returns raw `r || s` (64 bytes for P-256). PKCS#11 callers expect
raw `r || s`. PIV GENERAL AUTHENTICATE callers (OpenSC, piv-tool) expect DER-encoded
`SEQUENCE { INTEGER r, INTEGER s }`. The `der_ecdsa_sig()` function converts between them.
For PKCS#11, raw bytes are returned; for PIV, DER is returned.

**ifd-vpcd is a prerequisite, not bundled.**
Most Linux distros ship `vsmartcard` or a `libifd-vpcd` package. Bundling the build
adds significant complexity (C build in our Cargo workflow). A setup doc is sufficient.

## Open Questions

<!-- OPEN: OpenPGP Card key fingerprints (DO C5) require SHA-1 of the V4 key packet.
     Does wolfcrypt-rs expose SHA-1? If not, we need to add the sha1 feature or use
     a small vendored SHA-1 implementation. The fingerprint is display-only and does
     not affect security; a missing or zero fingerprint is acceptable initially. -->

<!-- OPEN: GnuPG scdaemon's detection of the OpenPGP Card AID requires exact byte
     matching including the 6-byte fixed prefix D2 76 00 01 24 01. The serial number
     bytes (positions 10-13) must be unique per card for some GnuPG key management.
     Should we derive the serial from the device's firmware version or use a fixed value?
     Tentative: use a fixed serial 00 00 00 01; test with `gpg --card-status`. -->

<!-- OPEN: PIV GENERAL AUTHENTICATE for NistP256 signing: the input is a 32-byte digest.
     But `piv-tool` (OpenSC) may send the data pre-hashed or raw depending on the
     algorithm reference byte. Verify the exact hash handling with a live piv-tool trace
     before implementing cmd_general_authenticate. -->

<!-- OPEN: Certstore path was originally `~/.local/share/onlykey-vcard/certs.db` and was
     unified to `~/.local/share/onlykey/certs.db` to share with the PKCS#11 module's
     certificate needs. Confirm this unified path before first release. -->
