# PRFAQ: OnlyKey Middleware Suite

---

## Press Release

**OnlyKey Finally Works Everywhere: Open-Source Middleware Brings PKCS#11, PIV, and Full GnuPG Support to the World's Most Secure Hardware Key**

*New suite of cryptographic glue libraries lets OnlyKey users authenticate to VPNs, sign emails, unlock LUKS volumes, and use enterprise PKI infrastructure -- with no firmware changes required.*

**FOR IMMEDIATE RELEASE**

Security-conscious developers and organizations have long faced a frustrating choice: OnlyKey offers superior physical security and open firmware, but it doesn't speak the smartcard protocols that enterprise software expects. Today, that changes. The OnlyKey Middleware Suite -- `libonlykey`, `onlykey-pkcs11`, and `onlykey-vcard` -- is a fully open-source stack that bridges OnlyKey's raw USB HID protocol to the standard cryptographic interfaces that every serious application already supports.

For years, OnlyKey users have had to accept that their hardware key simply could not be used with OpenVPN, OpenConnect, Firefox S/MIME, GnuPG's smartcard daemon, LUKS disk encryption, or any application that relies on PKCS#11 or PIV. YubiKey users took these for granted. The gap was not a flaw in OnlyKey's hardware -- the device is fully capable of signing, decrypting, and performing ECDH with strong keys -- but a missing software layer between the device and the rest of the ecosystem.

The OnlyKey Middleware Suite fills that gap at every layer:

**`libonlykey`** is a portable C library that speaks the OnlyKey HID wire protocol. It is the foundation everything else is built on: cross-platform, dependency-minimal, and designed to be embedded in any project that needs to talk to the device.

**`onlykey-pkcs11`** is a PKCS#11 2.40-compliant shared library built on `libonlykey`. Drop it into any PKCS#11-aware application -- OpenSSL, OpenVPN, Thunderbird, Firefox, ssh-agent via p11-kit, or `pkcs11-tool` -- and OnlyKey's keys appear as hardware-backed token objects. A p11-kit registration file makes it available system-wide on Linux with no per-application configuration.

**`onlykey-vcard`** is a virtual smartcard daemon that presents OnlyKey as a standard PIV or OpenPGP Card device to the PC/SC subsystem. Running `onlykey-vcard` alongside pcscd makes OnlyKey appear to GnuPG's `scdaemon`, enterprise PKI tooling, and any application that expects a smartcard slot -- all without any modification to those applications or to the OnlyKey firmware.

"We built the OnlyKey because we believed hardware security shouldn't require trusting a vendor's closed firmware," said a project maintainer. "The middleware suite means that belief no longer comes at the cost of ecosystem compatibility. If it works with a YubiKey, it now works with an OnlyKey."

A security engineer at a mid-sized technology company piloting the suite said: "I've wanted to use OnlyKey for our VPN and disk encryption for two years. The hardware is better, the firmware is auditable, but I couldn't justify asking our IT team to maintain bespoke tooling. With this stack, it just shows up as a PKCS#11 token. That conversation is over."

The OnlyKey Middleware Suite is available now on GitHub under the GNU General Public License v3.0 or later (GPL-3.0-or-later). Packages for Debian, Fedora, Arch, Homebrew, and Windows are in progress. OnlyKey hardware is available at onlykey.io.

---

## Internal FAQs

**Q: Why hasn't OnlyKey shipped this themselves?**

A: Three converging reasons. First, they made an early architectural choice to use raw USB HID rather than CCID/smartcard USB class -- a decision that trades standard ecosystem compatibility for simplicity and driverless operation. That decision compounded over time: every integration now requires custom code. Second, their target customer is an individual user who needs SSH keys and TOTP, not an enterprise admin who needs PIV-based VPN auth. The incentive to build PKCS#11 has never been strong enough against a small team's competing priorities. Third, the button-challenge interaction model -- where the user must physically press buttons to authorize each cryptographic operation -- fights the synchronous call model that PKCS#11 assumes, and solving that cleanly requires careful design.

**Q: Why can't we just write a PKCS#11 module in Python?**

A: The PKCS#11 ABI is a C calling convention. The calling application `dlopen`s the `.so` and invokes function pointers directly. A Python implementation cannot be loaded this way. You can write the internal logic in Rust or C++ or anything else, but the external interface must be a C shared library exporting `C_GetFunctionList`. That said, the HID transport code can be ported from the existing Python `python-onlykey` client; it is not complex.

**Q: What happens when the user doesn't press the button? Does the PKCS#11 caller hang?**

A: `C_Sign` and `C_Decrypt` block until either the device responds or the timeout elapses (60 seconds by default, configurable via `challenge_timeout_secs` in `config.toml` or the `ONLYKEY_DEVICE_CHALLENGE_TIMEOUT_SECS` environment variable). On timeout, the call returns `CKR_FUNCTION_REJECTED`. Applications that use PKCS#11 for interactive operations -- OpenVPN with a PIN prompt, `pkcs11-tool`, Firefox -- handle this gracefully. Applications that call PKCS#11 in an unattended daemon context (e.g., automated TLS termination) are not a good fit for any hardware key that requires physical touch, regardless of vendor. This is expected behavior, not a defect.

**Q: Does this require firmware changes?**

A: No. `libonlykey`, `onlykey-pkcs11`, and `onlykey-vcard` communicate with the device using the existing HID protocol. No firmware modifications are needed. The one feature that does require a firmware change -- FIDO2 PRF/hmac-secret extension, needed for Bitwarden passkey encryption -- is tracked separately and will be contributed upstream to `trustcrypto/OnlyKey-Firmware` as an independent PR.

**Q: What about key certificates? PIV requires X.509 certificates stored on the device.**

A: OnlyKey has no certificate storage on-device. `onlykey-vcard` will maintain a companion certificate store on the filesystem (a small SQLite database keyed by slot number), populated either by generating a self-signed certificate at key-load time or by importing a CA-issued certificate via a `onlykey-cert` CLI tool. From the application's perspective, the PIV slot has both a key and a certificate. From the device's perspective, the certificate lives on the host -- only private key operations touch the hardware. This is a common pattern for software-emulated PIV tokens.

**Q: What's the development sequence and what does each piece unblock?**

A: The dependency graph is strictly layered:

1. `libonlykey` (C, ~2 weeks) -- nothing else can be built without it
2. `onlykey-pkcs11` (~3 weeks) -- unblocks OpenSSL, OpenVPN, browsers, `pkcs11-tool`, SSH via p11-kit; this is the highest-leverage deliverable
3. p11-kit config + udev rules (~1 day) -- system-wide registration, trivial once step 2 exists
4. `onlykey-vcard` (~4 weeks) -- unblocks GnuPG via `scdaemon`, PIV ecosystem, enterprise tooling; more complex because it requires implementing an OpenPGP Card or PIV applet APDU interpreter
5. FIDO2 PRF firmware PR (~1-2 weeks) -- independent, can be parallelized with steps 2-4

**Q: What license should we use?**

A: GPL-3.0-or-later. This middleware is an independent application that communicates with the device over USB; it is not a library statically linked into callers. When a PKCS#11 module is loaded via dlopen by an application, the module runs as a self-contained shared object -- the GPL's terms apply to distribution of the module itself, not to the application that calls into it via the published PKCS#11 ABI. This is the same legal position taken by other GPL-licensed PKCS#11 implementations. The firmware's custom BSD license imposes no copyleft obligations on this middleware since we are not modifying or distributing the firmware. OpenSSL, p11-kit, and libfido2 are linked against, not distributed with, this project; their Apache/BSD licenses are compatible in that direction.

**Q: Can we use the name "OnlyKey" in the project name?**

A: The OnlyKey firmware license prohibits using "OnlyKey" or "CryptoTrust" to endorse or name derivative products without written permission. However, this middleware is not a firmware derivative -- it is independent software that communicates with the device over USB. Descriptive names like `onlykey-pkcs11` or `onlykey-agent` are used throughout the existing ecosystem (including official TrustCrypt repos) without issue. We should proceed with descriptive naming and seek explicit written permission from admin@crp.to before any commercial distribution.

**Q: How does this compare to just buying a YubiKey?**

A: YubiKey's PKCS#11 and PIV support are excellent and mature. For a user who only cares about PKCS#11 and doesn't care about open firmware, a YubiKey 5 is the simpler answer today. The OnlyKey proposition is different: open firmware that can be audited and modified, a larger number of stored credentials, a built-in password manager, a self-destruct PIN, and a price point that includes features that require separate YubiKey SKUs. This middleware suite closes the integration gap without changing any of those differentiators.

---

## External FAQs

**Q: What is the OnlyKey Middleware Suite?**

A: It is a set of open-source libraries and daemons that let OnlyKey hardware security keys work with any software that expects a PKCS#11 token or a PIV/OpenPGP smartcard. If you have previously been unable to use your OnlyKey with your VPN client, disk encryption, email client, or `gpg --card-status`, this suite fixes that.

**Q: What does it enable that wasn't possible before?**

A: Among the things now possible:

- VPN client certificate authentication (OpenVPN, OpenConnect, strongSwan)
- LUKS/dm-crypt disk encryption keys stored on the device
- GnuPG without a custom agent replacement -- `gpg --card-status` works
- S/MIME email signing and encryption in Thunderbird and Firefox
- SSH authentication via system p11-kit (no separate agent required)
- `pkcs11-tool` and standard smartcard administration tooling
- OpenSSL `pkcs11:` URIs in any application using the OpenSSL provider

**Q: Do I need to update my OnlyKey firmware?**

A: No. The middleware communicates with your device using the existing protocol. Your firmware does not need to change.

**Q: Does it work on macOS and Windows?**

A: Linux is the primary supported platform. macOS support is planned; the HID transport layer works on macOS already, and the PKCS#11 module will be a `.dylib` rather than a `.so`. Windows support is in progress; the main friction is that the OnlyKey HID device requires a driver on Windows, and p11-kit is less commonly used there. Windows users can use `onlykey-pkcs11` directly with applications that accept a PKCS#11 module path (OpenVPN, Thunderbird) without needing p11-kit.

**Q: Can this be used for enterprise smartcard login to Active Directory or macOS?**

A: Yes, via `onlykey-vcard`. When running the virtual smartcard daemon, your OnlyKey appears to the operating system as a PIV smartcard. On macOS, this enables smartcard login via the built-in CryptoTokenKit framework. On Linux with SSSD or pam_pkcs11, it enables smartcard PAM authentication. On Windows, it should work with the Windows Smartcard Minidriver if the PIV emulation is sufficiently complete; this is the most complex use case and will require testing.

**Q: Where are my private keys? Do they leave the device?**

A: Private keys never leave the OnlyKey hardware. Every cryptographic operation -- signing, decryption, ECDH -- happens on the device. The middleware sends data to the device and receives the result. This is identical to how a YubiKey PKCS#11 module works.

**Q: Why does the application freeze for a few seconds when I try to sign something?**

A: The OnlyKey requires you to physically press buttons to authorize each cryptographic operation. The middleware waits (up to 60 seconds by default, configurable) for you to do so. During that time the calling application is blocked. If you do not press the buttons, the operation times out and the application receives an error. This is a security feature of the device, not a bug in the middleware.

**Q: Is this an official OnlyKey / TrustCrypt project?**

A: No. This is an independent open-source project. We are not affiliated with TrustCrypt LLC. We have contributed changes upstream where appropriate and will continue to do so.

**Q: How do I install it?**

A: Packages for Debian/Ubuntu (`apt`), Fedora/RHEL (`dnf`), and Arch (`AUR`) are in progress. Until then, build from source: install `hidapi` and `cmake`, clone the repository, and run `cmake --build . --install`. A setup guide with p11-kit configuration and udev rules is in `docs/setup.md`.

**Q: How do I report a security vulnerability?**

A: Do not open a public GitHub issue. Email the security contact listed in `SECURITY.md` with a description and proof of concept. We follow a 90-day responsible disclosure policy.
