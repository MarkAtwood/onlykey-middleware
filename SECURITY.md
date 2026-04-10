# Security Policy

## Scope

This policy covers the **OnlyKey Middleware** software in this repository:
`onlykey-hid`, `onlykey-transport`, `onlykey-pkcs11`, `onlykey-vcard`, `onlykey-tool`.

Out of scope:
- OnlyKey device firmware (report to CryptoTrust at https://onlykey.io)
- Vulnerabilities that require physical access to an already-unlocked device
- Denial of service against a single local user

## Reporting a Vulnerability

Email: **mark@wolfssl.com**

Include:
- A description of the vulnerability and the affected component
- The version or commit hash where you observed it
- A proof of concept or reproduction steps
- Your assessment of severity and exploitability

We follow a **90-day responsible disclosure** policy. We will acknowledge receipt
within 5 business days and provide a status update within 30 days. If a fix cannot
be issued within 90 days we will notify you and agree on a coordinated disclosure date.

We do not currently offer a bug bounty.

## Supported Versions

The latest commit on `main` is the supported version. No backport branches are maintained.
