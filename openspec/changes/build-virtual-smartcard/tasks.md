## 1. Crate Setup

- [ ] 1.1 Create `crates/onlykey-vcard/Cargo.toml`: deps: onlykey-transport, wolfcrypt (digest/cipher/hmac), rusqlite (bundled), clap (derive), thiserror, dirs
- [ ] 1.2 Create `src/main.rs` skeleton with clap `Cli` struct and `Command` enum (ImportCert, ListCerts, GenerateCert)

## 2. vpcd Wire Protocol

- [ ] 2.1 Implement `src/vpcd.rs`: `VpcdConnection` wrapping `TcpStream`
- [ ] 2.2 Implement `read_message()`: read 2-byte big-endian length, read payload, dispatch to `VpcdMessage::Control` or `VpcdMessage::Apdu`
- [ ] 2.3 Implement `VpcdCtrl` enum: Off(0), On(1), Reset(2), Atr(4)
- [ ] 2.4 Implement `send_frame(data)`, `send_atr(atr)`, `send_rapdu(bytes)`
- [ ] 2.5 Write unit test: `read_message` from a cursor with known control-message bytes and APDU bytes

## 3. APDU Layer

- [ ] 3.1 Implement `src/apdu.rs`: `Apdu { cla, ins, p1, p2, data, ne }` with `parse(raw)`
- [ ] 3.2 Support all 7 APDU cases (1/2S/2E/3S/3E/4S/4E) including extended Lc/Le
- [ ] 3.3 Implement `RApdu { data, sw1, sw2 }` with `as_bytes()` and common error constructors (wrong_length, file_not_found, security_not_satisfied, etc.)
- [ ] 3.4 Implement BER-TLV helpers: `tlv(tag, value)`, `parse_tlv(data)`, `ber_len()`
- [ ] 3.5 Write unit tests: APDU parsing for all 7 cases with known byte sequences, `tlv()` round-trip through `parse_tlv()`

## 4. Applet Trait

- [ ] 4.1 Define `Applet` trait in `src/applet/mod.rs`: `aid()`, `atr()`, `reset()`, `process(apdu, device, certstore) -> RApdu`

## 5. OpenPGP Card Applet

- [ ] 5.1 Create `src/applet/openpgp.rs`: `OpenPgpApplet { selected, pin1_verified, pin2_verified, sig_counter, chained_response }`
- [ ] 5.2 Implement AID `D2 76 00 01 24 01 03 04 ...` and ATR bytes
- [ ] 5.3 Implement `cmd_select`: verify AID, reset PIN state, return FCI `6F [84 [AID]]`
- [ ] 5.4 Implement `cmd_verify_pin1` (INS=0x20, P2=0x81) and `cmd_verify_pin2` (P2=0x82): check device unlocked state
- [ ] 5.5 Implement `cmd_compute_sig` (INS=0x2A P1=0x9E P2=0x9A): check pin1_verified, sign on slot 101, increment sig_counter
- [ ] 5.6 Implement `cmd_decipher` (INS=0x2A P1=0x80 P2=0x86): parse A6/7F49/86 wrapper, ECDH on slot 102, prepend 0x00 to response
- [ ] 5.7 Implement `parse_decipher_data(data) -> Option<[u8; 32]>`: parse nested TLV to extract 32-byte peer key
- [ ] 5.8 Implement `cmd_internal_auth` (INS=0x88): sign on slot 103 (Aut slot)
- [ ] 5.9 Implement `cmd_generate_key` (INS=0x47): call get_ecc_pubkey on appropriate slot, return `7F 49 [len] 86 [len] [key]`
- [ ] 5.10 Implement `algorithm_attributes(alg: SlotAlgorithm) -> Vec<u8>` for all algorithms
- [ ] 5.11 Implement `cmd_get_data` for DOs: 6E (Application Related Data), C4 (PW Status), C5 (fingerprints), C1/C2/C3 (algorithm attrs), 7A (signature counter), 65 (cardholder), 5B (name), 5F50 (URL)
- [ ] 5.12 Implement `cmd_put_data` (INS=0xDA/0xDB): store name/URL in certstore metadata table
- [ ] 5.13 Implement `cmd_get_response` (INS=0xC0): drain chained_response buffer; return next chunk with SW=61xx or 9000
- [ ] 5.14 Implement `begin_chained_response(data)`: return first 256 bytes with SW=61xx if oversized
- [ ] 5.15 Write unit tests: `algorithm_attributes` byte output against spec values for Ed25519/Curve25519/P-256

## 6. PIV Applet

- [ ] 6.1 Create `src/applet/piv.rs`: `PivApplet { selected, pin_verified, chained_response, put_data_buffer }`
- [ ] 6.2 Implement AID `A0 00 00 03 08 00 00 10 00 01` and ATR bytes
- [ ] 6.3 Implement `piv_key_ref_to_ok_slot(key_ref)` mapping: 9A->104, 9C->105, 9D->106, 9E->107
- [ ] 6.4 Implement `piv_key_ref_to_cert_slot(key_ref)` mapping: 9A->"piv-9A", etc.
- [ ] 6.5 Implement `cmd_select`: verify PIV AID, reset state, return FCI
- [ ] 6.6 Implement `cmd_verify` (INS=0x20 PIN=0x80): check device unlocked; no PIN required for 9E
- [ ] 6.7 Implement `cmd_general_authenticate` (INS=0x87): parse 7C/81/82 dynamic auth template; dispatch to sign (P-256) or ECDH (Curve25519); return 7C/82 response
- [ ] 6.8 Implement `cmd_get_data` (INS=0xCB): parse 5C tag; look up cert from certstore; wrap in 53/70/71/FE; use response chaining for large certs
- [ ] 6.9 Implement `cmd_put_data` (INS=0xDB): handle CLA=0x10 chaining; write final cert to certstore on last block
- [ ] 6.10 Write unit tests: `cmd_get_data` response format with hardcoded cert blob (verify 53/70/71/FE tags)

## 7. Certificate Store

- [ ] 7.1 Implement `src/certstore.rs`: `Certstore { conn: Connection }` wrapping rusqlite
- [ ] 7.2 Implement `Certstore::open(path)`: create parent dir, open SQLite, run schema (certs + metadata tables)
- [ ] 7.3 Implement `Certstore::open_default()`: resolve XDG data dir, use `~/.local/share/onlykey/certs.db`
- [ ] 7.4 Implement `get_cert(slot)`, `put_cert(slot, der, label)`, `list()`
- [ ] 7.5 Implement `get_metadata(slot, key)`, `put_metadata(slot, key, value)` for fingerprints and timestamps
- [ ] 7.6 Implement `generate_self_signed(slot, subject_cn, device)`:
  - Fetch public key from device via `get_ecc_pubkey`
  - Encode TBSCertificate DER (minimal: serial, subject, validity, SPKI, basic constraints)
  - For Ed25519: sign TBSCertificate raw bytes via OKSIGN
  - For NistP256: SHA-256 hash TBSCertificate, sign digest via OKSIGN, DER-encode ECDSA signature
  - DER-encode full Certificate, store via `put_cert`
- [ ] 7.7 Implement DER encoding helpers: `encode_tbs_certificate()`, `encode_rdn_sequence()`, `encode_subject_public_key_info()`, `encode_certificate()`, `encode_sig_algorithm()`
- [ ] 7.8 Implement `der_ecdsa_sig(raw_64: &[u8]) -> Vec<u8>`: convert raw r||s to DER SEQUENCE { INTEGER r, INTEGER s }
- [ ] 7.9 Write unit tests: schema creation with in-memory SQLite, put/get round-trip, `generate_self_signed` with mock device (hardware-tests feature for real device)

## 8. CLI and Daemon Loop

- [ ] 8.1 Implement `main.rs` CLI subcommand dispatch: ImportCert, ListCerts, GenerateCert
- [ ] 8.2 Implement `run_daemon(cli, config)`: open device, open certstore, start listener threads
- [ ] 8.3 Implement `serve_applet<A, F>(listener, make_applet, device, certstore, verbose)`: accept loop, vpcd message dispatch
- [ ] 8.4 Implement `AppletKind` (OpenPgp, Piv, Both) and thread spawning for Both mode
- [ ] 8.5 Implement `load_cert_file(path)`: detect DER vs PEM, decode to DER bytes

## 9. pcscd Integration

- [ ] 9.1 Create `config/pcscd/onlykey-vcard.conf`: pcscd reader config pointing to ifd-vpcd at port 35963
- [ ] 9.2 Document ifd-vpcd as a prerequisite (vsmartcard / libifd-vpcd distro package) in `docs/setup.md`

## 10. Smoke Tests (hardware-tests feature)

- [ ] 10.1 Run `onlykey-vcard --applet openpgp --verbose` in background; run `gpg --card-status` (hardware-tests feature)
- [ ] 10.2 Run `onlykey-vcard --applet piv --verbose` in background; run `piv-tool -a` (hardware-tests feature)
- [ ] 10.3 Generate a self-signed cert for slot piv-9A; verify DER is valid X.509 (hardware-tests feature)
