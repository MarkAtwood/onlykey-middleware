### Requirement: Crate Layering
The workspace SHALL contain four crates in strict dependency order with no cycles.

#### Scenario: Dependency graph is acyclic and layered
- **WHEN** the workspace dependency graph is resolved
- **THEN** onlykey-hid has no dependency on any other workspace crate
- **AND** onlykey-transport depends only on onlykey-hid
- **AND** onlykey-pkcs11 depends on onlykey-transport (not on onlykey-vcard)
- **AND** onlykey-vcard depends on onlykey-transport (not on onlykey-pkcs11)

### Requirement: Protocol Crate is no_std
onlykey-hid SHALL be compilable without std, using only `#![no_std]` and `extern crate alloc`.

#### Scenario: no_std compile check passes in CI
- **WHEN** `cargo check -p onlykey-hid --target wasm32-unknown-unknown` is run
- **THEN** compilation succeeds with zero errors
- **AND** no std-only item (std::fs, std::net, std::thread, etc.) is reachable from the crate

#### Scenario: alloc is available
- **WHEN** onlykey-hid code uses Vec or Box
- **THEN** these come from `alloc::vec::Vec` and `alloc::boxed::Box`, not `std`

### Requirement: Shared Dependency Declaration
wolfcrypt and thiserror SHALL be declared once in `[workspace.dependencies]` and inherited by all crates.

#### Scenario: wolfcrypt path is declared in one place
- **WHEN** any crate adds a wolfcrypt dependency
- **THEN** it uses `wolfcrypt = { workspace = true, features = [...] }`
- **AND** the path `"/home/mark/wolfssl-rs/wolfcrypt"` appears only in the workspace Cargo.toml

### Requirement: Workspace Layout
The workspace root SHALL be `onlykey-middleware/` with resolver = "2" and members under `crates/`.

#### Scenario: workspace members
- **WHEN** cargo resolves the workspace
- **THEN** members are exactly: `crates/onlykey-hid`, `crates/onlykey-transport`, `crates/onlykey-pkcs11`, `crates/onlykey-vcard`

### Requirement: Apache 2.0 License
All crates SHALL declare `license = "Apache-2.0"`.

#### Scenario: PKCS#11 module loads into proprietary application
- **GIVEN** onlykey-pkcs11.so is loaded by Thunderbird, OpenVPN, or another non-GPL application
- **WHEN** license compatibility is evaluated
- **THEN** Apache 2.0 creates no copyleft obligation on the loading application

### Requirement: Layering Rationale
The split between onlykey-hid (no_std) and onlykey-transport (std) SHALL be maintained because packet framing is pure data transformation that requires no OS calls, while USB I/O requires std.

#### Scenario: Protocol logic has no I/O dependency
- **WHEN** onlykey-hid is compiled for any target (including embedded)
- **THEN** it contains no hidapi calls, no file I/O, no thread primitives
- **AND** all HID frame construction and parsing is pure function computation
