### Requirement: XDG Base Directory Paths
All persistent state SHALL follow the XDG Base Directory specification.

#### Scenario: Config file location
- **WHEN** `Config::load()` is called
- **THEN** it reads from `$XDG_CONFIG_HOME/onlykey/config.toml`
- **AND** defaults to `~/.config/onlykey/config.toml` when `$XDG_CONFIG_HOME` is unset

#### Scenario: Certificate store location
- **WHEN** the certstore is opened with default path
- **THEN** it uses `$XDG_DATA_HOME/onlykey/certs.db`
- **AND** defaults to `~/.local/share/onlykey/certs.db`

#### Scenario: Runtime directory
- **WHEN** onlykey-vcard creates sockets or PID files
- **THEN** they are placed in `$XDG_RUNTIME_DIR/onlykey/`
- **AND** defaults to `/run/user/$UID/onlykey/`

### Requirement: Config File Schema
The configuration file SHALL use TOML format with a `[device]` section.

#### Scenario: Full config file
- **WHEN** `~/.config/onlykey/config.toml` contains:
  ```toml
  [device]
  challenge_timeout_secs = 60
  challenge_display = "tty"
  [pkcs11]
  expose_derived_keys = false
  [vcard]
  applets = ["openpgp", "piv"]
  openpgp_port = 35963
  piv_port = 35964
  ```
- **THEN** all fields are parsed and applied

### Requirement: Challenge Timeout Default
The default challenge timeout SHALL be 60 seconds. Partial seconds are not supported; sub-second values are rounded up to 1 second.

#### Scenario: Default timeout
- **WHEN** `Config::default()` is constructed
- **THEN** `challenge_timeout` = `Duration::from_secs(60)`

### Requirement: Challenge Display Default
The default challenge display mode SHALL be `"tty"` (write to `/dev/tty` with stderr fallback).

#### Scenario: Default display mode
- **WHEN** `Config::default()` is constructed
- **THEN** `challenge_display` = `ChallengeDisplayKind::Tty`

### Requirement: Environment Variable Override
Environment variables with the prefix `ONLYKEY_` SHALL override config file values. The key is `ONLYKEY_` + uppercased TOML key with `.` replaced by `_`.

#### Scenario: Timeout override
- **WHEN** `ONLYKEY_DEVICE_CHALLENGE_TIMEOUT_SECS=120` is set in the environment
- **THEN** `Config::load()` uses a 120-second timeout regardless of the config file

### Requirement: Config Resolution Order
Settings SHALL resolve in priority order: environment variable > config.toml > compiled-in default.

#### Scenario: Three-way precedence
- **GIVEN** config.toml sets timeout to 30 s AND environment sets it to 120 s
- **WHEN** `Config::load()` is called
- **THEN** the effective timeout is 120 s (environment wins)

- **GIVEN** config.toml sets timeout to 30 s AND no environment variable is set
- **WHEN** `Config::load()` is called
- **THEN** the effective timeout is 30 s (config.toml wins over default)

### Requirement: p11-kit pReserved Config Passing
The PKCS#11 module SHALL parse the `pInitArgs->pReserved` string (when non-null) as semicolon-separated `key=value` overrides.

#### Scenario: Per-application timeout override
- **WHEN** the p11-kit module file contains `x-init-reserved = challenge_timeout_secs=120`
- **AND** p11-kit passes this string to `C_Initialize` as `pInitArgs->pReserved`
- **THEN** the timeout for this session is 120 s
- **AND** this override does not persist beyond `C_Finalize`

### Requirement: Missing Config File is Not an Error
If the config file does not exist, `Config::load()` SHALL return `Config::default()` without error.

#### Scenario: Absent config file
- **WHEN** `~/.config/onlykey/config.toml` does not exist
- **THEN** `Config::load()` returns `Ok(Config::default())`

### Requirement: Slots.toml Algorithm Metadata
A companion file at `$XDG_DATA_HOME/onlykey/slots.toml` SHALL map ECC slot numbers (101-116) and RSA slot numbers (1-4) to algorithm strings.

#### Scenario: slots.toml format
- **WHEN** the file is read
- **THEN** valid algorithm strings are: `"ed25519"`, `"curve25519"`, `"nist_p256"`, `"secp256k1"`, `"rsa2048"`, `"rsa4096"`

#### Scenario: Missing entry
- **WHEN** an ECC slot has no entry in slots.toml
- **THEN** a warning is printed to stderr and the slot is excluded from the object table
- **AND** the module continues without error
