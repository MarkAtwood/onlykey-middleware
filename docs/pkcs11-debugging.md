# Debugging the onlykey-pkcs11 Module

`onlykey-pkcs11` is loaded by `dlopen` into the calling process (Firefox, gpg-agent,
ssh-agent, OpenVPN, etc.). Writing to stdout would corrupt the host application's output
stream. Writing to stderr is unsafe in some callers. The module therefore never touches
stdout or stderr; all logging is opt-in via environment variables.

## Enabling Logging

Set `ONLYKEY_PKCS11_LOG` to the path of a log file before starting the application that
loads the module:

```sh
ONLYKEY_PKCS11_LOG=/tmp/onlykey-pkcs11.log pkcs11-tool --module /usr/lib/onlykey-pkcs11.so -I
```

If `ONLYKEY_PKCS11_LOG` is not set, logging is a complete no-op -- no file is created and
no output is produced. This is the default for production use.

## Log Level

The default log level is `WARN`. To see more detail, set `ONLYKEY_PKCS11_LOG_LEVEL`:

```sh
ONLYKEY_PKCS11_LOG=./debug.log ONLYKEY_PKCS11_LOG_LEVEL=debug pkcs11-tool ...
```

Valid values (case-insensitive): `error`, `warn`, `info`, `debug`, `trace`.

## Implementation

The module uses the `tracing` crate with a `tracing-subscriber` file appender:

- A file-based `tracing_subscriber::fmt::Subscriber` is initialized in `C_Initialize`
  pointing to `ONLYKEY_PKCS11_LOG`.
- The subscriber guard is held in `ModuleState` and dropped in `C_Finalize`, which
  flushes and closes the log file.
- If `ONLYKEY_PKCS11_LOG` is unset, `C_Initialize` skips subscriber setup entirely --
  no fallback to stderr.
- The `tracing` facade is used throughout the codebase. Library code never calls
  `log::set_logger` or initializes any backend.

## What Gets Logged

At `WARN` (default): unexpected return values from the device, initialization errors,
slots skipped due to missing `slots.toml` entries.

At `INFO`: slot enumeration results, session open/close, sign/decrypt operations.

At `DEBUG`: HID frame-level I/O, session state transitions, mechanism resolution.

At `TRACE`: raw byte buffers (may contain public key material -- do not share trace logs).

## Application-Specific Notes

### Firefox / Thunderbird

Firefox forks worker processes that inherit the environment. Set the env var in the
process that launches Firefox, or set it in `~/.profile`.

### gpg-agent

gpg-agent is typically started by the systemd user session. Set env vars with:

```sh
systemctl --user set-environment ONLYKEY_PKCS11_LOG=/tmp/onlykey-pkcs11.log
systemctl --user restart gpg-agent
```

### ssh-agent / p11-kit

p11-kit proxy modules inherit the ssh-agent environment. Start ssh-agent with the env var
set, or export it from your shell profile before the agent starts.

### OpenVPN

OpenVPN is typically started as root by NetworkManager. Env vars set in the user session
are not inherited. Use the `setenv` directive in the OpenVPN config file:

```
setenv ONLYKEY_PKCS11_LOG /tmp/onlykey-pkcs11.log
setenv ONLYKEY_PKCS11_LOG_LEVEL info
```

## Log File Security

The log file may contain public key material and operation timing. Do not place it in a
world-readable directory. `/tmp` is per-user on most modern Linux systems (`PrivateTmp`
equivalent via the kernel's `tmpfs` per-uid namespacing), but `/tmp/` itself is
group-readable on some distributions. Prefer `$XDG_RUNTIME_DIR/onlykey-pkcs11.log` for
sensitive debug sessions:

```sh
ONLYKEY_PKCS11_LOG="${XDG_RUNTIME_DIR}/onlykey-pkcs11.log" pkcs11-tool ...
```

`$XDG_RUNTIME_DIR` (usually `/run/user/$UID`) is always mode 0700.
