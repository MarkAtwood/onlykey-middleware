use crate::error::TransportError;
use serde::Deserialize;
use std::time::Duration;

/// How the challenge code is presented to the user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChallengeDisplayKind {
    /// Write challenge to `/dev/tty` (falls back to stderr if unavailable).
    Tty,
    /// Write challenge to stderr.
    Stderr,
    /// Execute a shell command, replacing `%d` with each digit in order.
    Exec(String),
}

impl ChallengeDisplayKind {
    /// Parse a display kind string as used in `config.toml`.
    ///
    /// Valid forms:
    /// - `"tty"` -> `Tty`
    /// - `"stderr"` -> `Stderr`
    /// - `"exec:<command>"` -> `Exec(command)` (must contain exactly 3 `%d` tokens)
    ///
    /// The `exec:` form requires exactly 3 `%d` tokens in the command template
    /// because `ExecDisplay::show` substitutes exactly three digits. A template
    /// with fewer tokens would silently drop some digits; with more, the extras
    /// would remain as literal `%d`. Both produce incorrect output with no
    /// error at runtime. Issue OnlyKey-w23a.
    pub fn parse(s: &str) -> Result<Self, TransportError> {
        match s {
            "tty"    => Ok(ChallengeDisplayKind::Tty),
            "stderr" => Ok(ChallengeDisplayKind::Stderr),
            _ if s.starts_with("exec:") => {
                let cmd = s[5..].to_string();
                let count = cmd.matches("%d").count();
                if count != 3 {
                    return Err(TransportError::Config(format!(
                        "exec: challenge_display template {:?} has {} %d token(s); \
                         expected exactly 3 (one per digit). \
                         Example: \"exec:notify-send 'OnlyKey' 'Press %d %d %d'\"",
                        cmd, count
                    )));
                }
                Ok(ChallengeDisplayKind::Exec(cmd))
            }
            _ => Err(TransportError::Config(format!(
                "unknown challenge_display value {:?}; expected \"tty\", \"stderr\", or \"exec:<cmd>\"",
                s
            ))),
        }
    }
}

/// Runtime configuration for the OnlyKey transport layer.
#[derive(Debug, Clone)]
pub struct Config {
    /// How long to wait for the user to press the button.
    /// Default: 60 seconds. Partial seconds are rounded up to 1 second.
    pub challenge_timeout: Duration,
    /// How the three-digit challenge code is shown to the user.
    pub challenge_display: ChallengeDisplayKind,
    /// Timeout for receiving continuation frames after the first frame of a
    /// multi-frame response arrives. Wireless OnlyKey adapters may have up to
    /// ~300 ms inter-frame gaps; 500 ms is the default to cover these cases.
    /// Configurable for environments with slower USB hubs. Issue OnlyKey-8gje.
    pub inter_frame_timeout: Duration,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            challenge_timeout: Duration::from_secs(60),
            challenge_display: ChallengeDisplayKind::Tty,
            inter_frame_timeout: Duration::from_millis(500),
        }
    }
}

/// TOML structure for the `[device]` section of `~/.config/onlykey/config.toml`.
#[derive(Debug, Deserialize, Default)]
struct TomlDevice {
    challenge_timeout_secs: Option<u64>,
    challenge_display: Option<String>,
    inter_frame_timeout_ms: Option<u64>,
}

#[derive(Debug, Deserialize, Default)]
struct TomlConfig {
    device: Option<TomlDevice>,
}

impl Config {
    /// Load configuration from `$XDG_CONFIG_HOME/onlykey/config.toml`.
    ///
    /// A missing file is silently ignored and returns `Config::default()`.
    /// Environment variables override file values:
    /// - `ONLYKEY_DEVICE_CHALLENGE_TIMEOUT_SECS`
    /// - `ONLYKEY_DEVICE_INTER_FRAME_TIMEOUT_MS`
    ///
    /// # Security
    ///
    /// When `challenge_display` is set to `exec:<cmd>`, the template string is
    /// passed verbatim to `sh -c`. If another local user can write to
    /// `config.toml`, they can inject arbitrary shell commands that execute as
    /// the PKCS#11 module user. This function therefore **rejects** a config
    /// file with group-write or world-write permission (i.e. mode bits wider
    /// than `0o600`) when `exec:` display is configured. Issue OnlyKey-kj0.
    pub fn load() -> Result<Self, TransportError> {
        let mut cfg = Config::default();

        // Try to read the config file. Missing file -> use defaults.
        let config_path = dirs::config_dir().map(|d| d.join("onlykey").join("config.toml"));

        if let Some(ref path) = config_path {
            if path.exists() {
                let content = std::fs::read_to_string(path).map_err(|e| {
                    TransportError::Config(format!("cannot read {:?}: {}", path, e))
                })?;
                let parsed: TomlConfig = toml::from_str(&content).map_err(|e| {
                    TransportError::Config(format!("parse error in {:?}: {}", path, e))
                })?;

                if let Some(device) = parsed.device {
                    if let Some(secs) = device.challenge_timeout_secs {
                        if secs < 1 {
                            eprintln!(
                                "onlykey: challenge_timeout_secs={} is below minimum (1); \
                                 clamping to 1 second",
                                secs
                            );
                        }
                        cfg.challenge_timeout = Duration::from_secs(secs.max(1));
                    }
                    if let Some(display) = device.challenge_display {
                        cfg.challenge_display = ChallengeDisplayKind::parse(&display)?;
                    }
                    if let Some(ms) = device.inter_frame_timeout_ms {
                        // Clamp to [1, i32::MAX] before storing. hidapi's read timeout is
                        // a C `int`; the Duration is cast `as i32` in device.rs. A value
                        // > i32::MAX wraps negative and hidapi treats negative as infinite
                        // wait, which would hang device reads permanently. Issue OnlyKey-8gje.
                        const MAX_INTER_FRAME_MS: u64 = i32::MAX as u64;
                        let clamped = ms.clamp(1, MAX_INTER_FRAME_MS);
                        if ms < 1 || ms > MAX_INTER_FRAME_MS {
                            eprintln!(
                                "onlykey: inter_frame_timeout_ms={} out of range [1, {}]; \
                                 clamping to {} ms",
                                ms, MAX_INTER_FRAME_MS, clamped
                            );
                        }
                        cfg.inter_frame_timeout = Duration::from_millis(clamped);
                    }
                }

                // Reject the config if exec: display is active and the file has
                // unsafe permissions. exec: passes the template to sh -c, so a
                // world- or group-writable file is a local privilege escalation
                // vector. This check intentionally happens after parsing so the
                // error message can name the display mode. Issue OnlyKey-kj0.
                if matches!(cfg.challenge_display, ChallengeDisplayKind::Exec(_)) {
                    check_exec_config_permissions(path)?;
                }
            }
        }

        // Environment variable overrides.
        if let Ok(val) = std::env::var("ONLYKEY_DEVICE_CHALLENGE_TIMEOUT_SECS") {
            let secs: u64 = val.parse().map_err(|_| {
                TransportError::Config(format!(
                    "ONLYKEY_DEVICE_CHALLENGE_TIMEOUT_SECS={:?} is not a valid integer",
                    val
                ))
            })?;
            if secs < 1 {
                eprintln!(
                    "onlykey: ONLYKEY_DEVICE_CHALLENGE_TIMEOUT_SECS={} is below minimum (1); \
                     clamping to 1 second",
                    secs
                );
            }
            cfg.challenge_timeout = Duration::from_secs(secs.max(1));
        }

        if let Ok(val) = std::env::var("ONLYKEY_DEVICE_INTER_FRAME_TIMEOUT_MS") {
            let ms: u64 = val.parse().map_err(|_| {
                TransportError::Config(format!(
                    "ONLYKEY_DEVICE_INTER_FRAME_TIMEOUT_MS={:?} is not a valid integer",
                    val
                ))
            })?;
            const MAX_INTER_FRAME_MS: u64 = i32::MAX as u64;
            let clamped = ms.clamp(1, MAX_INTER_FRAME_MS);
            if ms < 1 || ms > MAX_INTER_FRAME_MS {
                eprintln!(
                    "onlykey: ONLYKEY_DEVICE_INTER_FRAME_TIMEOUT_MS={} out of range [1, {}]; \
                     clamping to {} ms",
                    ms, MAX_INTER_FRAME_MS, clamped
                );
            }
            cfg.inter_frame_timeout = Duration::from_millis(clamped);
        }

        Ok(cfg)
    }

    /// Parse a `Config` from a raw TOML string.
    ///
    /// Useful for unit tests without touching the filesystem. Does not perform
    /// any filesystem permission checks (there is no file to stat).
    pub fn parse(toml_str: &str) -> Result<Self, TransportError> {
        let mut cfg = Config::default();
        let parsed: TomlConfig = toml::from_str(toml_str)
            .map_err(|e| TransportError::Config(format!("TOML parse error: {}", e)))?;
        if let Some(device) = parsed.device {
            if let Some(secs) = device.challenge_timeout_secs {
                cfg.challenge_timeout = Duration::from_secs(secs.max(1));
            }
            if let Some(display) = device.challenge_display {
                cfg.challenge_display = ChallengeDisplayKind::parse(&display)?;
            }
            if let Some(ms) = device.inter_frame_timeout_ms {
                // Same [1, i32::MAX] clamp as in load(); see issue OnlyKey-8gje.
                const MAX_INTER_FRAME_MS: u64 = i32::MAX as u64;
                cfg.inter_frame_timeout =
                    Duration::from_millis(ms.clamp(1, MAX_INTER_FRAME_MS));
            }
        }
        Ok(cfg)
    }
}

/// Verify that a config file used with `exec:` display cannot be written by
/// users other than the owner.
///
/// The `exec:` display mode passes the template string verbatim to `sh -c`.
/// If another local user can modify config.toml they can run arbitrary
/// commands as the PKCS#11 module user. We reject any file with group-write
/// or world-write permission bits set (mode & 0o022 != 0). We also reject
/// group-read and world-read (mode & 0o044 != 0) to match the `chmod 0600`
/// recommendation in HOWTO.md. Issue OnlyKey-kj0.
///
/// On non-Unix platforms this check is a no-op: the OS provides a different
/// access-control model and we cannot meaningfully apply Unix permission bits.
#[cfg(unix)]
fn check_exec_config_permissions(path: &std::path::Path) -> Result<(), TransportError> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path).map_err(|e| {
        TransportError::Config(format!(
            "cannot stat {:?} to check permissions: {}",
            path, e
        ))
    })?;
    let mode = meta.permissions().mode();
    // Reject any group or world permission bits. 0o077 covers all of:
    //   group-read (0o040), group-write (0o020), group-execute (0o010),
    //   other-read  (0o004), other-write  (0o002), other-execute (0o001).
    // Only owner-read + owner-write (0o600) is acceptable.
    if mode & 0o077 != 0 {
        return Err(TransportError::Config(format!(
            "{:?} uses exec: challenge display but has unsafe permissions \
             (mode {:#o}); run: chmod 0600 {:?}\n\
             Reason: exec: passes the display template to sh -c. A file \
             writable by other users is a local shell-injection vector.",
            path,
            mode & 0o777,
            path,
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_exec_config_permissions(_path: &std::path::Path) -> Result<(), TransportError> {
    // Non-Unix platforms use a different access-control model; the Unix
    // permission bit check does not apply.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Serializes all tests that mutate environment variables. Rust runs tests in
    // parallel by default; std::env::set_var is not thread-safe (UB in C, and
    // unsafe in Rust 2024). A process-wide Mutex is the standard workaround.
    // Issue OnlyKey-8c9.
    static ENV_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn default_timeout_is_60s() {
        assert_eq!(Config::default().challenge_timeout, Duration::from_secs(60));
    }

    #[test]
    fn default_inter_frame_is_500ms() {
        assert_eq!(
            Config::default().inter_frame_timeout,
            Duration::from_millis(500)
        );
    }

    #[test]
    fn parse_inter_frame_timeout() {
        let toml = r#"
            [device]
            inter_frame_timeout_ms = 250
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert_eq!(cfg.inter_frame_timeout, Duration::from_millis(250));
    }

    /// Values larger than i32::MAX must be clamped to i32::MAX to prevent the
    /// `as i32` cast in device.rs from wrapping negative (which hidapi treats
    /// as infinite wait). Issue OnlyKey-8gje.
    #[test]
    fn parse_inter_frame_timeout_overflow_clamped() {
        let oversized = (i32::MAX as u64) + 1;
        let toml = format!(
            "[device]\ninter_frame_timeout_ms = {}",
            oversized
        );
        let cfg = Config::parse(&toml).unwrap();
        assert_eq!(cfg.inter_frame_timeout, Duration::from_millis(i32::MAX as u64));
    }

    #[test]
    fn default_display_is_tty() {
        assert_eq!(
            Config::default().challenge_display,
            ChallengeDisplayKind::Tty
        );
    }

    #[test]
    fn parse_known_toml() {
        let toml = r#"
            [device]
            challenge_timeout_secs = 120
            challenge_display = "stderr"
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert_eq!(cfg.challenge_timeout, Duration::from_secs(120));
        assert_eq!(cfg.challenge_display, ChallengeDisplayKind::Stderr);
    }

    #[test]
    fn parse_exec_display() {
        let toml = r#"
            [device]
            challenge_display = "exec:notify-send %d %d %d"
        "#;
        let cfg = Config::parse(toml).unwrap();
        assert_eq!(
            cfg.challenge_display,
            ChallengeDisplayKind::Exec("notify-send %d %d %d".into())
        );
    }

    #[test]
    fn parse_exec_display_wrong_token_count_is_error() {
        // A template with fewer than 3 %d tokens would silently drop digits;
        // with more, extras remain as literal %d. Both are user errors that
        // should be caught at parse time. Issue OnlyKey-w23a.
        assert!(ChallengeDisplayKind::parse("exec:notify-send %d").is_err());
        assert!(ChallengeDisplayKind::parse("exec:notify-send %d %d").is_err());
        assert!(ChallengeDisplayKind::parse("exec:notify-send %d %d %d %d").is_err());
        assert!(ChallengeDisplayKind::parse("exec:no-tokens-at-all").is_err());
        // Exactly 3 tokens: ok.
        assert!(ChallengeDisplayKind::parse("exec:cmd %d %d %d").is_ok());
    }

    #[test]
    fn missing_file_returns_default() {
        // Override the env var to avoid interference from real config files.
        // We can't easily isolate $XDG_CONFIG_HOME in a unit test, but we can
        // verify that parse("") (empty TOML) gives the default.
        let cfg = Config::parse("").unwrap();
        assert_eq!(cfg.challenge_timeout, Duration::from_secs(60));
    }

    #[test]
    fn env_var_override() {
        // ENV_MUTEX serializes env-mutating tests so set_var does not race with
        // other tests reading the same variable. Issue OnlyKey-8c9.
        let _guard = ENV_MUTEX.lock().unwrap();
        std::env::set_var("ONLYKEY_DEVICE_CHALLENGE_TIMEOUT_SECS", "45");
        let cfg = Config::load().unwrap();
        std::env::remove_var("ONLYKEY_DEVICE_CHALLENGE_TIMEOUT_SECS");
        assert_eq!(cfg.challenge_timeout, Duration::from_secs(45));
    }

    #[test]
    fn display_kind_parse_tty() {
        assert_eq!(
            ChallengeDisplayKind::parse("tty").unwrap(),
            ChallengeDisplayKind::Tty
        );
    }

    #[test]
    fn display_kind_parse_stderr() {
        assert_eq!(
            ChallengeDisplayKind::parse("stderr").unwrap(),
            ChallengeDisplayKind::Stderr
        );
    }

    #[test]
    fn display_kind_parse_exec() {
        assert_eq!(
            ChallengeDisplayKind::parse("exec:my-script %d %d %d").unwrap(),
            ChallengeDisplayKind::Exec("my-script %d %d %d".into())
        );
    }

    #[test]
    fn display_kind_parse_unknown_is_error() {
        assert!(ChallengeDisplayKind::parse("popup").is_err());
    }

    // Permission tests: only meaningful on Unix, where file mode bits exist.
    // These tests create real temporary files to exercise the permission check
    // that runs when exec: display is loaded from an actual file on disk.
    // Issue OnlyKey-kj0.
    #[cfg(unix)]
    mod permissions {
        use super::super::check_exec_config_permissions;
        use std::os::unix::fs::PermissionsExt;

        fn tmp_file_with_mode(mode: u32) -> tempfile::NamedTempFile {
            let f = tempfile::NamedTempFile::new().expect("tempfile");
            std::fs::set_permissions(f.path(), std::fs::Permissions::from_mode(mode))
                .expect("set_permissions");
            f
        }

        #[test]
        fn mode_0600_is_accepted() {
            let f = tmp_file_with_mode(0o600);
            assert!(
                check_exec_config_permissions(f.path()).is_ok(),
                "mode 0600 must be accepted"
            );
        }

        #[test]
        fn mode_0644_is_rejected() {
            // World-readable: another user could read the exec: template and
            // infer what commands will be dispatched (information disclosure).
            let f = tmp_file_with_mode(0o644);
            let err = check_exec_config_permissions(f.path())
                .expect_err("mode 0644 must be rejected");
            assert!(
                err.to_string().contains("unsafe permissions"),
                "error should mention unsafe permissions: {err}"
            );
        }

        #[test]
        fn mode_0622_is_rejected() {
            // Group-write: another group member could replace the exec: template
            // to inject arbitrary shell commands (shell injection via config file).
            let f = tmp_file_with_mode(0o622);
            assert!(
                check_exec_config_permissions(f.path()).is_err(),
                "mode 0622 (group-write) must be rejected"
            );
        }

        #[test]
        fn mode_0602_is_rejected() {
            // World-write: any local user can inject shell commands.
            let f = tmp_file_with_mode(0o602);
            assert!(
                check_exec_config_permissions(f.path()).is_err(),
                "mode 0602 (world-write) must be rejected"
            );
        }
    }
}
