use std::io::Write;

/// Trait for displaying the three-digit challenge code to the user.
///
/// The challenge must be displayed BEFORE the blocking read that waits for
/// the button press. Implementations must be `Send + Sync` so they can be
/// used across threads.
pub trait ChallengeDisplay: Send + Sync {
    /// Show the three-digit challenge code.
    ///
    /// The three bytes are each in the range `[1, 6]` (matching OnlyKey's buttons).
    ///
    /// # Failure behaviour (best-effort, no return value)
    ///
    /// This method has no return type; display failures are silent from the
    /// caller's perspective.  The C_Sign path cannot distinguish "display
    /// succeeded" from "display failed" -- it simply blocks waiting for the
    /// button press regardless.
    ///
    /// When the `exec:` display mode is used, a failure to spawn the configured
    /// command causes the digits to be written to stderr as a fallback.  In
    /// daemon contexts where stderr is redirected to a log file or `/dev/null`,
    /// the user may therefore never see the challenge, and the operation will
    /// time out silently.
    ///
    /// Changing this signature to return `Result` would be a breaking trait
    /// change and would require every implementation and every call site to be
    /// updated.  The current design is an accepted limitation; see issue
    /// OnlyKey-se3.
    fn show(&self, digits: [u8; 3]);
}

/// Write the challenge to stderr.
pub struct StderrDisplay;

impl ChallengeDisplay for StderrDisplay {
    fn show(&self, digits: [u8; 3]) {
        eprintln!(
            "OnlyKey challenge: {} {} {} (press corresponding buttons)",
            digits[0], digits[1], digits[2]
        );
    }
}

/// Write the challenge to `/dev/tty`, falling back to stderr.
///
/// `/dev/tty` is the controlling terminal regardless of stdout/stderr
/// redirection, making it suitable for interactive prompts in daemon or
/// piped contexts.
pub struct TtyDisplay;

impl ChallengeDisplay for TtyDisplay {
    fn show(&self, digits: [u8; 3]) {
        let message = format!(
            "OnlyKey challenge: {} {} {} (press corresponding buttons)\n",
            digits[0], digits[1], digits[2]
        );
        // Try /dev/tty first; fall back to stderr.
        if let Ok(mut tty) = std::fs::OpenOptions::new().write(true).open("/dev/tty") {
            let _ = tty.write_all(message.as_bytes());
        } else {
            eprint!("{}", message);
        }
    }
}

/// Execute a shell command, substituting each `%d` with the corresponding digit.
///
/// The three digits are substituted in order for each `%d` occurrence.
/// Example: `ExecDisplay("notify-send 'Press %d %d %d'")` produces
/// `notify-send 'Press 3 1 4'` for digits `[3, 1, 4]`.
///
/// # Security note
///
/// The template string is passed verbatim to `sh -c`, so it can contain
/// arbitrary shell syntax. This is intentional -- common use-cases like
/// `notify-send` require shell quoting. The template comes from
/// `~/.config/onlykey/config.toml`, which is user-owned and should have
/// mode 0600. Treat it with the same trust level as an executable script:
/// do not allow other users to write to it.
pub struct ExecDisplay(pub String);

impl ChallengeDisplay for ExecDisplay {
    fn show(&self, digits: [u8; 3]) {
        let mut cmd = self.0.clone();
        for &d in &digits {
            cmd = cmd.replacen("%d", &d.to_string(), 1);
        }
        // Log to stderr if spawn fails (e.g. sh not found, permission denied).
        // show() cannot return an error (see trait doc), so stderr is the best
        // available fallback: at least the user sees why the challenge was not
        // displayed rather than watching the operation silently time out.
        // In daemon contexts where stderr is redirected, the user may still not
        // see the output -- that is the accepted limitation documented on the
        // trait (issue OnlyKey-se3).
        //
        // The child must be reaped to avoid zombie processes. Because show()
        // returns () and must not block, we move the Child into a background
        // thread that calls wait(). Issue OnlyKey-stxr.
        match std::process::Command::new("sh").args(["-c", &cmd]).spawn() {
            Ok(mut child) => {
                std::thread::spawn(move || {
                    let _ = child.wait();
                });
            }
            Err(e) => {
                eprintln!("onlykey: challenge display command failed to spawn: {e}");
                eprintln!(
                    "onlykey: challenge digits: {} {} {}",
                    digits[0], digits[1], digits[2]
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::config::ChallengeDisplayKind;

    #[test]
    fn exec_display_interpolates_digits() {
        // Verify the substitution logic without actually executing a command.
        let template = "echo %d-%d-%d".to_string();
        let mut cmd = template.clone();
        let digits = [3u8, 1, 4];
        for &d in &digits {
            cmd = cmd.replacen("%d", &d.to_string(), 1);
        }
        assert_eq!(cmd, "echo 3-1-4");
    }

    #[test]
    fn challenge_display_kind_parse_coverage() {
        assert_eq!(
            ChallengeDisplayKind::parse("tty").unwrap(),
            ChallengeDisplayKind::Tty
        );
        assert_eq!(
            ChallengeDisplayKind::parse("stderr").unwrap(),
            ChallengeDisplayKind::Stderr
        );
        assert!(matches!(
            ChallengeDisplayKind::parse("exec:some-cmd %d %d %d"),
            Ok(ChallengeDisplayKind::Exec(_))
        ));
        assert!(ChallengeDisplayKind::parse("invalid").is_err());
    }
}
