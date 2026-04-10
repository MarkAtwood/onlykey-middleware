use std::time::{Duration, Instant};

use hidapi::HidDevice;
use onlykey_hid::{HidFrame, Response};

use crate::error::TransportError;

/// Low-level HID I/O wrapper.
///
/// Handles the Windows 0x00 prefix for HID writes and the inter-frame
/// gap detection for multi-frame responses.
///
/// # HID read timeout contract
///
/// hidapi `read_timeout` semantics:
/// - `timeout_ms > 0`: wait at most N milliseconds; returns 0 on timeout.
/// - `timeout_ms == 0`: non-blocking; returns 0 if no data.
/// - `timeout_ms < 0`: block indefinitely (never used here).
///
/// Callers interpret `n == 0` as "no data within timeout" and `n == 64` as a
/// complete frame. Partial frames (`1 <= n < 64`) are always a hard protocol
/// error -- they indicate a corrupt or mis-framed response.
pub struct RawIo {
    pub(crate) hid: HidDevice,
    /// On Windows, hidapi requires a leading 0x00 report-ID byte.
    /// On Linux/macOS this is not needed.
    windows_prefix: bool,
    /// Timeout used when waiting for continuation frames after the first
    /// frame of a multi-frame response arrives. Set from `Config::inter_frame_timeout`
    /// at construction time. Default 500 ms covers wireless adapters with
    /// ~300 ms inter-frame gaps. Issue OnlyKey-8gje.
    inter_frame_timeout_ms: i32,
}

/// Maximum number of write retries for transient HID write failures.
///
/// Some USB hosts return a transient EAGAIN / EBUSY on the first write after a
/// USB suspend-resume cycle. Retrying up to this many times (with a short
/// delay) recovers in practice without confusing the device.
const WRITE_MAX_RETRIES: u32 = 3;
const WRITE_RETRY_DELAY: Duration = Duration::from_millis(10);

/// Substrings of hidapi error messages that indicate permanent device removal.
///
/// Each entry is annotated with the platform(s) and hidapi version where it was
/// observed. Audit this list on every hidapi version bump (Cargo.lock shows the
/// version). Add entries for new platforms; remove entries that no longer appear
/// in current hidapi error strings. Issue OnlyKey-hoj.
const DISCONNECT_SUBSTRINGS: &[&str] = &[
    // hidapi 2.6.5, Linux (libusb backend): "hid_error: device disconnected"
    "disconnected",
    // hidapi 2.6.5, macOS (IOHIDDevice): "IOHIDDevice - device removed"
    "device removed",
    // hidapi 2.6.5, Linux (raw hid backend): error messages include "hid_read"
    // when the file descriptor is closed by a device removal event.
    "hid_read",
    // hidapi 2.6.5, Windows (SetupAPI): "HID device not found" / "no device"
    "no device",
    // hidapi 2.6.5, Windows (SetupAPI): alternate form
    "device not found",
];

/// Returns `true` if the hidapi error message indicates the device was removed.
///
/// Detects USB disconnection by matching error message substrings from hidapi.
/// This is fragile: hidapi does not expose typed disconnect errors, so we
/// pattern-match on known strings. Tested against hidapi 2.6.5 on Linux and macOS.
/// MAINTENANCE: audit this list on every hidapi version bump, or when adding
/// new platform support.
pub(crate) fn is_disconnect_error(e: &hidapi::HidError) -> bool {
    let msg = e.to_string().to_ascii_lowercase();
    DISCONNECT_SUBSTRINGS.iter().any(|s| msg.contains(s))
}

impl RawIo {
    pub fn new(hid: HidDevice, inter_frame_timeout_ms: i32) -> Self {
        RawIo {
            hid,
            windows_prefix: cfg!(target_os = "windows"),
            inter_frame_timeout_ms,
        }
    }

    /// Write a single HID frame to the device.
    ///
    /// On Windows, prepends a 0x00 report-ID byte (hidapi requirement).
    ///
    /// Retries up to `WRITE_MAX_RETRIES` times on transient failures (e.g.
    /// USB resume cycle). Converts device-removal errors to
    /// `TransportError::Disconnected`.
    pub fn write(&self, frame: &HidFrame) -> Result<(), TransportError> {
        let bytes = frame.as_bytes();
        let mut last_err: Option<TransportError> = None;

        for attempt in 0..=WRITE_MAX_RETRIES {
            if attempt > 0 {
                std::thread::sleep(WRITE_RETRY_DELAY);
            }
            let result = if self.windows_prefix {
                let mut buf = [0u8; 65];
                buf[1..].copy_from_slice(bytes);
                self.hid.write(&buf)
            } else {
                self.hid.write(bytes)
            };
            match result {
                // hidapi returns 65 on Windows (report ID prefix included in count), 64 elsewhere; both are valid
                Ok(written) if written >= 64 => return Ok(()),
                Ok(written) => {
                    return Err(TransportError::Protocol(format!(
                        "short write: {} bytes instead of 64",
                        written
                    )));
                }
                Err(ref e) if is_disconnect_error(e) => {
                    return Err(TransportError::Disconnected);
                }
                Err(e) => {
                    last_err = Some(TransportError::Hid(e));
                }
            }
        }
        Err(last_err.unwrap_or(TransportError::Disconnected))
    }

    /// Read a single HID frame with the given timeout.
    ///
    /// Returns `ChallengeTimeout` if no data arrives within `timeout_ms`.
    /// Returns `Protocol` error for partial frames (1-63 bytes).
    /// Converts device-removal errors to `TransportError::Disconnected`.
    pub fn read_frame(&self, timeout_ms: i32) -> Result<HidFrame, TransportError> {
        let mut buf = [0u8; 64];
        let n = self.hid.read_timeout(&mut buf, timeout_ms).map_err(|e| {
            if is_disconnect_error(&e) {
                TransportError::Disconnected
            } else {
                TransportError::Hid(e)
            }
        })?;
        match n {
            0 => Err(TransportError::ChallengeTimeout),
            64 => Ok(HidFrame::from_bytes(buf)),
            _ => Err(TransportError::Protocol(format!(
                "partial HID frame: {} bytes (expected 64)",
                n
            ))),
        }
    }

    /// Read frames until an idle gap is detected.
    ///
    /// Accumulates payload bytes (bytes 7-63 of each frame) until the device
    /// stops sending for `inter_frame_timeout_ms`. Used for OKGETPUBKEY
    /// responses which span 1-9 frames (RSA-4096 = 512 bytes / 57 bytes/frame).
    ///
    /// Partial frames (1-63 bytes) are a hard protocol error. Disconnections
    /// are mapped to `TransportError::Disconnected`.
    ///
    /// Response payload size validation (256 bytes for RSA-2048, 512 for
    /// RSA-4096) is performed by the caller (`ops::get_pubkey`), not here.
    pub fn read_until_idle(&self, inter_frame_timeout_ms: i32) -> Result<Response, TransportError> {
        let mut payload: Vec<u8> = Vec::new();
        let mut frame_count: usize = 0;

        loop {
            let mut buf = [0u8; 64];
            let n = self
                .hid
                .read_timeout(&mut buf, inter_frame_timeout_ms)
                .map_err(|e| {
                    if is_disconnect_error(&e) {
                        TransportError::Disconnected
                    } else {
                        TransportError::Hid(e)
                    }
                })?;
            match n {
                0 => break,
                64 => accumulate_frame(buf, &mut payload, &mut frame_count)?,
                _ => {
                    return Err(TransportError::Protocol(format!(
                        "partial HID frame: {} bytes (expected 64)",
                        n
                    )));
                }
            }
        }

        Ok(Response::new(payload))
    }

    /// Block until the device responds or the deadline is reached.
    ///
    /// Polls with a 500ms read timeout. Once the first frame arrives, collects
    /// all subsequent frames using `self.inter_frame_timeout_ms` (default 500ms,
    /// configurable via `Config::inter_frame_timeout`; chosen to handle wireless
    /// adapters with ~300ms inter-frame gaps). Issue OnlyKey-8gje.
    ///
    /// Returns `ChallengeTimeout` if the deadline passes before any response.
    /// Returns `Disconnected` if the device is removed during the wait.
    /// Partial frames are a hard `Protocol` error.
    pub fn wait_for_response(&self, deadline: Instant) -> Result<Response, TransportError> {
        const POLL_MS: i32 = 500;
        let mut buf = [0u8; 64];

        // Outer loop: poll every POLL_MS until the first frame arrives or the
        // deadline passes. Once the first frame is received, switch to collecting
        // continuation frames with self.inter_frame_timeout_ms.
        loop {
            if Instant::now() >= deadline {
                return Err(TransportError::ChallengeTimeout);
            }
            let n = self.hid.read_timeout(&mut buf, POLL_MS).map_err(|e| {
                if is_disconnect_error(&e) {
                    TransportError::Disconnected
                } else {
                    TransportError::Hid(e)
                }
            })?;
            match n {
                0 => continue,
                64 => {
                    let mut payload: Vec<u8> = Vec::new();
                    let mut frame_count: usize = 0;
                    // Validate first frame and start accumulating payload.
                    accumulate_frame(buf, &mut payload, &mut frame_count)?;

                    // Collect any continuation frames until an idle gap.
                    loop {
                        let mut buf2 = [0u8; 64];
                        let n2 = self
                            .hid
                            .read_timeout(&mut buf2, self.inter_frame_timeout_ms)
                            .map_err(|e| {
                                if is_disconnect_error(&e) {
                                    TransportError::Disconnected
                                } else {
                                    TransportError::Hid(e)
                                }
                            })?;
                        match n2 {
                            0 => break,
                            64 => accumulate_frame(buf2, &mut payload, &mut frame_count)?,
                            _ => {
                                return Err(TransportError::Protocol(format!(
                                    "partial HID frame: {} bytes (expected 64)",
                                    n2
                                )));
                            }
                        }
                    }
                    return Ok(Response::new(payload));
                }
                _ => {
                    return Err(TransportError::Protocol(format!(
                        "partial HID frame: {} bytes (expected 64)",
                        n
                    )));
                }
            }
        }
    }
}

/// Validate and accumulate a single 64-byte HID frame into `payload`.
///
/// Shared by `read_until_idle` and `wait_for_response` to eliminate
/// duplicated per-frame validation logic. Issue OnlyKey-1ku.
///
/// Checks (in order):
/// 1. Error response prefix — returns `TransportError::Device`
/// 2. Magic header `0xFF*4` — returns `TransportError::Protocol`
/// 3. Frame count limit (14 frames max) — returns `TransportError::Protocol`
/// 4. Payload size limit (768 bytes max) — returns `TransportError::Protocol`
///
/// On success, `frame_count` is incremented and `buf[7..]` is appended to
/// `payload`.
fn accumulate_frame(
    buf: [u8; 64],
    payload: &mut Vec<u8>,
    frame_count: &mut usize,
) -> Result<(), TransportError> {
    /// Maximum frames in a complete response: ceil(768 / 57) = 14.
    const MAX_FRAMES: usize = 14;
    const _: () = assert!(
        MAX_FRAMES * 57 >= 768,
        "MAX_FRAMES must cover a full 768-byte payload"
    );

    // Check for a device error frame before accumulating payload.
    // Without this, an error response is silently treated as key/signature
    // bytes. Issue OnlyKey-3w7.
    let frame = HidFrame::from_bytes(buf);
    if frame.is_error_response() {
        let msg = String::from_utf8_lossy(frame.as_bytes())
            .trim_end_matches('\0')
            .to_string();
        return Err(TransportError::Device(msg));
    }
    // All frames carry the 0xFF*4 magic header per the OnlyKey wire protocol.
    // Issue OnlyKey-4cx.
    if buf[0..4] != [0xFF, 0xFF, 0xFF, 0xFF] {
        return Err(TransportError::Protocol(format!(
            "invalid response frame magic: {:02x?}",
            &buf[0..4]
        )));
    }
    *frame_count += 1;
    if *frame_count > MAX_FRAMES {
        return Err(TransportError::Protocol("too many response frames".into()));
    }
    payload.extend_from_slice(&buf[7..]);
    if payload.len() > 768 {
        return Err(TransportError::Protocol(
            "response exceeds 768-byte protocol maximum".into(),
        ));
    }
    Ok(())
}

/// Challenge timeout for HMAC operations.
///
/// HMAC does not require a button press; 3 seconds is generous for any
/// USB scheduling jitter.
///
/// # SHA-256 infallibility note
///
/// wolfcrypt's `Sha256::digest()` implements the RustCrypto `digest::Digest`
/// trait, which is infallible (no `Result` return). There are no wolfcrypt
/// return codes to check for hashing operations in this crate.
pub const HMAC_TIMEOUT_MS: Duration = Duration::from_secs(3);

#[cfg(test)]
mod tests {
    use super::DISCONNECT_SUBSTRINGS;

    // Construct a minimal HidError with a given message for testing
    // is_disconnect_error without a real HID device. hidapi::HidError does
    // not expose a public constructor for the message string, so we test via
    // strings that contain each known DISCONNECT_SUBSTRING.
    // Note: we can only test is_disconnect_error indirectly through the
    // DISCONNECT_SUBSTRINGS constant since HidError is opaque.

    #[test]
    fn disconnect_substrings_are_lowercase() {
        // is_disconnect_error calls .to_ascii_lowercase() before matching.
        // All DISCONNECT_SUBSTRINGS must already be lowercase so that the
        // comparison is correct. Issue OnlyKey-hoj.
        for s in DISCONNECT_SUBSTRINGS {
            assert_eq!(
                *s,
                s.to_ascii_lowercase(),
                "DISCONNECT_SUBSTRINGS entry {:?} is not lowercase",
                s
            );
        }
    }

    #[test]
    fn disconnect_substrings_are_nonempty() {
        // An empty substring would match every error message, causing all
        // transient HID errors to be misclassified as disconnections. Issue OnlyKey-hoj.
        for s in DISCONNECT_SUBSTRINGS {
            assert!(
                !s.is_empty(),
                "DISCONNECT_SUBSTRINGS must not contain empty strings"
            );
        }
    }
}
