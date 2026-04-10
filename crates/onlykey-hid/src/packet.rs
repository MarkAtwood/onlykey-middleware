use crate::error::HidError;

/// State of the OnlyKey device as decoded from an OKCONNECT response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeviceState {
    /// Device is unlocked and ready. Carries the firmware version string.
    Unlocked(alloc::string::String),
    /// Device is initialized but locked (awaiting PIN entry on device).
    Locked,
    /// Device has not been initialized.
    Uninitialized,
}

/// A single 64-byte HID frame.
///
/// Frame layout:
/// - bytes [0..3]: `0xFF 0xFF 0xFF 0xFF` header
/// - byte [4]: command byte
/// - byte [5]: slot byte
/// - byte [6]: field byte (payload length for last chunk, `0xFF` for non-last)
/// - bytes [7..64]: payload (zero-padded)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HidFrame([u8; 64]);

impl HidFrame {
    /// The mandatory 4-byte header that begins every frame.
    pub(crate) const HEADER: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];

    /// Maximum number of payload bytes in a single frame (64 - 7 = 57).
    pub const MAX_SINGLE_PAYLOAD: usize = 57;

    /// Build a single-packet command frame.
    ///
    /// Fails with [`HidError::PayloadTooLarge`] if `payload.len() > 57`.
    pub fn command(cmd: u8, slot: u8, payload: &[u8]) -> Result<Self, HidError> {
        if payload.len() > Self::MAX_SINGLE_PAYLOAD {
            return Err(HidError::PayloadTooLarge);
        }
        let mut frame = [0u8; 64];
        frame[0..4].copy_from_slice(&Self::HEADER);
        frame[4] = cmd;
        frame[5] = slot;
        frame[6] = payload.len() as u8;
        frame[7..7 + payload.len()].copy_from_slice(payload);
        Ok(HidFrame(frame))
    }

    /// Construct a frame directly from 64 raw bytes (e.g. a device response).
    #[inline]
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        HidFrame(bytes)
    }

    /// Return the 64 raw bytes of the frame.
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    /// Returns `true` if the frame is an error response from the device.
    ///
    /// An error frame begins with the ASCII bytes `"Error"` and every
    /// remaining byte is printable ASCII (0x20-0x7E) or NUL (0x00).
    ///
    /// This is stricter than `Response::is_error()`, which checks only the
    /// `"Error"` prefix. That is intentional layering: this method validates
    /// the raw frame before constructing a `Response`; once the `Response`
    /// exists its bytes are already known to be valid ASCII/NUL.
    ///
    /// # Frame-length note
    ///
    /// `HidFrame` always holds exactly 64 bytes, so the `len < 5` guard
    /// present in some earlier versions was dead code. The check is omitted
    /// here; the compile-time assertion below enforces the invariant.
    /// Issue OnlyKey-4m7d.
    pub fn is_error_response(&self) -> bool {
        let b = &self.0;
        // HidFrame is always 64 bytes (enforced by the struct definition and
        // the assertion below); b.len() < 5 can never be true. Issue OnlyKey-4m7d.
        const _: () = assert!(
            core::mem::size_of::<HidFrame>() == 64,
            "HidFrame must be exactly 64 bytes"
        );
        if &b[0..5] != b"Error" {
            return false;
        }
        b[5..].iter().all(|&c| c == 0 || (0x20..=0x7E).contains(&c))
    }

    /// Extract the device state from an OKCONNECT response frame.
    ///
    /// Matches the prefix strings sent by the OnlyKey firmware:
    /// - `"UNLOCKEDv..."` -> `DeviceState::Unlocked(version_suffix)`
    /// - `"INITIALIZED"`  -> `DeviceState::Locked`
    /// - `"UNINITIALIZED"` -> `DeviceState::Uninitialized`
    ///
    /// Returns `None` if the frame does not match any known state string.
    pub fn device_state(&self) -> Option<DeviceState> {
        let raw = &self.0;
        // Stop at the first byte outside printable ASCII (0x20-0x7E), which
        // includes NUL (0x00). The OnlyKey firmware sends only printable ASCII
        // in state strings; stopping here prevents padding bytes (zeros or
        // non-ASCII) from leaking into the version string. Issue OnlyKey-eba.
        let len = raw.iter().position(|&b| b < 0x20 || b > 0x7E).unwrap_or(raw.len());
        // Silently return None for invalid UTF-8: an unrecognized frame is
        // treated as "unknown state" rather than a hard error. The OnlyKey
        // firmware always sends ASCII-printable state strings, so invalid UTF-8
        // means we're looking at a non-state response frame, and the caller
        // already handles None by falling back to polling. Issue OnlyKey-ccv.
        let s = core::str::from_utf8(&raw[..len]).ok()?;

        if let Some(version) = s.strip_prefix("UNLOCKEDv") {
            return Some(DeviceState::Unlocked(alloc::string::String::from(version)));
        }
        if s.starts_with("INITIALIZED") {
            return Some(DeviceState::Locked);
        }
        if s.starts_with("UNINITIALIZED") {
            return Some(DeviceState::Uninitialized);
        }
        None
    }

    /// Extract the firmware version string from a `DeviceState::Unlocked` frame.
    ///
    /// Returns `None` if the frame does not represent an unlocked state.
    pub fn firmware_version(&self) -> Option<alloc::string::String> {
        match self.device_state()? {
            DeviceState::Unlocked(v) => Some(v),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_frame_layout() {
        let payload = &[0x01, 0x02, 0x03];
        let frame = HidFrame::command(0xEC, 101, payload).unwrap();
        let b = frame.as_bytes();
        // Header
        assert_eq!(&b[0..4], &[0xFF, 0xFF, 0xFF, 0xFF]);
        // Command
        assert_eq!(b[4], 0xEC);
        // Slot
        assert_eq!(b[5], 101);
        // Field = payload length
        assert_eq!(b[6], 3);
        // Payload
        assert_eq!(&b[7..10], payload);
        // Rest is zero-padded
        assert!(b[10..].iter().all(|&x| x == 0));
    }

    #[test]
    fn payload_too_large() {
        let big = [0u8; 58];
        assert_eq!(
            HidFrame::command(0xED, 101, &big),
            Err(HidError::PayloadTooLarge)
        );
    }

    #[test]
    fn exact_max_payload_fits() {
        let max = [0u8; 57];
        assert!(HidFrame::command(0xED, 101, &max).is_ok());
    }

    #[test]
    fn device_state_unlocked() {
        let mut raw = [0u8; 64];
        let s = b"UNLOCKEDv5.2.0";
        raw[..s.len()].copy_from_slice(s);
        let frame = HidFrame::from_bytes(raw);
        assert_eq!(
            frame.device_state(),
            Some(DeviceState::Unlocked("5.2.0".into()))
        );
        assert_eq!(frame.firmware_version(), Some("5.2.0".into()));
    }

    #[test]
    fn device_state_locked() {
        let mut raw = [0u8; 64];
        let s = b"INITIALIZED";
        raw[..s.len()].copy_from_slice(s);
        let frame = HidFrame::from_bytes(raw);
        assert_eq!(frame.device_state(), Some(DeviceState::Locked));
    }

    #[test]
    fn device_state_uninitialized() {
        let mut raw = [0u8; 64];
        let s = b"UNINITIALIZED";
        raw[..s.len()].copy_from_slice(s);
        let frame = HidFrame::from_bytes(raw);
        assert_eq!(frame.device_state(), Some(DeviceState::Uninitialized));
    }

    #[test]
    fn is_error_response_true() {
        let mut raw = [0u8; 64];
        let s = b"Error invalid slot";
        raw[..s.len()].copy_from_slice(s);
        let frame = HidFrame::from_bytes(raw);
        assert!(frame.is_error_response());
    }

    #[test]
    fn binary_not_error() {
        let raw = [0xABu8; 64];
        let frame = HidFrame::from_bytes(raw);
        assert!(!frame.is_error_response());
    }

    #[test]
    fn device_state_invalid_utf8_returns_none() {
        // A frame with invalid UTF-8 bytes must return None (not panic).
        // This covers a firmware bug or non-state frame being passed by mistake.
        // Issue OnlyKey-ccv.
        let mut raw = [0u8; 64];
        raw[0] = 0xFF; // invalid UTF-8 lead byte
        raw[1] = 0xFE;
        let frame = HidFrame::from_bytes(raw);
        assert_eq!(frame.device_state(), None);
    }

    #[test]
    fn device_state_no_nul_terminator_stops_at_non_printable() {
        // A frame where the printable content is followed by non-printable bytes
        // (rather than NUL) must still parse cleanly and not include garbage.
        // Previously the parser fell back to raw.len() (64), producing a version
        // string with trailing junk. Issue OnlyKey-eba.
        let mut raw = [0xABu8; 64]; // fill with non-printable non-ASCII
        let s = b"UNLOCKEDv5.2.0";
        raw[..s.len()].copy_from_slice(s);
        // bytes after "UNLOCKEDv5.2.0" are 0xAB (non-ASCII) -- no NUL present
        let frame = HidFrame::from_bytes(raw);
        assert_eq!(
            frame.device_state(),
            Some(DeviceState::Unlocked("5.2.0".into())),
            "version string must not include non-printable trailing bytes"
        );
    }
}
