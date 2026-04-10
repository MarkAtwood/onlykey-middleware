/// Errors that can occur in the `onlykey-transport` layer.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// HID I/O error from hidapi.
    #[error("HID error: {0}")]
    Hid(#[from] hidapi::HidError),

    /// The device was disconnected during an operation.
    ///
    /// Detected by inspecting the hidapi error message for known disconnection
    /// substrings ("disconnected", "device removed", "hid_read"). This heuristic
    /// is cross-platform; callers should prompt the user to reconnect.
    #[error("OnlyKey disconnected")]
    Disconnected,

    /// No OnlyKey device found on any of the known VID/PID pairs.
    #[error("OnlyKey device not found")]
    NotFound,

    /// Device is initialized but locked. User must unlock it physically.
    #[error("OnlyKey is locked -- unlock it and try again")]
    Locked,

    /// Device has not been initialized by the OnlyKey app.
    #[error("OnlyKey is uninitialized")]
    Uninitialized,

    /// The user did not press the button within the challenge timeout.
    ///
    /// This maps to `CKR_FUNCTION_REJECTED` in the PKCS#11 layer
    /// (NOT `CKR_FUNCTION_CANCELED`). See openspec/AGENTS.md settled constraints.
    #[error("challenge button press timed out")]
    ChallengeTimeout,

    /// The device returned an error response (begins with "Error").
    #[error("device error: {0}")]
    Device(String),

    /// The device response was malformed or had an unexpected length.
    #[error("protocol error: {0}")]
    Protocol(String),

    /// Configuration file parse error.
    #[error("config error: {0}")]
    Config(String),
}

impl From<onlykey_hid::HidError> for TransportError {
    fn from(e: onlykey_hid::HidError) -> Self {
        TransportError::Protocol(e.to_string())
    }
}
