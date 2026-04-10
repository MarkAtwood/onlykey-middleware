/// Errors that can occur in the `onlykey-hid` protocol layer.
///
/// This type is `no_std` compatible: `fmt::Display` is implemented via
/// `core::fmt`. `std::error::Error` is intentionally absent -- callers in
/// `onlykey-transport` wrap these via `From` conversions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HidError {
    /// A key slot number is out of the valid range.
    ///
    /// RSA stored slots: 1-4. ECC stored slots: 101-116.
    InvalidSlot(u8),
    /// The payload is too large to encode.
    ///
    /// Maximum is 768 bytes (`MAX_PAYLOAD`).
    PayloadTooLarge,
    /// A device response is shorter than the required minimum.
    ResponseTooShort,
    /// A device response has a length that does not match any valid value for
    /// the operation. For RSA signatures this means the response was not
    /// exactly 256 bytes (RSA-2048) or 512 bytes (RSA-4096).
    ///
    /// Carries the actual byte count received. Issue OnlyKey-uhd.
    ResponseWrongLength(usize),
    /// The ECDSA signature contains an invalid (zero) component.
    InvalidSignature,
    /// Device returned an unrecognized error code byte.
    Unknown(u8),
}

impl core::fmt::Display for HidError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HidError::InvalidSlot(n) => write!(f, "invalid key slot: {}", n),
            HidError::PayloadTooLarge => write!(f, "payload exceeds maximum of 768 bytes"),
            HidError::ResponseTooShort => write!(f, "device response is too short"),
            HidError::ResponseWrongLength(n) => write!(
                f,
                "device response has unexpected length: {} bytes (expected 256 or 512)",
                n
            ),
            HidError::InvalidSignature => {
                write!(f, "invalid ECDSA signature: zero component")
            }
            HidError::Unknown(b) => write!(f, "unknown device error code: 0x{:02x}", b),
        }
    }
}
