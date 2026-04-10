//! ISO 7816-4 APDU parsing, R-APDU construction, and BER-TLV helpers.
//!
//! All seven APDU cases are supported, including extended Lc/Le fields.

/// Errors produced when parsing a command APDU.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum ApduError {
    /// The raw bytes are too short to contain a valid APDU header.
    #[error("APDU too short")]
    TooShort,
    /// The declared Lc length does not match the actual data bytes present.
    #[error("Lc/data length mismatch")]
    LcMismatch,
    /// The Le field is in an invalid position or cannot be parsed.
    #[error("Le field invalid")]
    LeInvalid,
}

/// A parsed ISO 7816-4 command APDU.
///
/// Covers all seven cases (1, 2S, 2E, 3S, 3E, 4S, 4E).
#[derive(Debug, Clone, PartialEq)]
pub struct Apdu {
    /// Class byte.
    pub cla: u8,
    /// Instruction byte.
    pub ins: u8,
    /// Parameter 1.
    pub p1: u8,
    /// Parameter 2.
    pub p2: u8,
    /// Command data (empty when no Lc field is present).
    pub data: Vec<u8>,
    /// Expected response length.
    ///
    /// - `None`: no Le field present (Cases 1 and 3).
    /// - `Some(256)`: short-form Le byte `0x00`.
    /// - `Some(65536)`: extended-form Le bytes `0x00 0x00`.
    /// - `Some(n)`: any other explicit Ne value.
    pub ne: Option<usize>,
}

impl Apdu {
    /// Parse a raw byte slice into a command APDU.
    ///
    /// Returns [`ApduError::TooShort`] when fewer than 4 bytes are supplied.
    /// Returns [`ApduError::LcMismatch`] when the stated Lc does not match
    /// the number of data bytes present.
    pub fn parse(raw: &[u8]) -> Result<Self, ApduError> {
        if raw.len() < 4 {
            return Err(ApduError::TooShort);
        }

        let (cla, ins, p1, p2) = (raw[0], raw[1], raw[2], raw[3]);
        let body = &raw[4..];

        let (data, ne) = Self::parse_body(body)?;

        Ok(Apdu {
            cla,
            ins,
            p1,
            p2,
            data,
            ne,
        })
    }

    /// Parses the body (everything after the 4-byte header) and returns
    /// `(data, ne)`.
    fn parse_body(body: &[u8]) -> Result<(Vec<u8>, Option<usize>), ApduError> {
        match body {
            // Case 1: no data, no Le.
            [] => Ok((vec![], None)),

            // Body starts with a non-zero byte: short Lc or short Le.
            [first, rest @ ..] if *first != 0x00 => {
                let lc = *first as usize;

                if rest.is_empty() {
                    // body.len() == 1, first != 0:
                    // Could be Case 2S (Le = first, which is non-zero).
                    // Could NOT be Case 3S (that would need lc==0, contradicting first!=0).
                    return Ok((vec![], Some(lc)));
                }

                // Attempt Case 3S or 4S: Lc = first, data = rest[0..lc].
                if rest.len() < lc {
                    return Err(ApduError::LcMismatch);
                }

                let data = rest[..lc].to_vec();
                let after = &rest[lc..];

                match after {
                    // Case 3S: no trailing Le.
                    [] => Ok((data, None)),
                    // Case 4S: one trailing Le byte.
                    [le] => {
                        let ne = if *le == 0x00 { 256 } else { *le as usize };
                        Ok((data, Some(ne)))
                    }
                    // Extra bytes -> ambiguous / malformed.
                    _ => Err(ApduError::LcMismatch),
                }
            }

            // Body starts with 0x00: extended form or Case 2S Le=256.
            [0x00, rest @ ..] => {
                match rest {
                    // body == [0x00]: Case 2S, Le = 256.
                    [] => Ok((vec![], Some(256))),

                    // body == [0x00, x]: 6 total bytes -- not a valid APDU case.
                    [_] => Err(ApduError::TooShort),

                    // body.len() == 3: Case 2E, Le = (rest[0] << 8) | rest[1].
                    [le_hi, le_lo] => {
                        let raw_le = (*le_hi as usize) << 8 | *le_lo as usize;
                        // raw_le=0 in extended form encodes Le=65536 per ISO 7816-4 sec.5.4.2
                        let ne = if raw_le == 0 { 65536 } else { raw_le };
                        Ok((vec![], Some(ne)))
                    }

                    // body.len() >= 4 (rest.len() >= 3): extended Lc form.
                    [lc_hi, lc_lo, tail @ ..] => {
                        let lc = (*lc_hi as usize) << 8 | *lc_lo as usize;

                        if lc == 0 {
                            // Extended Lc of zero is not meaningful here; only
                            // the 3-byte body form (Case 2E) is valid for Lc=0.
                            return Err(ApduError::LcMismatch);
                        }

                        if tail.len() < lc {
                            return Err(ApduError::LcMismatch);
                        }

                        let data = tail[..lc].to_vec();
                        let after = &tail[lc..];

                        match after {
                            // Case 3E: no trailing Le.
                            [] => Ok((data, None)),
                            // Case 4E: two trailing Le bytes.
                            [le_hi, le_lo] => {
                                let raw_le = (*le_hi as usize) << 8 | *le_lo as usize;
                                // raw_le=0 in extended form encodes Le=65536 per ISO 7816-4 sec.5.4.2
                                let ne = if raw_le == 0 { 65536 } else { raw_le };
                                Ok((data, Some(ne)))
                            }
                            // Anything else is malformed.
                            _ => Err(ApduError::LcMismatch),
                        }
                    }
                }
            }

            // The match is exhaustive; this arm is unreachable.
            _ => unreachable!(),
        }
    }
}

// ---------------------------------------------------------------------------
// Response APDU
// ---------------------------------------------------------------------------

/// An ISO 7816-4 response APDU.
///
/// Serialises to `data || SW1 || SW2` via [`RApdu::as_bytes`].
#[derive(Debug, Clone, PartialEq)]
pub struct RApdu {
    /// Response data (may be empty).
    pub data: Vec<u8>,
    /// Status word high byte.
    pub sw1: u8,
    /// Status word low byte.
    pub sw2: u8,
}

impl RApdu {
    /// Success response (SW `9000`) carrying `data`.
    pub fn ok(data: Vec<u8>) -> Self {
        RApdu {
            data,
            sw1: 0x90,
            sw2: 0x00,
        }
    }

    /// Success response (SW `9000`) with no data.
    pub fn ok_empty() -> Self {
        RApdu {
            data: vec![],
            sw1: 0x90,
            sw2: 0x00,
        }
    }

    /// Response chaining: SW `61xx`, where `xx` = number of remaining bytes.
    pub fn more_data(data: Vec<u8>, remaining: u8) -> Self {
        RApdu {
            data,
            sw1: 0x61,
            sw2: remaining,
        }
    }

    /// Wrong length: SW `6Cxx`, where `xx` is the correct expected length.
    pub fn wrong_length(expected: u8) -> Self {
        RApdu {
            data: vec![],
            sw1: 0x6C,
            sw2: expected,
        }
    }

    /// Security status not satisfied: SW `6982`.
    pub fn security_not_satisfied() -> Self {
        RApdu {
            data: vec![],
            sw1: 0x69,
            sw2: 0x82,
        }
    }

    /// Command not allowed -- conditions of use not satisfied: SW `6985`.
    pub fn conditions_not_satisfied() -> Self {
        RApdu {
            data: vec![],
            sw1: 0x69,
            sw2: 0x85,
        }
    }

    /// Wrong data: SW `6A80`.
    pub fn wrong_data() -> Self {
        RApdu {
            data: vec![],
            sw1: 0x6A,
            sw2: 0x80,
        }
    }

    /// Function not supported: SW `6A81`.
    pub fn func_not_supported() -> Self {
        RApdu {
            data: vec![],
            sw1: 0x6A,
            sw2: 0x81,
        }
    }

    /// File or application not found: SW `6A82`.
    pub fn file_not_found() -> Self {
        RApdu {
            data: vec![],
            sw1: 0x6A,
            sw2: 0x82,
        }
    }

    /// Instruction code not supported or invalid: SW `6D00`.
    pub fn ins_not_supported() -> Self {
        RApdu {
            data: vec![],
            sw1: 0x6D,
            sw2: 0x00,
        }
    }

    /// Wrong parameters P1/P2: SW `6B00`.
    pub fn wrong_parameters() -> Self {
        RApdu {
            data: vec![],
            sw1: 0x6B,
            sw2: 0x00,
        }
    }

    /// Class not supported: SW `6E00`.
    pub fn cla_not_supported() -> Self {
        RApdu {
            data: vec![],
            sw1: 0x6E,
            sw2: 0x00,
        }
    }

    /// Serialise to `data || SW1 || SW2`.
    pub fn as_bytes(&self) -> Vec<u8> {
        let mut out = self.data.clone();
        out.push(self.sw1);
        out.push(self.sw2);
        out
    }
}

// ---------------------------------------------------------------------------
// BER-TLV helpers
// ---------------------------------------------------------------------------

/// Encode a BER length field.
///
/// - Values 0-127: one byte.
/// - Values 128-255: `0x81` prefix + one byte.
/// - Values 256-65535: `0x82` prefix + two bytes (big-endian).
///
/// `pub(crate)` so cert.rs can share this implementation instead of duplicating it.
pub(crate) fn ber_len(len: usize) -> Vec<u8> {
    // Guard against lengths exceeding the two-byte long form (0x82 prefix).
    // Values > 65535 would silently produce a truncated/wrong length encoding.
    // X.690 sec.8.1.3 supports up to 126 long-form bytes, but nothing in this
    // codebase needs more than two. This is a programming error, not a
    // user error -- assert! (not debug_assert!) so it fires in release builds too.
    // Callers guard against this before calling (apdu.rs:85, piv.rs:138), but
    // a silent wrong encoding in a certificate is far worse than a panic.
    assert!(
        len <= 0xFFFF,
        "ber_len: length {} exceeds two-byte form limit (65535)",
        len
    );
    if len <= 0x7F {
        vec![len as u8]
    } else if len <= 0xFF {
        vec![0x81, len as u8]
    } else {
        vec![0x82, (len >> 8) as u8, (len & 0xFF) as u8]
    }
}

/// Encode a BER-TLV object: `tag || BER-length || value`.
///
/// `tag` may be 1 or 2 bytes; it is written verbatim.
pub fn tlv(tag: &[u8], value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(tag.len() + 3 + value.len());
    out.extend_from_slice(tag);
    out.extend_from_slice(&ber_len(value.len()));
    out.extend_from_slice(value);
    out
}

/// Parse BER-TLV with a nesting-depth budget.
///
/// This function is a thin wrapper around [`parse_tlv`] that only guards the
/// direct call site against `depth == 0`.  Actual recursion depth control is
/// **caller-enforced**: if the caller loops over returned values and calls
/// `parse_tlv_nested` again on nested TLV values, it must pass `depth - 1` on
/// each level.  Issue OnlyKey-yo3.
///
/// Recommended call pattern:
/// ```ignore
/// fn process(data: &[u8], depth: usize) {
///     for (tag, val) in parse_tlv_nested(data, depth) {
///         if is_constructed(&tag) {
///             process(&val, depth.saturating_sub(1));
///         }
///     }
/// }
/// process(input, 8);
/// ```
pub fn parse_tlv_nested(data: &[u8], depth: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
    if depth == 0 {
        return vec![];
    }
    parse_tlv(data)
}

/// Decode a flat BER-TLV list, returning `(tag, value)` pairs.
///
/// Tags of the form where the low 5 bits of the first byte are `0x1F` are
/// treated as two-byte tags (the multi-byte tag form); all other tags are
/// one byte.  Parsing stops at the first malformed or truncated TLV.
///
/// # Truncation behaviour (issue OnlyKey-463)
///
/// When the parser encounters a length byte it cannot handle -- in particular
/// `0x80` (BER indefinite-length form, forbidden in DER per X.690 sec.8.1.3)
/// or any long-form byte beyond `0x82` -- it stops immediately and returns
/// only the objects that were successfully parsed before that point.
///
/// **There is no indication to callers that parsing was truncated.**  The
/// return value looks identical whether the input contained exactly `n` objects
/// or whether parsing stopped early after `n` objects because the `(n+1)`th
/// TLV was malformed.
///
/// Consequence: if a caller is searching for a specific tag that happens to
/// appear *after* an indefinite-length (or otherwise unsupported) TLV in the
/// input stream, the tag will appear absent rather than triggering any error.
/// The caller will silently treat a malformed input as a "tag not found" case.
///
/// The stop-on-malformed behaviour is intentional and safe -- it prevents
/// unbounded reads and rejects non-DER encodings -- but callers that need to
/// verify completeness of parsing must use one of the following strategies:
///
/// - Know the expected number of TLV objects and verify `result.len()` matches.
/// - Check that all expected tags were found after parsing, and treat any
///   missing tag as a potential parse truncation rather than a genuine absence.
pub fn parse_tlv(data: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
    let mut result = Vec::new();
    let mut pos = 0;

    while pos < data.len() {
        // --- Tag ---
        let first = data[pos];

        // ISO 7816-4 sec.5.2.2.1: 0x00 is a padding byte (shall be skipped).
        // 0xFF is used for erased flash and is treated as padding (issue OnlyKey-qn5).
        if first == 0x00 || first == 0xFF {
            pos += 1;
            continue;
        }
        pos += 1;

        let tag = if (first & 0x1F) == 0x1F {
            // Long-form tag: subsequent bytes carry the tag number.
            // X.690 sec.8.1.2.4: a subsequent byte with bit 7 set means more bytes
            // follow (3+ byte tags). OpenPGP/PIV only use 1-2 byte tags, so we
            // stop rather than silently misinterpreting the following byte as a
            // length field (issue OnlyKey-dcp).
            if pos >= data.len() {
                break;
            }
            let second = data[pos];
            pos += 1;
            if second & 0x80 != 0 {
                // Tag spans >= 3 bytes -- not supported; stop parsing.
                break;
            }
            vec![first, second]
        } else {
            vec![first]
        };

        // --- Length ---
        if pos >= data.len() {
            break;
        }

        let len_byte = data[pos];
        pos += 1;

        let value_len = if len_byte <= 0x7F {
            len_byte as usize
        } else if len_byte == 0x81 {
            if pos >= data.len() {
                break;
            }
            let l = data[pos] as usize;
            pos += 1;
            l
        } else if len_byte == 0x82 {
            if pos + 1 >= data.len() {
                break;
            }
            let l = (data[pos] as usize) << 8 | data[pos + 1] as usize;
            pos += 2;
            l
        } else {
            // 0x80 is BER indefinite-length form, which is forbidden in DER
            // (X.690 sec.8.1.3). 0x83-0xFF are length forms beyond two long-form
            // bytes. Both are unsupported -- stop parsing (issue OnlyKey-xhq).
            break;
        };

        // --- Value ---
        if pos + value_len > data.len() {
            break;
        }

        let value = data[pos..pos + value_len].to_vec();
        pos += value_len;

        result.push((tag, value));
    }

    result
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // APDU parsing
    // -----------------------------------------------------------------------

    #[test]
    fn case1_no_data_no_le() {
        let raw = [0x00, 0xA4, 0x04, 0x00];
        let apdu = Apdu::parse(&raw).unwrap();
        assert_eq!(apdu.cla, 0x00);
        assert_eq!(apdu.ins, 0xA4);
        assert_eq!(apdu.p1, 0x04);
        assert_eq!(apdu.p2, 0x00);
        assert!(apdu.data.is_empty());
        assert_eq!(apdu.ne, None);
    }

    #[test]
    fn case2s_le_zero_means_256() {
        // Le byte 0x00 -> Ne = 256
        let raw = [0x00, 0xCA, 0x00, 0x6E, 0x00];
        let apdu = Apdu::parse(&raw).unwrap();
        assert!(apdu.data.is_empty());
        assert_eq!(apdu.ne, Some(256));
    }

    #[test]
    fn case2s_nonzero_le() {
        let raw = [0x00, 0xCA, 0x00, 0x6E, 0x40];
        let apdu = Apdu::parse(&raw).unwrap();
        assert!(apdu.data.is_empty());
        assert_eq!(apdu.ne, Some(0x40));
    }

    #[test]
    fn case3s_data_no_le() {
        let raw = [0x00, 0xA4, 0x04, 0x00, 0x05, 0xD2, 0x76, 0x00, 0x01, 0x24];
        let apdu = Apdu::parse(&raw).unwrap();
        assert_eq!(apdu.data, [0xD2, 0x76, 0x00, 0x01, 0x24]);
        assert_eq!(apdu.ne, None);
    }

    #[test]
    fn case4s_data_and_le() {
        let raw = [
            0x00, 0xA4, 0x04, 0x00, 0x05, 0xD2, 0x76, 0x00, 0x01, 0x24, 0x00,
        ];
        let apdu = Apdu::parse(&raw).unwrap();
        assert_eq!(apdu.data, [0xD2, 0x76, 0x00, 0x01, 0x24]);
        assert_eq!(apdu.ne, Some(256));
    }

    #[test]
    fn case2e_le_zero_means_65536() {
        // Extended Le: 4-byte header + [0x00, 0x00, 0x00]
        let raw = [0x00, 0xCA, 0x00, 0x6E, 0x00, 0x00, 0x00];
        let apdu = Apdu::parse(&raw).unwrap();
        assert!(apdu.data.is_empty());
        assert_eq!(apdu.ne, Some(65536));
    }

    #[test]
    fn case2e_nonzero_le() {
        let raw = [0x00, 0xCA, 0x00, 0x6E, 0x00, 0x01, 0x00];
        let apdu = Apdu::parse(&raw).unwrap();
        assert!(apdu.data.is_empty());
        assert_eq!(apdu.ne, Some(0x0100));
    }

    #[test]
    fn case3e_extended_lc_no_le() {
        // Lc_ext = 0x0003, data = [0xAA, 0xBB, 0xCC]
        let raw = [
            0x00, 0xDB, 0x3F, 0xFF, // header
            0x00, 0x00, 0x03, // extended Lc = 3
            0xAA, 0xBB, 0xCC, // data
        ];
        let apdu = Apdu::parse(&raw).unwrap();
        assert_eq!(apdu.data, [0xAA, 0xBB, 0xCC]);
        assert_eq!(apdu.ne, None);
    }

    #[test]
    fn case4e_extended_lc_and_le() {
        // Lc_ext = 2, data = [0x01, 0x02], Le_ext = 0x0100 = 256
        let raw = [
            0x00, 0xDB, 0x3F, 0xFF, // header
            0x00, 0x00, 0x02, // extended Lc = 2
            0x01, 0x02, // data
            0x01, 0x00, // extended Le = 256
        ];
        let apdu = Apdu::parse(&raw).unwrap();
        assert_eq!(apdu.data, [0x01, 0x02]);
        assert_eq!(apdu.ne, Some(0x0100));
    }

    #[test]
    fn too_short_returns_error() {
        assert_eq!(
            Apdu::parse(&[0x00, 0xA4, 0x04]).unwrap_err(),
            ApduError::TooShort
        );
        assert_eq!(Apdu::parse(&[]).unwrap_err(), ApduError::TooShort);
    }

    #[test]
    fn lc_mismatch_returns_error() {
        // Lc says 5 bytes but only 2 follow.
        let raw = [0x00, 0xA4, 0x04, 0x00, 0x05, 0xD2, 0x76];
        assert_eq!(Apdu::parse(&raw).unwrap_err(), ApduError::LcMismatch);
    }

    // -----------------------------------------------------------------------
    // R-APDU
    // -----------------------------------------------------------------------

    #[test]
    fn rapdu_ok_encodes_data_then_9000() {
        let r = RApdu::ok(vec![0x01, 0x02, 0x03]);
        assert_eq!(r.as_bytes(), [0x01, 0x02, 0x03, 0x90, 0x00]);
    }

    #[test]
    fn rapdu_ok_empty_is_9000_only() {
        assert_eq!(RApdu::ok_empty().as_bytes(), [0x90, 0x00]);
    }

    #[test]
    fn rapdu_more_data_sw_61xx() {
        let r = RApdu::more_data(vec![0xAB], 3);
        assert_eq!(r.sw1, 0x61);
        assert_eq!(r.sw2, 0x03);
        assert_eq!(r.as_bytes(), [0xAB, 0x61, 0x03]);
    }

    #[test]
    fn rapdu_wrong_length_sw_6cxx() {
        let r = RApdu::wrong_length(0x10);
        assert_eq!(r.as_bytes(), [0x6C, 0x10]);
    }

    #[test]
    fn rapdu_status_words() {
        assert_eq!(RApdu::security_not_satisfied().as_bytes(), [0x69, 0x82]);
        assert_eq!(RApdu::conditions_not_satisfied().as_bytes(), [0x69, 0x85]);
        assert_eq!(RApdu::wrong_data().as_bytes(), [0x6A, 0x80]);
        assert_eq!(RApdu::func_not_supported().as_bytes(), [0x6A, 0x81]);
        assert_eq!(RApdu::file_not_found().as_bytes(), [0x6A, 0x82]);
        assert_eq!(RApdu::ins_not_supported().as_bytes(), [0x6D, 0x00]);
        assert_eq!(RApdu::wrong_parameters().as_bytes(), [0x6B, 0x00]);
        assert_eq!(RApdu::cla_not_supported().as_bytes(), [0x6E, 0x00]);
    }

    // -----------------------------------------------------------------------
    // Lc/Le validation (OnlyKey-mj6 / OnlyKey-8tc)
    // -----------------------------------------------------------------------

    #[test]
    fn lc_mismatch_short_case() {
        // Lc declares 5 but only 2 bytes present -- short form.
        let raw = [0x00, 0xA4, 0x04, 0x00, 0x05, 0xD2, 0x76];
        assert_eq!(Apdu::parse(&raw).unwrap_err(), ApduError::LcMismatch);
    }

    #[test]
    fn lc_mismatch_extended_case() {
        // Extended Lc declares 4 bytes but only 2 are present.
        let raw = [0x00, 0xDB, 0x3F, 0xFF, 0x00, 0x00, 0x04, 0xAA, 0xBB];
        assert_eq!(Apdu::parse(&raw).unwrap_err(), ApduError::LcMismatch);
    }

    // -----------------------------------------------------------------------
    // parse_tlv_nested depth guard (OnlyKey-7zg)
    // -----------------------------------------------------------------------

    #[test]
    fn parse_tlv_nested_zero_depth_returns_empty() {
        let encoded = tlv(&[0x01], b"data");
        let result = parse_tlv_nested(&encoded, 0);
        assert!(result.is_empty(), "depth=0 must return empty vec");
    }

    #[test]
    fn parse_tlv_nested_nonzero_depth_parses_normally() {
        let encoded = tlv(&[0x01], b"data");
        let result = parse_tlv_nested(&encoded, 8);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].1, b"data");
    }

    // -----------------------------------------------------------------------
    // BER-TLV
    // -----------------------------------------------------------------------

    #[test]
    fn ber_len_short_form() {
        assert_eq!(ber_len(0), vec![0x00]);
        assert_eq!(ber_len(0x7F), vec![0x7F]);
    }

    #[test]
    fn ber_len_0x80_uses_81_prefix() {
        assert_eq!(ber_len(0x80), vec![0x81, 0x80]);
    }

    #[test]
    fn ber_len_0xff_uses_81_prefix() {
        assert_eq!(ber_len(0xFF), vec![0x81, 0xFF]);
    }

    #[test]
    fn ber_len_0x200_uses_82_prefix() {
        assert_eq!(ber_len(0x200), vec![0x82, 0x02, 0x00]);
    }

    #[test]
    fn tlv_roundtrip_single_byte_tag() {
        let encoded = tlv(&[0x6E], b"hello");
        let pairs = parse_tlv(&encoded);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, vec![0x6E]);
        assert_eq!(pairs[0].1, b"hello");
    }

    #[test]
    fn tlv_roundtrip_two_byte_tag() {
        // 0x5F prefix: low 5 bits of 0x5F are 0x1F -> two-byte tag.
        let encoded = tlv(&[0x5F, 0x28], b"world");
        let pairs = parse_tlv(&encoded);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, vec![0x5F, 0x28]);
        assert_eq!(pairs[0].1, b"world");
    }

    #[test]
    fn tlv_roundtrip_multiple_objects() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&tlv(&[0x01], b"abc"));
        buf.extend_from_slice(&tlv(&[0x02], b"xy"));
        let pairs = parse_tlv(&buf);
        assert_eq!(pairs.len(), 2);
        assert_eq!(pairs[0], (vec![0x01], b"abc".to_vec()));
        assert_eq!(pairs[1], (vec![0x02], b"xy".to_vec()));
    }

    #[test]
    fn tlv_long_value_uses_ber_81_prefix() {
        let value = vec![0u8; 0x80];
        let encoded = tlv(&[0x53], &value);
        // tag(1) + 0x81 + 0x80 + 128 bytes
        assert_eq!(encoded[0], 0x53);
        assert_eq!(encoded[1], 0x81);
        assert_eq!(encoded[2], 0x80);
        let pairs = parse_tlv(&encoded);
        assert_eq!(pairs[0].1.len(), 0x80);
    }

    #[test]
    fn parse_tlv_truncated_stops_cleanly() {
        // A well-formed TLV followed by a truncated one -- should return only the first.
        let mut buf = tlv(&[0x01], b"ok");
        buf.extend_from_slice(&[0x02, 0x05]); // says length 5 but no data follows
        let pairs = parse_tlv(&buf);
        assert_eq!(pairs.len(), 1);
    }

    #[test]
    fn parse_tlv_skips_0x00_padding() {
        // ISO 7816-4: 0x00 bytes are padding and must be skipped.
        // Previously these were parsed as 1-byte tag 0x00 (issue OnlyKey-qn5).
        let mut buf = vec![0x00, 0x00]; // two padding bytes
        buf.extend_from_slice(&tlv(&[0x41], b"data"));
        buf.extend_from_slice(&[0x00]); // trailing padding
        let pairs = parse_tlv(&buf);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, &[0x41]);
        assert_eq!(pairs[0].1, b"data");
    }

    #[test]
    fn parse_tlv_skips_0xff_padding() {
        // 0xFF is used for erased flash and is padding per ISO 7816-4.
        // Previously 0xFF caused entry into the two-byte tag branch (issue OnlyKey-qn5).
        let mut buf = vec![0xFF, 0xFF]; // erased flash / padding
        buf.extend_from_slice(&tlv(&[0x41], b"hi"));
        let pairs = parse_tlv(&buf);
        assert_eq!(pairs.len(), 1);
        assert_eq!(pairs[0].0, &[0x41]);
    }

    #[test]
    fn parse_tlv_stops_on_three_byte_tag() {
        // X.690 sec.8.1.2.4: a second tag byte with bit 7 set means more bytes follow.
        // parse_tlv only supports 1- and 2-byte tags; it must stop rather than
        // misinterpreting the third byte as a length field (issue OnlyKey-dcp).
        // Input: tag 0x1F 0x81 (second byte has bit 7 set -> 3-byte tag) + dummy data.
        let buf = [0x1F, 0x81, 0x01, 0xAB];
        let pairs = parse_tlv(&buf);
        assert!(
            pairs.is_empty(),
            "3-byte tag must not be parsed as two-byte tag"
        );
    }

    #[test]
    fn parse_tlv_stops_on_indefinite_length() {
        // 0x80 is the BER indefinite-length form, forbidden in DER (issue OnlyKey-xhq).
        // parse_tlv must stop on 0x80 rather than treating it as a 128-byte length.
        let buf = [0x41, 0x80, 0x01, 0x02]; // tag=0x41, len=0x80 (indefinite)
        let pairs = parse_tlv(&buf);
        assert!(
            pairs.is_empty(),
            "0x80 indefinite-length must not be accepted"
        );
    }
}
