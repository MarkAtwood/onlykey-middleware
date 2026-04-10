use std::path::Path;

/// Load a certificate from a PEM or DER file, returning DER bytes.
///
/// - If the file starts with `-----`, it is treated as PEM and the base64 body
///   between the first `-----BEGIN ...-----` and `-----END ...-----` markers is decoded.
/// - Otherwise the raw bytes are returned as-is (assumed to be DER).
/// - Files larger than 64 KiB are rejected.
pub fn load_cert_file(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let canonical = std::fs::canonicalize(path)?;

    // Require a resolvable home directory so the guard cannot be silently
    // bypassed in containers or service accounts where home_dir() is None.
    let home =
        dirs::home_dir().ok_or("cannot determine home directory; refusing to load certificate")?;
    if !canonical.starts_with(&home) {
        return Err("certificate path is outside home directory".into());
    }

    let metadata = std::fs::metadata(&canonical)?;
    if metadata.len() > 65536 {
        return Err(format!("file too large: {} bytes (max 64 KiB)", metadata.len()).into());
    }

    let bytes = std::fs::read(&canonical)?;

    if bytes.starts_with(b"-----") {
        let text = std::str::from_utf8(&bytes).map_err(|_| "PEM file is not valid UTF-8")?;
        let body: String = text
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        let b64: String = body.chars().filter(|c| !c.is_whitespace()).collect();
        decode_base64(&b64).map_err(|e| format!("PEM base64 decode error: {}", e).into())
    } else {
        Ok(bytes)
    }
}

/// Minimal base64 decoder (standard alphabet, with padding).
pub fn decode_base64(s: &str) -> Result<Vec<u8>, &'static str> {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let decode_char =
        |c: u8| -> Option<u8> { ALPHABET.iter().position(|&x| x == c).map(|i| i as u8) };

    let s = s.trim_end_matches('=');
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let bytes: Vec<u8> = s.bytes().collect();

    for chunk in bytes.chunks(4) {
        let a = decode_char(chunk[0]).ok_or("invalid base64 character")?;
        let b = decode_char(*chunk.get(1).ok_or("truncated base64")?)
            .ok_or("invalid base64 character")?;
        out.push((a << 2) | (b >> 4));
        if let Some(&c_byte) = chunk.get(2) {
            let c = decode_char(c_byte).ok_or("invalid base64 character")?;
            out.push(((b & 0x0F) << 4) | (c >> 2));
            if let Some(&d_byte) = chunk.get(3) {
                let d = decode_char(d_byte).ok_or("invalid base64 character")?;
                out.push(((c & 0x03) << 6) | d);
            }
        }
    }
    Ok(out)
}
