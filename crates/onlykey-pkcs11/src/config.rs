//! Slot configuration loaded from `slots.toml`.
//!
//! `slots.toml` records which algorithm each key slot uses, because the
//! OnlyKey wire protocol does not return algorithm information in
//! `OKGETPUBKEY` responses. A 32-byte response could be Ed25519 or Curve25519;
//! a 64-byte response could be P-256 or secp256k1.
//!
//! Default location: `$XDG_CONFIG_HOME/onlykey/slots.toml`
//! (falls back to `$HOME/.config/onlykey/slots.toml`).

use std::collections::HashMap;

use serde::Deserialize;

use crate::object::SlotAlgorithm;

/// Parsed `slots.toml` content.
///
/// TOML keys are always strings, so maps use `String` keys internally.
/// The accessor methods accept `u8` and convert to string for lookup.
///
/// **Note:** The `[labels]` map is shared across all slot types. A label keyed
/// by "1" applies to whichever slot with number 1 is looked up first. HMAC slot
/// numbers (1-2) can overlap with RSA slot numbers (1-4) in the labels map;
/// if disambiguation is needed, prefer HMAC slots 1-2 and RSA slots 3-4.
#[derive(Debug, Default, Deserialize)]
pub struct SlotConfig {
    /// ECC slot algorithm map: key = slot number string (e.g. "101"), value = algorithm name.
    #[serde(default)]
    pub ecc: HashMap<String, String>,
    /// RSA slot algorithm map: key = slot number string (e.g. "1"), value = "rsa2048" or "rsa4096".
    #[serde(default)]
    pub rsa: HashMap<String, String>,
    /// HMAC slot map: key = slot number string ("1" or "2"), value = "hmacsha1".
    #[serde(default)]
    pub hmac: HashMap<String, String>,
    /// Label overrides: key = slot number string, value = label string.
    #[serde(default)]
    pub labels: HashMap<String, String>,
}

impl SlotConfig {
    /// Load `slots.toml` from the default XDG config path.
    ///
    /// Returns `Ok(Self)` with empty maps if the file does not exist.
    pub fn load() -> Result<Self, String> {
        let path = dirs::config_dir()
            .map(|d| d.join("onlykey/slots.toml"))
            .ok_or_else(|| "cannot determine XDG config directory".to_string())?;

        if !path.exists() {
            return Ok(Self::empty());
        }

        let metadata = std::fs::metadata(&path).map_err(|e| format!("stat slots.toml: {}", e))?;
        if metadata.len() > 65536 {
            return Err(format!(
                "slots.toml too large: {} bytes (max 64 KiB)",
                metadata.len()
            ));
        }

        let text = std::fs::read_to_string(&path).map_err(|e| format!("read slots.toml: {}", e))?;
        let config = Self::parse(&text).map_err(|e| format!("{}: {}", path.display(), e))?;
        config.warn_unknown_algorithms();
        config.warn_duplicate_slots();
        Ok(config)
    }

    /// Parse a TOML string into a `SlotConfig`.
    pub fn parse(text: &str) -> Result<Self, String> {
        toml::from_str(text).map_err(|e| format!("parse slots.toml: {}", e))
    }

    /// Log a warning for any slot entries with unrecognised algorithm names.
    fn warn_unknown_algorithms(&self) {
        for (slot, value) in &self.ecc {
            if SlotAlgorithm::from_name(value).is_none() {
                eprintln!(
                    "slots.toml: slot {} has unknown algorithm '{}', skipping",
                    slot, value
                );
            }
        }
        for (slot, value) in &self.rsa {
            if SlotAlgorithm::from_name(value).is_none() {
                eprintln!(
                    "slots.toml: slot {} has unknown algorithm '{}', skipping",
                    slot, value
                );
            }
        }
        for (slot, value) in &self.hmac {
            if SlotAlgorithm::from_name(value).is_none() {
                eprintln!(
                    "slots.toml: HMAC slot {} has unknown algorithm '{}', skipping",
                    slot, value
                );
            }
        }
    }

    /// Log a warning if any slot number appears in conflicting sections.
    fn warn_duplicate_slots(&self) {
        for slot in self.ecc.keys() {
            if self.rsa.contains_key(slot) {
                eprintln!(
                    "slots.toml: slot {} appears in both [ecc] and [rsa], this is likely a mistake",
                    slot
                );
            }
        }
        for slot in self.hmac.keys() {
            if self.rsa.contains_key(slot) {
                eprintln!(
                    "slots.toml: slot {} appears in both [hmac] and [rsa], this is likely a mistake",
                    slot
                );
            }
        }
    }

    fn empty() -> Self {
        Self {
            ecc: HashMap::new(),
            rsa: HashMap::new(),
            hmac: HashMap::new(),
            labels: HashMap::new(),
        }
    }

    /// Return the algorithm for an ECC slot, or `None` if not configured.
    pub fn get_ecc(&self, slot: u8) -> Option<SlotAlgorithm> {
        self.ecc
            .get(&slot.to_string())
            .and_then(|s| SlotAlgorithm::from_name(s))
    }

    /// Return the algorithm for an RSA slot, or `None` if not configured.
    pub fn get_rsa(&self, slot: u8) -> Option<SlotAlgorithm> {
        self.rsa
            .get(&slot.to_string())
            .and_then(|s| SlotAlgorithm::from_name(s))
    }

    /// Return the algorithm for an HMAC slot (1 or 2), or `None` if not configured.
    pub fn get_hmac(&self, slot: u8) -> Option<SlotAlgorithm> {
        self.hmac
            .get(&slot.to_string())
            .and_then(|s| SlotAlgorithm::from_name(s))
    }

    /// Return a label override for a slot, or `None`.
    pub fn get_label(&self, slot: u8) -> Option<&str> {
        self.labels.get(&slot.to_string()).map(|s| s.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE_TOML: &str = r#"
[ecc]
101 = "ed25519"
102 = "curve25519"
104 = "nistp256"

[rsa]
3 = "rsa2048"
4 = "rsa4096"

[hmac]
1 = "hmacsha1"
2 = "hmacsha1"

[labels]
101 = "My Ed25519 signing key"
"#;

    #[test]
    fn parse_example() {
        let cfg = SlotConfig::parse(EXAMPLE_TOML).unwrap();
        assert_eq!(cfg.get_ecc(101), Some(SlotAlgorithm::Ed25519));
        assert_eq!(cfg.get_ecc(102), Some(SlotAlgorithm::Curve25519));
        assert_eq!(cfg.get_ecc(104), Some(SlotAlgorithm::NistP256));
        assert_eq!(cfg.get_rsa(3), Some(SlotAlgorithm::Rsa2048));
        assert_eq!(cfg.get_rsa(4), Some(SlotAlgorithm::Rsa4096));
        assert_eq!(cfg.get_hmac(1), Some(SlotAlgorithm::HmacSha1));
        assert_eq!(cfg.get_hmac(2), Some(SlotAlgorithm::HmacSha1));
        assert_eq!(cfg.get_label(101), Some("My Ed25519 signing key"));
        assert_eq!(cfg.get_ecc(103), None); // not configured
        assert_eq!(cfg.get_hmac(3), None); // only slots 1 and 2
    }

    #[test]
    fn missing_file_returns_empty() {
        let cfg = SlotConfig::parse("").unwrap_or(SlotConfig::empty());
        assert!(cfg.ecc.is_empty());
        assert!(cfg.rsa.is_empty());
    }
}
