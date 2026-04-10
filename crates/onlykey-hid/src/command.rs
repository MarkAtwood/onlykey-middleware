use crate::error::HidError;

/// OnlyKey firmware command bytes (TYPE_INIT offsets from `okcore.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Command {
    Connect = 0xE4,
    GetLabels = 0xE5,
    GetPubkey = 0xEC,
    Sign = 0xED,
    Decrypt = 0xF0,
    Hmac = 0xF5,
}

impl Command {
    /// Wire byte value for this command.
    #[inline]
    pub fn wire_byte(self) -> u8 {
        self as u8
    }
}

/// A key slot on the OnlyKey device.
///
/// Derived key slots (201-204) are NOT variants here -- they are
/// exposed only as [`DerivedKeySlot`] constants, so the PKCS#11
/// object model cannot accidentally enumerate them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeySlot {
    /// RSA stored key, slots 1-4. Wire byte = slot number.
    RsaStored(u8),
    /// ECC stored key, slots 101-116. Wire byte = slot number.
    EccStored(u8),
}

impl KeySlot {
    /// Return `Ok(())` if the slot number is in the valid range,
    /// or `Err(HidError::InvalidSlot)` otherwise.
    pub fn validate(self) -> Result<(), HidError> {
        match self {
            KeySlot::RsaStored(n) if (1..=4).contains(&n) => Ok(()),
            KeySlot::EccStored(n) if (101..=116).contains(&n) => Ok(()),
            KeySlot::RsaStored(n) => Err(HidError::InvalidSlot(n)),
            KeySlot::EccStored(n) => Err(HidError::InvalidSlot(n)),
        }
    }

    /// Wire byte sent in frame[5] for this slot.
    #[inline]
    pub fn wire_slot(self) -> u8 {
        match self {
            KeySlot::RsaStored(n) | KeySlot::EccStored(n) => n,
        }
    }

    /// Returns `true` for RSA slots, `false` for ECC slots.
    #[inline]
    pub fn is_rsa(self) -> bool {
        matches!(self, KeySlot::RsaStored(_))
    }
}

/// Derived (agent-only) key slot constants -- wire byte values 201-204.
///
/// These slots are NEVER exposed through the PKCS#11 object model.
/// Code that addresses them must cast explicitly: `DerivedKeySlot::Ed25519 as u8`.
#[repr(u8)]
pub enum DerivedKeySlot {
    Ed25519 = 201,
    NistP256 = 202,
    Secp256k1 = 203,
    Curve25519 = 204,
}

/// Key capability flags packed into a single wire byte.
///
/// Bits 0-2: algorithm (Ed25519=1, NistP256=2, Secp256k1=3, Curve25519=4).
/// Bit 6 (0x40): signing capability.
/// Bit 5 (0x20): decryption capability.
/// Bit 7 (0x80): backup capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KeyType {
    Ed25519 = 1,
    NistP256 = 2,
    Secp256k1 = 3,
    Curve25519 = 4,
}

impl KeyType {
    /// Encode the algorithm and capability flags into a single wire byte.
    ///
    /// # Arguments
    ///
    /// - `sign`   -- set bit 6 (0x40) for signing capability
    /// - `decrypt` -- set bit 5 (0x20) for decryption capability
    /// - `backup`  -- set bit 7 (0x80) for backup capability
    pub fn with_flags(self, sign: bool, decrypt: bool, backup: bool) -> u8 {
        let mut byte = self as u8;
        if sign {
            byte |= 0x40;
        }
        if decrypt {
            byte |= 0x20;
        }
        if backup {
            byte |= 0x80;
        }
        byte
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_wire_bytes() {
        assert_eq!(Command::Connect.wire_byte(), 0xE4);
        assert_eq!(Command::GetLabels.wire_byte(), 0xE5);
        assert_eq!(Command::GetPubkey.wire_byte(), 0xEC);
        assert_eq!(Command::Sign.wire_byte(), 0xED);
        assert_eq!(Command::Decrypt.wire_byte(), 0xF0);
        assert_eq!(Command::Hmac.wire_byte(), 0xF5);
    }

    #[test]
    fn valid_rsa_slots() {
        for n in 1u8..=4 {
            assert_eq!(KeySlot::RsaStored(n).validate(), Ok(()));
            assert_eq!(KeySlot::RsaStored(n).wire_slot(), n);
            assert!(KeySlot::RsaStored(n).is_rsa());
        }
    }

    #[test]
    fn invalid_rsa_slot_0() {
        assert_eq!(
            KeySlot::RsaStored(0).validate(),
            Err(HidError::InvalidSlot(0))
        );
    }

    #[test]
    fn invalid_rsa_slot_5() {
        assert_eq!(
            KeySlot::RsaStored(5).validate(),
            Err(HidError::InvalidSlot(5))
        );
    }

    #[test]
    fn valid_ecc_slots() {
        for n in 101u8..=116 {
            assert_eq!(KeySlot::EccStored(n).validate(), Ok(()));
            assert_eq!(KeySlot::EccStored(n).wire_slot(), n);
            assert!(!KeySlot::EccStored(n).is_rsa());
        }
    }

    #[test]
    fn invalid_ecc_slot_100() {
        assert_eq!(
            KeySlot::EccStored(100).validate(),
            Err(HidError::InvalidSlot(100))
        );
    }

    #[test]
    fn invalid_ecc_slot_117() {
        assert_eq!(
            KeySlot::EccStored(117).validate(),
            Err(HidError::InvalidSlot(117))
        );
    }

    #[test]
    fn derived_slot_wire_values() {
        assert_eq!(DerivedKeySlot::Ed25519 as u8, 201);
        assert_eq!(DerivedKeySlot::NistP256 as u8, 202);
        assert_eq!(DerivedKeySlot::Secp256k1 as u8, 203);
        assert_eq!(DerivedKeySlot::Curve25519 as u8, 204);
    }

    #[test]
    fn key_type_flag_encoding() {
        // Ed25519 signing key: 0x41 (0x01 | 0x40)
        assert_eq!(KeyType::Ed25519.with_flags(true, false, false), 0x41);
        // Curve25519 ECDH key: 0x24 (0x04 | 0x20)
        assert_eq!(KeyType::Curve25519.with_flags(false, true, false), 0x24);
        // NistP256 signing key: 0x42 (0x02 | 0x40)
        assert_eq!(KeyType::NistP256.with_flags(true, false, false), 0x42);
        // All flags set on Ed25519: 0x01 | 0x40 | 0x20 | 0x80 = 0xE1
        assert_eq!(KeyType::Ed25519.with_flags(true, true, true), 0xE1);
        // No flags: just the algorithm byte
        assert_eq!(KeyType::Secp256k1.with_flags(false, false, false), 0x03);
    }
}
