// Challenge derivation requires wolfcrypt SHA-256, which wraps C code.
// wasm32-unknown-unknown cannot link against C code, so this entire module
// is excluded from wasm32 builds. The `cargo check --target wasm32-unknown-unknown`
// CI gate verifies that the rest of onlykey-hid is no_std without this module.
#![cfg(not(target_arch = "wasm32"))]

use wolfcrypt::digest::digest_trait::Digest;
use wolfcrypt::digest::Sha256;
use zeroize::Zeroize;

/// Derive the 3-button challenge code from a command payload.
///
/// The OnlyKey firmware displays three numbers on its six-button interface
/// before executing each cryptographic operation. The host must derive the
/// same numbers to prompt the user correctly.
///
/// # Algorithm (from `okcore.ino`)
///
/// 1. Compute `hash = SHA-256(payload)`
/// 2. For indices `i in {0, 15, 31}`: `result[i] = hash[i] % 6 + 1`
///
/// Each output byte is in the inclusive range `[1, 6]`, corresponding to
/// the six physical buttons on the device.
///
/// # Test vectors (from NIST SHA-256)
///
/// - `derive_challenge(b"")` = `[6, 1, 2]`
///   - SHA-256("") = `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
///   - byte[0]  = 0xe3 = 227; 227 % 6 = 5; 5 + 1 = 6
///   - byte[15] = 0x24 = 36;   36 % 6 = 0; 0 + 1 = 1
///   - byte[31] = 0x55 = 85;   85 % 6 = 1; 1 + 1 = 2
///
/// - `derive_challenge(b"hello")` = `[3, 3, 1]`
///   - SHA-256("hello") = `2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824`
///   - byte[0]  = 0x2c = 44;  44 % 6 = 2; 2 + 1 = 3
///   - byte[15] = 0x9e = 158; 158 % 6 = 2; 2 + 1 = 3
///   - byte[31] = 0x24 = 36;   36 % 6 = 0; 0 + 1 = 1
pub fn derive_challenge(payload: &[u8]) -> [u8; 3] {
    let mut hash: [u8; 32] = Sha256::digest(payload).into();
    let result = [hash[0] % 6 + 1, hash[15] % 6 + 1, hash[31] % 6 + 1];
    hash.zeroize();
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_empty_payload() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        // Verified with Python: hashlib.sha256(b"").hexdigest()
        // byte[0]  = 0xe3 = 227; 227 % 6 = 5; 5 + 1 = 6
        // byte[15] = 0x24 = 36;   36 % 6 = 0; 0 + 1 = 1
        // byte[31] = 0x55 = 85;   85 % 6 = 1; 1 + 1 = 2
        assert_eq!(derive_challenge(b""), [6, 1, 2]);
    }

    #[test]
    fn challenge_hello() {
        // SHA-256("hello") = 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824
        // Verified with Python: hashlib.sha256(b"hello").hexdigest()
        // byte[0]  = 0x2c = 44;  44 % 6 = 2; 2 + 1 = 3
        // byte[15] = 0x9e = 158; 158 % 6 = 2; 2 + 1 = 3
        // byte[31] = 0x24 = 36;   36 % 6 = 0; 0 + 1 = 1
        assert_eq!(derive_challenge(b"hello"), [3, 3, 1]);
    }

    #[test]
    fn challenge_range_all_values_in_1_6() {
        // Test a variety of payloads and verify all output bytes are in [1, 6].
        let test_inputs: &[&[u8]] = &[
            b"",
            b"hello",
            b"OnlyKey",
            b"the quick brown fox jumps over the lazy dog",
            &[0x00u8; 64],
            &[0xFFu8; 100],
        ];
        for input in test_inputs {
            let result = derive_challenge(input);
            for &byte in &result {
                assert!(
                    (1..=6).contains(&byte),
                    "challenge byte {} out of range [1,6] for input {:?}",
                    byte,
                    input
                );
            }
        }
    }
}
