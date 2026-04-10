#![no_main]

use libfuzzer_sys::fuzz_target;
use onlykey_hid::{encode_large_message, HidFrame, Response};

fuzz_target!(|data: &[u8]| {
    // === Single 64-byte frame parsing ===
    // Pad short inputs to 64 bytes (tests both "bad magic" and partial-data paths).
    let mut buf = [0u8; 64];
    let n = data.len().min(64);
    buf[..n].copy_from_slice(&data[..n]);
    let frame = HidFrame::from_bytes(buf);
    let _ = frame.is_error_response();
    let _ = frame.device_state();
    let _ = frame.firmware_version();

    // === Multi-frame encoding (exercises MAX_PAYLOAD overflow path) ===
    // Use first two bytes as cmd and slot if available; rest is payload.
    if data.len() >= 2 {
        let cmd = data[0];
        let slot = data[1];
        let payload = &data[2..];
        // encode_large_message returns Err(PayloadTooLarge) when payload > 768.
        let _ = encode_large_message(cmd, slot, payload);
    }

    // === Response parsing (arbitrary bytes returned by device) ===
    let response = Response::new(data.to_vec());
    let _ = response.is_error();
    let _ = response.error_message();
    let _ = response.as_ecc32();
    let _ = response.as_ecc64();
    let _ = response.as_rsa2048();
    let _ = response.as_rsa4096();
    let _ = response.as_ed25519_sig();
    let _ = response.as_ecdsa_p256_sig();
    let _ = response.as_rsa_sig();
    let _ = response.as_shared_secret32();
});
