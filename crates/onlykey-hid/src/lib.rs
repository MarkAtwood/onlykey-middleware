//! OnlyKey USB HID wire protocol.
//!
// Deny unsafe patterns at the FFI / library boundary.
// Test modules are exempted: `#[cfg(test)]` blocks inherit these denials
// but individual test bodies may use allow(clippy::...) when justified.
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
//!
//! This crate is `no_std + alloc`. It implements:
//!
//! - **Frame encoding** -- 64-byte HID frames with the `0xFF*4` header (`packet`)
//! - **Multi-packet chunking** -- payloads > 57 bytes split across frames (`large_message`)
//! - **Challenge derivation** -- 3-button challenge from SHA-256 of payload (`challenge`)
//! - **Response parsing** -- typed accessors for public keys, signatures, secrets (`response`)
//! - **Command encoding** -- wire byte values for OnlyKey firmware commands (`command`)
//! - **Error types** -- `HidError` for slot/length errors (`error`)
//!
//! # no_std
//!
//! This crate is `no_std` with `alloc`. It compiles for `wasm32-unknown-unknown`
//! as a no_std guard. The `challenge` module is excluded from wasm32 builds
//! because wolfcrypt (which provides SHA-256) requires a C toolchain that
//! wasm32 does not provide.

#![no_std]

extern crate alloc;

pub mod command;
pub mod error;
pub mod large_message;
pub mod packet;
pub mod response;
pub mod types;

// Challenge derivation is excluded from wasm32 targets (wolfcrypt requires C).
#[cfg(not(target_arch = "wasm32"))]
pub mod challenge;

pub use command::{Command, DerivedKeySlot, KeySlot, KeyType};
pub use error::HidError;
pub use large_message::{encode_large_message, LargeMessageFrames, MAX_PAYLOAD};
pub use packet::{DeviceState, HidFrame};
pub use response::Response;
pub use types::{DecryptedBytes, PublicKeyBytes, SignatureBytes};

#[cfg(not(target_arch = "wasm32"))]
pub use challenge::derive_challenge;
