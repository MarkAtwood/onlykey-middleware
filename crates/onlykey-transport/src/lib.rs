//! OnlyKey transport layer.
//!
//! This crate bridges `onlykey-hid` (pure protocol) with the OS:
//! - HID device enumeration and connection via `hidapi`
//! - Blocking sign/decrypt/HMAC operations with challenge display
//! - Typed public key construction validated by wolfcrypt
//! - Configuration loading from XDG paths and environment variables
//!
//! # Quick start
//!
//! ```no_run
//! use onlykey_transport::{Config, OnlyKeyDevice, challenge_ui::TtyDisplay};
//!
//! let config = Config::load().expect("config error");
//! let device = OnlyKeyDevice::open(config).expect("no OnlyKey found");
//! println!("Connected: firmware {}", device.firmware_version);
//! ```
#![deny(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

pub mod challenge_ui;
pub mod config;
pub mod device;
pub mod error;
pub mod io;
pub mod ops;
pub mod types;

pub use config::Config;
pub use device::OnlyKeyDevice;
pub use error::TransportError;
pub use ops::detect_ecc_algorithm;
pub use ops::FALLBACK_PSEUDO_SERIAL;
pub use types::{
    DecryptOp, Decrypted, EccAlgorithm, PublicKey, SignOp, Signature, RSA_PUBLIC_EXPONENT,
};

// Re-export HID types needed by dependent crates.
pub use onlykey_hid::{DeviceState, KeySlot};
