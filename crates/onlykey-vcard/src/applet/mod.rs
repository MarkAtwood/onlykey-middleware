//! Applet trait and sub-module declarations.
//!
//! Each smartcard protocol (OpenPGP Card 3.4, PIV) is implemented as a type
//! that implements the [`Applet`] trait. The daemon loop calls
//! [`Applet::process`] for every C-APDU received from vpcd.

use std::time::Duration;

use onlykey_transport::challenge_ui::ChallengeDisplay;
use onlykey_transport::OnlyKeyDevice;

use crate::apdu::{Apdu, RApdu};
use crate::certstore::Certstore;

pub mod openpgp;
pub mod piv;

pub use openpgp::OpenPgpApplet;
pub use piv::PivApplet;

/// A smartcard applet served by onlykey-vcard over the vpcd TCP bridge.
///
/// An `Applet` is stateful per-connection: the daemon creates a fresh instance
/// for each accepted TCP connection. State includes the selected flag, PIN
/// verification status, response-chaining buffer, and the signature counter.
///
/// All `Applet` implementations must be `Send` so they can be moved into the
/// per-connection thread spawned by [`crate::serve_applet`].
pub trait Applet: Send {
    /// The AID that activates this applet (matched against the SELECT APDU data).
    fn aid(&self) -> &[u8];

    /// The ATR (Answer-To-Reset) bytes sent in response to a VpcdCtrl::Atr request.
    fn atr(&self) -> &[u8];

    /// Reset applet state (called on VpcdCtrl::Reset and after SELECT).
    fn reset(&mut self);

    /// Dispatch a C-APDU and return the R-APDU.
    ///
    /// - `apdu`: parsed command APDU
    /// - `device`: locked handle to the OnlyKey device (caller holds the mutex)
    /// - `display`: challenge display for signing/decryption operations
    /// - `timeout`: how long to wait for a button press
    /// - `certstore`: certificate store for GET DATA / PUT DATA
    fn process(
        &mut self,
        apdu: &Apdu,
        device: &OnlyKeyDevice,
        display: &dyn ChallengeDisplay,
        timeout: Duration,
        certstore: &mut Certstore,
    ) -> RApdu;
}
