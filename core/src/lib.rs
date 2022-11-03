//! A crate to communicate with JPKI card through an APDU delegate.

extern crate core;

#[cfg(feature = "pcsc")]
pub mod pcsc;

pub mod ap;
pub mod card;
pub mod der;
pub mod nfc;

pub use card::Card;
