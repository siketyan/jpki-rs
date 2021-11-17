//! Implementation of APDU (Application Protocol Data Unit) commands and responses

mod command;
mod handler;
mod ins;
mod response;

pub use command::Command;
pub use handler::Handler;
pub use response::Response;

use std::fmt::{Display, Formatter};

/// Default CLA (class) value of commands
pub const CLA_DEFAULT: u8 = 0x00;

/// An error that was returned from the card or reader
#[derive(Debug)]
pub struct Error {
    sw1: u8,
    sw2: u8,
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "The APDU reader returned an error ({:#X}, {:#X}).",
            self.sw1, self.sw2
        )
    }
}

impl std::error::Error for Error {}
