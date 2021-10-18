mod command;
mod handler;
mod ins;
mod response;

pub use command::Command;
pub use handler::Handler;
pub use response::Response;
use std::fmt::{Display, Formatter};

pub const CLA_DEFAULT: u8 = 0x00;

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
