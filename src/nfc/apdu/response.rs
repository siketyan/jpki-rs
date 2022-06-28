use crate::nfc::apdu::Error;

/// An response that was received from the card
#[derive(Default)]
pub struct Response {
    payload: Vec<u8>,
    trailer: (u8, u8),
}

impl Response {
    /// Creates an empty response.
    pub fn new() -> Self {
        Default::default()
    }

    /// Parses a response from the octets.
    pub fn from_bytes(mut bytes: Vec<u8>) -> Self {
        let sw2 = bytes.pop();
        let sw1 = bytes.pop();

        Self {
            payload: bytes,
            trailer: match (sw1, sw2) {
                (Some(a), Some(b)) => (a, b),
                _ => (0x00, 0x00),
            },
        }
    }

    /// Determines whether the response indicates success or not.
    pub fn is_ok(&self) -> bool {
        matches!(self.trailer, (0x90, 0x00) | (0x91, 0x00))
    }

    /// Converts the response to a result of octets.
    pub fn into_result(self) -> Result<Vec<u8>, Error> {
        let is_ok = self.is_ok();
        let Self { payload, trailer } = self;

        match is_ok {
            true => Result::Ok(payload),
            _ => Result::Err(trailer.into()),
        }
    }
}

impl From<(u8, u8)> for Error {
    fn from((sw1, sw2): (u8, u8)) -> Self {
        Error { sw1, sw2 }
    }
}
