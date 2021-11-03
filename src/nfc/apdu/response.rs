use crate::nfc::apdu::Error;

pub struct Response {
    payload: Vec<u8>,
    trailer: (u8, u8),
}

impl Response {
    pub fn new() -> Self {
        Self {
            payload: vec![],
            trailer: (0, 0),
        }
    }

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

    pub fn is_ok(&self) -> bool {
        match self.trailer {
            (0x90, 0x00) | (0x91, 0x00) => true,
            _ => false,
        }
    }

    pub fn into_result(self) -> Result<Vec<u8>, Error> {
        let is_ok = self.is_ok();
        let Self { payload, trailer } = self;

        match is_ok {
            true => Result::Ok(payload),
            _ => Result::Err(trailer.into()),
        }
    }
}

impl Into<Error> for (u8, u8) {
    fn into(self) -> Error {
        let (sw1, sw2) = self;

        Error { sw1, sw2 }
    }
}
