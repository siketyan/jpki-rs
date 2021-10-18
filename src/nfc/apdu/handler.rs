use crate::nfc::apdu::{Command, Response};

pub trait Handler {
    fn handle(&self, command: Command) -> Response;
}
