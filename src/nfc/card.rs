use crate::nfc::apdu;

/// A delegate to communicate with the card outside
pub trait Card<Ctx>: apdu::Handler<Ctx> {}
