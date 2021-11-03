use crate::nfc::apdu;

pub trait Card<Ctx>: apdu::Handler<Ctx> {}
