use crate::nfc::apdu;

pub trait Card: apdu::Handler {}
