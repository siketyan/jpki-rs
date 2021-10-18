use crate::nfc;
use crate::nfc::apdu;
use crate::nfc::apdu::CLA_DEFAULT;

const SELECT_P1_DF: u8 = 0x04;
const SELECT_P1_EF: u8 = 0x02;
const SELECT_P2: u8 = 0x0C;

const VERIFY_P2: u8 = 0x80;

const SIGN_INS: u8 = 0x2A;
const SIGN_P1: u8 = 0x00;
const SIGN_P2: u8 = 0x80;

pub struct Card {
    delegate: Box<dyn nfc::Card>,
}

impl Card {
    pub fn new(delegate: Box<dyn nfc::Card>) -> Self {
        Self { delegate }
    }

    pub fn select_df(&self, name: Vec<u8>) -> Result<(), apdu::Error> {
        self.delegate
            .handle(apdu::Command::select_file(SELECT_P1_DF, SELECT_P2, name))
            .into_result()
            .map(|_| ())
    }

    pub fn select_ef(&self, id: Vec<u8>) -> Result<(), apdu::Error> {
        self.delegate
            .handle(apdu::Command::select_file(SELECT_P1_EF, SELECT_P2, id))
            .into_result()
            .map(|_| ())
    }

    pub fn read(&self, len: Option<u16>) -> Result<Vec<u8>, apdu::Error> {
        let mut pos: u16 = 0;
        let mut buf: Vec<u8> = Vec::new();

        while match len {
            Some(l) => pos < l,
            None => true,
        } {
            let [p1, p2] = pos.to_be_bytes();
            let le: u8 = match len {
                Some(l) => match l - pos > 0xFF {
                    true => 0,
                    _ => (l & 0xFF) as u8,
                },
                _ => 0,
            };

            let mut fragment = self
                .delegate
                .handle(apdu::Command::read_binary(p1, p2, le))
                .into_result()?;

            buf.append(&mut fragment);
            pos += fragment.len() as u16;

            if (fragment.len() as u8) < le {
                break;
            }
        }

        Ok(buf)
    }

    pub fn verify(&self, pin: Vec<u8>) -> Result<(), apdu::Error> {
        self.delegate
            .handle(apdu::Command::verify(VERIFY_P2, pin))
            .into_result()
            .map(|_| ())
    }

    pub fn sign(&self, digest: Vec<u8>) -> Result<Vec<u8>, apdu::Error> {
        self.delegate
            .handle(apdu::Command::new_with_payload_le(
                CLA_DEFAULT,
                SIGN_INS,
                SIGN_P1,
                SIGN_P2,
                0,
                digest,
            ))
            .into_result()
    }
}
