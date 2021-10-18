use crate::jpki::card::Card;
use crate::nfc::apdu;

const DF_NAME: [u8; 10] = [0xD3, 0x92, 0xF0, 0x00, 0x26, 0x01, 0x00, 0x00, 0x00, 0x01];
const EF_SIGN: [u8; 2] = [0x00, 0x1A];
const EF_SIGN_PIN: [u8; 2] = [0x00, 0x1B];

pub enum CertType {
    Auth,
    AuthCA,
    Sign,
    SignCA,
}

impl CertType {
    pub fn into_efid(self) -> [u8; 2] {
        match self {
            Self::Auth => [0x00, 0x0A],
            Self::AuthCA => [0x00, 0x0B],
            Self::Sign => [0x00, 0x01],
            Self::SignCA => [0x00, 0x02],
        }
    }
}

pub struct JpkiAp<'a> {
    card: &'a Card,
}

impl<'a> JpkiAp<'a> {
    pub fn open(card: &'a Card) -> Result<Self, apdu::Error> {
        let ap = Self { card };

        ap.card.select_df(DF_NAME.into()).map(|_| ap)
    }

    pub fn read_certificate(&self, ty: CertType) -> Result<Vec<u8>, apdu::Error> {
        self.card
            .select_ef(ty.into_efid().into())
            .and_then(|_| self.card.read(None))
    }

    pub fn sign(&self, pin: Vec<u8>, digest: Vec<u8>) -> Result<Vec<u8>, apdu::Error> {
        self.verify_sign_pin(pin)
            .and_then(|_| self.card.select_ef(EF_SIGN.into()))
            .and_then(|_| self.card.sign(digest))
    }

    fn verify_sign_pin(&self, pin: Vec<u8>) -> Result<(), apdu::Error> {
        self.card
            .select_ef(EF_SIGN_PIN.into())
            .and_then(|_| self.card.verify(pin.into()))
    }
}
