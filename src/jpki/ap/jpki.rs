use crate::jpki::card::Card;
use crate::nfc;
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

    pub fn is_pin_required(&self) -> bool {
        match self {
            Self::Sign | Self::SignCA => true,
            _ => false,
        }
    }
}

pub struct JpkiAp<T, Ctx>
where
    T: nfc::Card<Ctx>,
    Ctx: Copy,
{
    card: Box<Card<T, Ctx>>,
}

impl<T, Ctx> JpkiAp<T, Ctx>
where
    T: nfc::Card<Ctx>,
    Ctx: Copy,
{
    pub fn open(ctx: Ctx, card: Box<Card<T, Ctx>>) -> Result<Self, apdu::Error> {
        let ap = Self { card };

        ap.card.select_df(ctx, DF_NAME.into()).map(|_| ap)
    }

    pub fn read_certificate(
        &self,
        ctx: Ctx,
        ty: CertType,
        pin: Vec<u8>,
    ) -> Result<Vec<u8>, apdu::Error> {
        if ty.is_pin_required() {
            self.verify_sign_pin(ctx, pin)?;
        }

        self.card
            .select_ef(ctx, ty.into_efid().into())
            .and_then(|_| self.read_certificate_size(ctx))
            .and_then(|size| self.card.read(ctx, Some(size)))
    }

    pub fn sign(&self, ctx: Ctx, pin: Vec<u8>, digest: Vec<u8>) -> Result<Vec<u8>, apdu::Error> {
        self.verify_sign_pin(ctx, pin)
            .and_then(|_| self.card.select_ef(ctx, EF_SIGN.into()))
            .and_then(|_| self.card.sign(ctx, digest))
    }

    fn verify_sign_pin(&self, ctx: Ctx, pin: Vec<u8>) -> Result<(), apdu::Error> {
        self.card
            .select_ef(ctx, EF_SIGN_PIN.into())
            .and_then(|_| self.card.verify(ctx, pin.into()))
    }

    fn read_certificate_size(&self, ctx: Ctx) -> Result<u16, apdu::Error> {
        let header = self.card.read(ctx, Some(7))?;
        let mut offset: usize = if header[0] & 0x1f == 0x1f { 2 } else { 1 };
        let head = header[offset] as u16;

        offset += 1;

        if head & 0x80 == 0 {
            Ok(head + (offset as u16))
        } else {
            let mut size = 0u16;
            for _ in 0..(head & 0x7f) {
                size <<= 8;
                size |= header[offset] as u16;
                offset += 1;
            }

            Ok(size + (offset as u16))
        }
    }
}
