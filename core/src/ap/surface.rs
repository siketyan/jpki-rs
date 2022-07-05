//! Card Surface AP: Application to provide information indicated on the card surface.

use std::rc::Rc;

use crate::{nfc, Card};

const DF_NAME: [u8; 10] = [0xD3, 0x92, 0x10, 0x00, 0x31, 0x00, 0x01, 0x01, 0x04, 0x02];
const EF_ID: [u8; 2] = [0x00, 0x02];
const EF_PIN_A: [u8; 2] = [0x00, 0x13];
const EF_PIN_B: [u8; 2] = [0x00, 0x12];

pub enum Pin {
    /// My Number (12 digits).
    /// Information from both front and back is available.
    A(Vec<u8>),

    /// DoB in 'YYYYMMDD' format + Expiry date in 'YYYY' format + PIN (4 digits).
    /// Information from only front is available.
    B(Vec<u8>),
}

pub struct SurfaceAp<T, Ctx>
where
    T: nfc::HandlerInCtx<Ctx>,
    Ctx: Copy,
{
    card: Rc<Card<T, Ctx>>,
}

impl<T, Ctx> SurfaceAp<T, Ctx>
where
    T: nfc::HandlerInCtx<Ctx>,
    Ctx: Copy,
{
    /// Opens the AP in the card by selecting the DF.
    pub fn open(ctx: Ctx, card: Rc<Card<T, Ctx>>) -> Result<Self, nfc::Error> {
        let ap = Self { card };

        ap.card.select_df(ctx, DF_NAME.into()).map(|_| ap)
    }

    /// Reads the surface information as DER-encoded ASN.1 data.
    pub fn read_surface(&self, ctx: Ctx, pin: Pin) -> Result<Vec<u8>, nfc::Error> {
        match pin {
            Pin::A(pin) => self.verify_pin_a(ctx, pin),
            Pin::B(pin) => self.verify_pin_b(ctx, pin),
        }
        .and_then(|_| self.card.select_ef(ctx, EF_ID.into()))
        .and_then(|_| self.card.read_der_size(ctx))
        .and_then(|size| self.card.read(ctx, Some(size)))
    }

    fn verify_pin_a(&self, ctx: Ctx, pin: Vec<u8>) -> Result<(), nfc::Error> {
        self.card.verify_pin(ctx, EF_PIN_A, pin)
    }

    fn verify_pin_b(&self, ctx: Ctx, pin: Vec<u8>) -> Result<(), nfc::Error> {
        self.card.verify_pin(ctx, EF_PIN_B, pin)
    }
}
