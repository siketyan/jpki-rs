//! JPKI AP

use std::rc::Rc;

use crate::jpki::card::Card;
use crate::nfc;

const DF_NAME: [u8; 10] = [0xD3, 0x92, 0xF0, 0x00, 0x26, 0x01, 0x00, 0x00, 0x00, 0x01];
const EF_AUTH: [u8; 2] = [0x00, 0x17];
const EF_AUTH_PIN: [u8; 2] = [0x00, 0x18];
const EF_SIGN: [u8; 2] = [0x00, 0x1A];
const EF_SIGN_PIN: [u8; 2] = [0x00, 0x1B];

/// Type of the certificate to fetch
#[derive(Copy, Clone)]
pub enum CertType {
    /// Certificate for authentication
    Auth,

    /// Certificate of CA (Certificate Authority) that issued the authentication certificate
    AuthCA,

    /// Certificate for signing documents
    Sign,

    /// Certificate of CA (Certificate Authority) that issued the signing certificate
    SignCA,
}

impl CertType {
    /// Converts the variant into the identifier to select a EF
    /// that corresponds with the selected certificate.
    pub fn into_efid(self) -> [u8; 2] {
        match self {
            Self::Auth => [0x00, 0x0A],
            Self::AuthCA => [0x00, 0x0B],
            Self::Sign => [0x00, 0x01],
            Self::SignCA => [0x00, 0x02],
        }
    }

    /// Determines whether it is needed for fetching the certificate to unlock it with a PIN.
    pub fn is_pin_required(&self) -> bool {
        matches!(self, Self::Sign)
    }
}

/// An AP to sign or verify messages using a key-pair issued by JPKI
pub struct JpkiAp<T, Ctx>
where
    T: nfc::Card<Ctx>,
    Ctx: Copy,
{
    card: Rc<Card<T, Ctx>>,
}

impl<T, Ctx> JpkiAp<T, Ctx>
where
    T: nfc::Card<Ctx>,
    Ctx: Copy,
{
    /// Opens the AP in the card by selecting the DF.
    pub fn open(ctx: Ctx, card: Rc<Card<T, Ctx>>) -> Result<Self, nfc::Error> {
        let ap = Self { card };

        ap.card.select_df(ctx, DF_NAME.into()).map(|_| ap)
    }

    /// Reads a certificate of the type, unlocking with the PIN if required.
    pub fn read_certificate(
        &self,
        ctx: Ctx,
        ty: CertType,
        pin: Vec<u8>,
    ) -> Result<Vec<u8>, nfc::Error> {
        if ty.is_pin_required() {
            self.verify_sign_pin(ctx, pin)?;
        }

        self.card
            .select_ef(ctx, ty.into_efid().into())
            .and_then(|_| self.card.read_der_size(ctx))
            .and_then(|size| self.card.read(ctx, Some(size)))
    }

    /// Computes a signature using the key-pair for authentication.
    pub fn auth(&self, ctx: Ctx, pin: Vec<u8>, digest: Vec<u8>) -> Result<Vec<u8>, nfc::Error> {
        self.verify_auth_pin(ctx, pin)
            .and_then(|_| self.card.select_ef(ctx, EF_AUTH.into()))
            .and_then(|_| self.card.sign(ctx, digest))
    }

    /// Computes a signature using the key-pair for signing.
    pub fn sign(&self, ctx: Ctx, pin: Vec<u8>, digest: Vec<u8>) -> Result<Vec<u8>, nfc::Error> {
        self.verify_sign_pin(ctx, pin)
            .and_then(|_| self.card.select_ef(ctx, EF_SIGN.into()))
            .and_then(|_| self.card.sign(ctx, digest))
    }

    fn verify_auth_pin(&self, ctx: Ctx, pin: Vec<u8>) -> Result<(), nfc::Error> {
        self.card.verify_pin(ctx, EF_AUTH_PIN, pin)
    }

    fn verify_sign_pin(&self, ctx: Ctx, pin: Vec<u8>) -> Result<(), nfc::Error> {
        self.card.verify_pin(ctx, EF_SIGN_PIN, pin)
    }
}
