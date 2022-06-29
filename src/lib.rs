//! A crate to communicate with JPKI card through an APDU delegate.

mod jpki;

#[cfg(feature = "digest")]
pub mod digest;

pub mod der;
pub mod nfc;

pub use apdu::core::Error;

pub use self::jpki::ap;
pub use self::jpki::Card;

use std::rc::Rc;

use apdu::core::Error as ApduError;

use crate::ap::JpkiAp;

/// High-level API to operate with authentication certificate and the key-pair
pub struct ClientForAuth<T, Ctx>
where
    T: nfc::Card<Ctx>,
    Ctx: Copy,
{
    #[allow(dead_code)]
    jpki_ap: Box<JpkiAp<T, Ctx>>,
}

impl<T, Ctx> ClientForAuth<T, Ctx>
where
    T: nfc::Card<Ctx>,
    Ctx: Copy,
{
    /// Initiates a client with the delegate.
    pub fn create(ctx: Ctx, delegate: Box<T>) -> Result<Self, ApduError> {
        Ok(Self {
            jpki_ap: Box::new(JpkiAp::open(ctx, Rc::new(Card::new(delegate)))?),
        })
    }

    /// Compute a signature for the message, unlocking the key with the PIN.
    #[cfg(feature = "digest")]
    pub fn sign(&self, ctx: Ctx, pin: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, ApduError> {
        self.jpki_ap.auth(ctx, pin, digest::calculate(message))
    }

    /// Verifies the signature for the message.
    #[cfg(feature = "digest")]
    pub fn verify(
        &self,
        ctx: Ctx,
        message: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, ApduError> {
        use crate::jpki::ap::jpki::CertType;

        Ok(digest::verify(
            self.jpki_ap.read_certificate(ctx, CertType::Auth, vec![])?,
            message,
            signature,
        ))
    }
}
