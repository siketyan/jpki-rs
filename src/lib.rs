//! A crate to communicate with JPKI card through an APDU delegate.

mod jpki;

pub mod nfc;

pub use self::jpki::ap;
pub use self::jpki::Card;

use crate::ap::JpkiAp;
use crate::jpki::ap::jpki::CertType;
use crate::nfc::apdu;

/// High-level API to operate with authentication certificate and the key-pair
pub struct ClientForAuth<T, Ctx>
where
    T: nfc::Card<Ctx>,
    Ctx: Copy,
{
    jpki_ap: Box<JpkiAp<T, Ctx>>,
}

impl<T, Ctx> ClientForAuth<T, Ctx>
where
    T: nfc::Card<Ctx>,
    Ctx: Copy,
{
    /// Initiates a client with the delegate.
    pub fn create(ctx: Ctx, delegate: Box<T>) -> Result<Self, apdu::Error> {
        Ok(Self {
            jpki_ap: Box::new(JpkiAp::open(ctx, Box::new(Card::new(delegate)))?),
        })
    }

    /// Compute a signature for the message, unlocking the key with the PIN.
    pub fn sign(&self, ctx: Ctx, pin: Vec<u8>, message: Vec<u8>) -> Result<Vec<u8>, apdu::Error> {
        let digest = ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, &message);
        let oid = yasna::models::ObjectIdentifier::from_slice(&[1, 3, 14, 3, 2, 26]);
        let digest_info = yasna::construct_der(|w| {
            w.write_sequence(|w| {
                w.next().write_sequence(|w| {
                    w.next().write_oid(&oid);
                    w.next().write_null();
                });
                w.next().write_bytes(digest.as_ref());
            });
        });

        self.jpki_ap.auth(ctx, pin, digest_info)
    }

    /// Verifies the signature for the message.
    pub fn verify(
        &self,
        ctx: Ctx,
        message: Vec<u8>,
        signature: Vec<u8>,
    ) -> Result<bool, apdu::Error> {
        let certificate = self.jpki_ap.read_certificate(ctx, CertType::Auth, vec![])?;
        let x509 = x509_certificate::X509Certificate::from_der(&certificate).unwrap();
        let public_key = x509.public_key_data();
        let public_key = ring::signature::UnparsedPublicKey::new(
            &ring::signature::RSA_PKCS1_1024_8192_SHA1_FOR_LEGACY_USE_ONLY,
            public_key,
        );

        Ok(public_key.verify(&message, &signature).is_ok())
    }
}
