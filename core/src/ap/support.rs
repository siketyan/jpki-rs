use std::rc::Rc;

use crate::ap::open;
use crate::{nfc, Card};

const DF_NAME: [u8; 10] = [0xD3, 0x92, 0x10, 0x00, 0x31, 0x00, 0x01, 0x01, 0x04, 0x08];
const EF_MY_NUMBER: [u8; 2] = [0x00, 0x01];
const EF_ATTRIBUTES: [u8; 2] = [0x00, 0x02];
const EF_PIN: [u8; 2] = [0x00, 0x11];

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub enum Sex {
    Male,
    Female,
    NotApplicable,
    Unknown,
}

#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Deserialize, serde::Serialize))]
pub struct Attributes {
    #[cfg_attr(feature = "serde", serde(skip_serializing))]
    _header: Vec<u8>,
    pub name: String,
    pub address: String,
    pub date_of_birth: String,
    pub sex: Sex,
}

impl<'a> From<&'a [u8]> for Attributes {
    fn from(buf: &'a [u8]) -> Self {
        crate::der::Reader::new(buf).in_sequence(|reader| Self {
            _header: Vec::from(reader.read_auto()),
            name: reader.read_string(),
            address: reader.read_string(),
            date_or_birth: reader.read_string(),
            sex: {
                use Sex::*;

                match reader.read_str().to_owned().as_ref() {
                    "1" => Male,
                    "2" => Female,
                    "9" => NotApplicable,
                    _ => Unknown,
                }
            },
        })
    }
}

pub struct SupportAp<T, Ctx>
where
    T: nfc::HandlerInCtx<Ctx>,
    Ctx: Copy,
{
    card: Rc<Card<T, Ctx>>,
}

impl<T, Ctx> SupportAp<T, Ctx>
where
    T: nfc::HandlerInCtx<Ctx>,
    Ctx: Copy,
{
    open!(T, Ctx, DF_NAME);

    /// Reads the "My Number" from the card as DER-encoded ASN.1 data.
    pub fn read_my_number_raw(&self, ctx: Ctx, pin: Vec<u8>) -> Result<Vec<u8>, nfc::Error> {
        self.verify_pin(ctx, pin)
            .and_then(|_| self.card.select_ef(ctx, EF_MY_NUMBER.into()))
            .and_then(|_| self.card.read(ctx, Some(17)))
    }

    /// Reads the "My Number" from the card as a string.
    pub fn read_my_number(&self, ctx: Ctx, pin: Vec<u8>) -> Result<String, nfc::Error> {
        self.read_my_number_raw(ctx, pin).map(|buf| {
            String::from_utf8_lossy(crate::der::Reader::new(&buf).read_auto()).to_string()
        })
    }

    /// Reads the text attributes from the card as DER-encoded ASN.1 data.
    pub fn read_attributes_raw(&self, ctx: Ctx, pin: Vec<u8>) -> Result<Vec<u8>, nfc::Error> {
        self.verify_pin(ctx, pin)
            .and_then(|_| self.card.select_ef(ctx, EF_ATTRIBUTES.into()))
            .and_then(|_| self.card.read_der_size(ctx))
            .and_then(|size| self.card.read(ctx, Some(size)))
    }

    /// Reads the text attributes from the card as decoded data.
    pub fn read_attributes(&self, ctx: Ctx, pin: Vec<u8>) -> Result<Attributes, nfc::Error> {
        self.read_attributes_raw(ctx, pin)
            .map(|attrs| Attributes::from(attrs.as_slice()))
    }

    /// Gets the status of PIN.
    pub fn pin_status(&self, ctx: Ctx) -> Result<u8, nfc::Error> {
        self.card.pin_status(ctx, EF_PIN)
    }

    fn verify_pin(&self, ctx: Ctx, pin: Vec<u8>) -> Result<(), nfc::Error> {
        self.card.verify_pin(ctx, EF_PIN, pin)
    }
}
