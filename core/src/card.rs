use std::marker::PhantomData;

use apdu::{command, Command};

use crate::der::entire_size_from_partial;
use crate::nfc;

const SELECT_P1_DF: u8 = 0x04;
const SELECT_P1_EF: u8 = 0x02;
const SELECT_P2: u8 = 0x0C;

const VERIFY_P2: u8 = 0x80;

const SIGN_CLA: u8 = 0x80;
const SIGN_INS: u8 = 0x2A;
const SIGN_P1: u8 = 0x00;
const SIGN_P2: u8 = 0x80;

/// An adapter to communicate with the card through the delegate
pub struct Card<T, Ctx>
where
    T: nfc::HandlerInCtx<Ctx>,
    Ctx: Copy,
{
    delegate: Box<T>,
    _ctx: PhantomData<Ctx>,
}

impl<T, Ctx> Card<T, Ctx>
where
    T: nfc::HandlerInCtx<Ctx>,
    Ctx: Copy,
{
    /// Initiates an adapter with the delegate.
    pub fn new(delegate: Box<T>) -> Self {
        Self {
            delegate,
            _ctx: PhantomData,
        }
    }

    /// Selects a DF with their name.
    pub fn select_df(&self, ctx: Ctx, name: Vec<u8>) -> Result<(), nfc::Error> {
        self.handle(ctx, command::select_file(SELECT_P1_DF, SELECT_P2, name))
            .map(|_| ())
    }

    /// Selects a EF with their name.
    pub fn select_ef(&self, ctx: Ctx, id: Vec<u8>) -> Result<(), nfc::Error> {
        self.handle(ctx, command::select_file(SELECT_P1_EF, SELECT_P2, id))
            .map(|_| ())
    }

    /// Reads binary from the selected file for `len` octets max.
    pub fn read(&self, ctx: Ctx, len: Option<u16>) -> Result<Vec<u8>, nfc::Error>
    where
        Ctx: Copy,
    {
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

            let mut fragment = self.handle(ctx, command::read_binary(p1, p2, le))?;
            let length = fragment.len();

            buf.append(&mut fragment);
            pos += length as u16;

            if (length as u8) < le {
                break;
            }
        }

        Ok(buf)
    }

    /// Verifies the PIN.
    pub fn verify(&self, ctx: Ctx, pin: Vec<u8>) -> Result<(), nfc::Error> {
        self.handle(ctx, command::verify(VERIFY_P2, pin))
            .map(|_| ())
    }

    /// Computes a signature using the selected key.
    pub fn sign(&self, ctx: Ctx, digest: Vec<u8>) -> Result<Vec<u8>, nfc::Error> {
        self.handle(
            ctx,
            Command::new_with_payload_le(SIGN_CLA, SIGN_INS, SIGN_P1, SIGN_P2, 0, digest),
        )
    }

    /// Selects a EF then verifies the pin using the EF.
    pub fn verify_pin(&self, ctx: Ctx, ef: [u8; 2], pin: Vec<u8>) -> Result<(), nfc::Error> {
        self.select_ef(ctx, ef.into())
            .and_then(|_| self.verify(ctx, pin))
    }

    /// Extracts the size of current file by reading DER-encoded ASN.1 header.
    pub fn read_der_size(&self, ctx: Ctx) -> Result<u16, nfc::Error> {
        let header = self.read(ctx, Some(7))?;

        Ok(entire_size_from_partial(&header) as u16)
    }

    fn handle(&self, ctx: Ctx, command: impl Into<Command>) -> Result<Vec<u8>, nfc::Error> {
        Result::from(self.delegate.handle_in_ctx(ctx, command.into())).map_err(|e| e.into())
    }
}
