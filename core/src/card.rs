use std::fmt::{Debug, Display, Formatter};
use std::marker::PhantomData;

use apdu::core::HandleError;
use apdu::{command, Command, Response};

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

#[derive(thiserror::Error)]
pub enum Error {
    /// APDU error returned by the card.
    Apdu(#[from] nfc::Error),

    /// Unexpected error occurred on the device.
    Device(Box<dyn Display>),
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        Display::fmt(self, f)
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Apdu(e) => Display::fmt(e, f),
            Error::Device(e) => e.fmt(f),
        }
    }
}

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
    pub fn select_df(&self, ctx: Ctx, name: Vec<u8>) -> Result<(), Error> {
        self.handle(ctx, command::select_file(SELECT_P1_DF, SELECT_P2, &name))
            .map(|_| ())
    }

    /// Selects a EF with their name.
    pub fn select_ef(&self, ctx: Ctx, id: Vec<u8>) -> Result<(), Error> {
        self.handle(ctx, command::select_file(SELECT_P1_EF, SELECT_P2, &id))
            .map(|_| ())
    }

    /// Reads binary from the selected file for `len` octets max.
    pub fn read(&self, ctx: Ctx, len: Option<u16>) -> Result<Vec<u8>, Error>
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
    pub fn verify(&self, ctx: Ctx, pin: Vec<u8>) -> Result<(), Error> {
        self.handle(ctx, command::verify(VERIFY_P2, &pin))
            .map(|_| ())
    }

    /// Computes a signature using the selected key.
    pub fn sign(&self, ctx: Ctx, digest: Vec<u8>) -> Result<Vec<u8>, Error> {
        self.handle(
            ctx,
            Command::new_with_payload_le(SIGN_CLA, SIGN_INS, SIGN_P1, SIGN_P2, 0, &digest),
        )
    }

    /// Selects a EF then verifies the pin using the EF.
    pub fn verify_pin(&self, ctx: Ctx, ef: [u8; 2], pin: Vec<u8>) -> Result<(), Error> {
        self.select_ef(ctx, ef.into())
            .and_then(|_| self.verify(ctx, pin))
    }

    pub fn pin_status(&self, ctx: Ctx, ef: [u8; 2]) -> Result<u8, Error> {
        match self
            .select_ef(ctx, ef.into())
            .and_then(|_| self.verify(ctx, vec![]))
        {
            Ok(_) => Ok(0),
            Err(Error::Apdu(nfc::Error::VerifyFailed(count))) => Ok(count),
            Err(e) => Err(e),
        }
    }

    /// Extracts the size of current file by reading DER-encoded ASN.1 header.
    pub fn read_der_size(&self, ctx: Ctx) -> Result<u16, Error> {
        let header = self.read(ctx, Some(7))?;

        Ok(entire_size_from_partial(&header) as u16)
    }

    fn handle<'a>(&'a self, ctx: Ctx, command: impl Into<Command<'a>>) -> Result<Vec<u8>, Error> {
        let command = command.into();
        let mut len = command.le.unwrap_or_default() as usize;
        let command_buf = Vec::from(command);

        let response = loop {
            let mut response = Vec::with_capacity(len);

            #[allow(clippy::uninit_vec)]
            unsafe {
                response.set_len(len);
            }

            let len = match self
                .delegate
                .handle_in_ctx(ctx, &command_buf, &mut response)
            {
                Ok(l) => l,
                Err(HandleError::NotEnoughBuffer(l)) => {
                    len = l;
                    continue;
                }
                Err(HandleError::Nfc(e)) => return Err(Error::Device(e)),
            };

            response.truncate(len);

            break response;
        };

        Result::from(Response::from(response.as_slice()))
            .map(|p| p.to_vec())
            .map_err(|e| nfc::Error::from(e).into())
    }
}
