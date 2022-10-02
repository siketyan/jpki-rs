//! PC/SC support for jpki library.
//! Can be enabled by turning `pcsc` feature on.
//!
//! ## What is PC/SC?
//! PC/SC (Personal Computer/Smart Card) is an abstraction layer for communicating with Smart Cards
//! from Windows. Using this layer, applications can connect to any devices that supports PC/SC,
//! without depending on their driver implementation. Windows and macOS supports PC/SC by themselves,
//! Linux also supports by installing pcsc-lite shared library.
//!
//! ## Supported platform
//! Platforms that supports PC/SC are limited because they are subjected to use devices on PCs.
//! Linux, Windows and macOS are supported by pcsc-rust, backend of this implementation.
//! Refer the documentation of pcsc-rust for details:
//! <https://github.com/bluetech/pcsc-rust>
//!
//! ## Usage
//! ```rust,no_run
//! use std::rc::Rc;
//!
//! use jpki::Card;
//! use jpki::ap::CryptoAp;
//! use jpki::pcsc::Context;
//!
//! let ctx = Context::try_new().unwrap();
//! let device = ctx.open().unwrap();
//! let pcsc_card = device.connect(ctx).unwrap();
//!
//! let card = Rc::new(Card::new(Box::new(pcsc_card)));
//! let jpki_ap = CryptoAp::open((), Rc::clone(&card)).unwrap();
//! ```

use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::thread::sleep;
use std::time::Duration;

use pcsc::{Card, Protocols, Scope, ShareMode, MAX_BUFFER_SIZE};

#[cfg(feature = "tracing")]
use tracing::{debug, info};

use crate::nfc::{Command, HandlerInCtx, Response};

#[cfg(not(feature = "tracing"))]
macro_rules! debug {
    ($($t: tt)*) => {};
}

#[cfg(not(feature = "tracing"))]
macro_rules! info {
    ($($t: tt)*) => {};
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Error occurred while communicating with PC/SC: {0}")]
    PcscError(#[from] pcsc::Error),

    #[error("Reader not found on PC/SC service")]
    ReaderNotFound,
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

/// PC/SC context.
pub struct Context<'a> {
    ctx: pcsc::Context,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> Context<'a> {
    /// Creates a PC/SC context in user scope.
    pub fn try_new() -> Result<Self> {
        Ok(Self {
            ctx: pcsc::Context::establish(Scope::User).map_err(Error::PcscError)?,
            _lifetime: Default::default(),
        })
    }

    /// Finds a PC/SC device, then opens a connection to them.
    pub fn open<'b>(&self) -> Result<Device<'b>> {
        let mut buf = [0u8; 2048];

        Ok(Device::new(
            self.ctx
                .list_readers(&mut buf)
                .map_err(Error::PcscError)?
                .next()
                .ok_or(Error::ReaderNotFound)?,
        ))
    }
}

/// PC/SC device handle.
pub struct Device<'a> {
    reader: Box<CString>,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> Device<'a> {
    fn new(reader: &CStr) -> Self {
        debug!("Using device: {}", reader.to_str().unwrap_or_default());

        Self {
            reader: Box::new(reader.to_owned()),
            _lifetime: Default::default(),
        }
    }

    /// Connects to the card inserted to the device after waiting them.
    pub fn connect(&self, ctx: Context) -> Result<PcscCard<'a>> {
        // Waits for touching card, polling for each seconds.
        debug!("Waiting for a card");

        loop {
            match ctx
                .ctx
                .connect(&self.reader, ShareMode::Shared, Protocols::ANY)
            {
                Ok(card) => {
                    debug!("Connected to your card");

                    return Ok(PcscCard::new(card));
                }
                Err(e) => match e {
                    pcsc::Error::NoSmartcard => {
                        info!("Still waiting for your card...");
                        sleep(Duration::from_secs(1));

                        continue;
                    }
                    _ => return Err(Error::PcscError(e)),
                },
            }
        }
    }
}

/// A card to be communicated through PC/SC.
pub struct PcscCard<'a> {
    card: Card,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> PcscCard<'a> {
    fn new(card: Card) -> Self {
        Self {
            card,
            _lifetime: Default::default(),
        }
    }

    /// Transmits an APDU command to the card, then receives a response from them.
    pub fn transmit(&self, tx: &[u8]) -> Result<Vec<u8>> {
        debug!("TX: {}", hex::encode(tx));

        let mut rx = [0u8; MAX_BUFFER_SIZE];
        let rx = self.card.transmit(tx, &mut rx).map_err(Error::PcscError)?;

        debug!("RX: {}", hex::encode(rx));

        Ok(Vec::from(rx))
    }
}

type Ctx = ();

impl<'a> HandlerInCtx<Ctx> for PcscCard<'a> {
    fn handle_in_ctx(&self, _: Ctx, command: Command) -> Response {
        let tx = Vec::from(command);
        let rx = self.transmit(&tx).unwrap();

        rx.into()
    }
}
