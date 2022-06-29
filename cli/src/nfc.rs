use std::ffi::{CStr, CString};
use std::marker::PhantomData;
use std::thread::sleep;
use std::time::Duration;

use pcsc::{Card, Protocols, Scope, ShareMode, MAX_BUFFER_SIZE};
use tracing::{debug, info};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Error occurred while communicating with PC/SC: {0}")]
    PcscError(#[from] pcsc::Error),

    #[error("Reader not found on PC/SC service")]
    ReaderNotFound,
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

pub struct Context<'a> {
    ctx: pcsc::Context,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> Context<'a> {
    pub fn try_new() -> Result<Self> {
        Ok(Self {
            ctx: pcsc::Context::establish(Scope::User).map_err(Error::PcscError)?,
            _lifetime: Default::default(),
        })
    }

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

    pub fn connect(&self, ctx: Context) -> Result<Target<'a>> {
        // Waits for touching card, polling for each seconds.
        debug!("Waiting for a card");

        loop {
            match ctx
                .ctx
                .connect(&self.reader, ShareMode::Shared, Protocols::ANY)
            {
                Ok(card) => {
                    debug!("Connected to your card");

                    return Ok(Target::new(card));
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

pub struct Target<'a> {
    card: Card,
    _lifetime: PhantomData<&'a ()>,
}

impl<'a> Target<'a> {
    fn new(card: Card) -> Self {
        Self {
            card,
            _lifetime: Default::default(),
        }
    }

    pub fn transmit(&self, tx: &[u8]) -> Result<Vec<u8>> {
        debug!("TX: {}", hex::encode(tx));

        let mut rx = [0u8; MAX_BUFFER_SIZE];
        let rx = self.card.transmit(tx, &mut rx).map_err(Error::PcscError)?;

        debug!("RX: {}", hex::encode(rx));

        Ok(Vec::from(rx))
    }
}
