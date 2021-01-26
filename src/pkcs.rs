pub(crate) mod attribute;
pub(crate) mod finder;
pub(crate) mod mechanism;
pub(crate) mod object;
pub(crate) mod session;
pub(crate) mod slot;

use std::path::Path;

use pkcs11::types::CK_INFO;
use pkcs11::Ctx;

use crate::pkcs::slot::Slot;

pub(crate) type Error = pkcs11::errors::Error;
pub(crate) type Result<T> = std::result::Result<T, Error>;

pub(crate) struct Pkcs11 {
    ctx: Ctx,
}

impl Pkcs11 {
    pub(crate) fn open<P>(path: P) -> Result<Self>
    where
        P: AsRef<Path>,
    {
        Ok(Self {
            ctx: Ctx::new_and_initialize(path)?,
        })
    }

    pub(crate) fn get_info(&self) -> Result<CK_INFO> {
        self.ctx.get_info()
    }

    pub(crate) fn get_slots(&self, only_present: bool) -> Result<Vec<Slot>> {
        Ok(self
            .ctx
            .get_slot_list(only_present)?
            .iter()
            .map(|id| Slot::new(&self.ctx, *id))
            .collect())
    }

    pub(crate) fn close(&mut self) -> Result<()> {
        self.ctx.finalize()
    }
}
