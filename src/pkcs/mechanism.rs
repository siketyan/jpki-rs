use std::ptr;

use pkcs11::types::*;
use pkcs11::Ctx;

use crate::pkcs::object::Object;
use crate::pkcs::slot::Slot;
use crate::pkcs::Result;

pub(crate) struct Mechanism<'a> {
    ctx: &'a Ctx,
    slot: &'a Slot<'a>,
    ty: CK_MECHANISM_TYPE,
}

impl<'a> Into<CK_MECHANISM> for &Mechanism<'a> {
    fn into(self) -> CK_MECHANISM {
        CK_MECHANISM {
            mechanism: self.ty,
            pParameter: ptr::null_mut(),
            ulParameterLen: 0,
        }
    }
}

impl<'a> Mechanism<'a> {
    pub(crate) fn new(ctx: &'a Ctx, slot: &'a Slot<'a>, ty: CK_MECHANISM_TYPE) -> Self {
        Self { ctx, slot, ty }
    }

    pub(crate) fn get_info(&self) -> Result<CK_MECHANISM_INFO> {
        self.ctx.get_mechanism_info(self.slot.id(), self.ty)
    }
}
