use pkcs11::types::*;
use pkcs11::Ctx;

use crate::pkcs::attribute::{AttributeType, Attributes};
use crate::pkcs::session::Session;
use crate::pkcs::Result;

#[derive(Debug)]
pub(crate) struct Object<'a> {
    ctx: &'a Ctx,
    session: &'a Session<'a>,
    handle: CK_OBJECT_HANDLE,
}

impl<'a> Object<'a> {
    pub(crate) fn new(ctx: &'a Ctx, session: &'a Session<'a>, handle: CK_OBJECT_HANDLE) -> Self {
        Self {
            ctx,
            session,
            handle,
        }
    }

    pub(crate) fn get_handle(&self) -> CK_OBJECT_HANDLE {
        self.handle
    }

    pub(crate) fn get_attributes(&self, types: &[AttributeType]) -> Result<Attributes> {
        let session_handle = self.session.get_handle();
        let mut template = types
            .iter()
            .map(|ty| CK_ATTRIBUTE::new(ty.into()))
            .collect::<Vec<CK_ATTRIBUTE>>();

        self.ctx
            .get_attribute_value(session_handle, self.handle, &mut template)?;

        let mut buffers = template
            .iter()
            .map(|t| Vec::<u8>::with_capacity(t.ulValueLen as usize))
            .collect::<Vec<Vec<u8>>>();

        template
            .iter_mut()
            .zip(buffers.iter_mut())
            .for_each(|(a, b)| {
                a.pValue = b.as_mut_ptr() as CK_VOID_PTR;
            });

        self.ctx
            .get_attribute_value(session_handle, self.handle, &mut template)?;

        unsafe {
            template.iter().zip(buffers.iter_mut()).for_each(|(a, b)| {
                b.set_len(a.ulValueLen as usize);
            });
        }

        Ok((template, buffers).into())
    }
}
