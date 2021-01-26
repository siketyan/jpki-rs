use pkcs11::types::CK_ATTRIBUTE;
use pkcs11::Ctx;

use crate::pkcs::attribute::Attribute;
use crate::pkcs::object::Object;
use crate::pkcs::session::Session;
use crate::pkcs::Result;

#[derive(Debug)]
pub(crate) struct Finder<'a> {
    ctx: &'a Ctx,
    session: &'a Session<'a>,
}

impl<'a> Finder<'a> {
    pub(crate) fn new(ctx: &'a Ctx, session: &'a Session<'a>) -> Self {
        Self { ctx, session }
    }

    pub(crate) fn init(&self, attributes: &[Attribute]) -> Result<()> {
        self.ctx.find_objects_init(
            self.session.get_handle(),
            &attributes
                .iter()
                .map(|attr| attr.into())
                .collect::<Vec<CK_ATTRIBUTE>>(),
        )
    }

    pub(crate) fn find_objects(&self, max: u32) -> Result<Vec<Object>> {
        Ok(self
            .ctx
            .find_objects(self.session.get_handle(), max)?
            .iter()
            .map(|handle| Object::new(self.ctx, self.session, *handle))
            .collect())
    }

    pub(crate) fn close(&self) -> Result<()> {
        self.ctx.find_objects_final(self.session.get_handle())
    }
}
