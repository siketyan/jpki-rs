use pkcs11::types::*;
use pkcs11::Ctx;

use crate::pkcs::finder::Finder;
use crate::pkcs::mechanism::Mechanism;
use crate::pkcs::object::Object;
use crate::pkcs::Result;

#[derive(Debug)]
pub(crate) enum UserType {
    So,
    User,
    ContextSpecific,
}

impl Into<CK_USER_TYPE> for UserType {
    fn into(self) -> CK_USER_TYPE {
        match self {
            Self::So => CKU_SO,
            Self::User => CKU_USER,
            Self::ContextSpecific => CKU_CONTEXT_SPECIFIC,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Session<'a> {
    ctx: &'a Ctx,
    handle: CK_SESSION_HANDLE,
}

impl<'a> Session<'a> {
    pub(crate) fn new(ctx: &'a Ctx, handle: CK_SESSION_HANDLE) -> Self {
        Self { ctx, handle }
    }

    pub(crate) fn get_handle(&self) -> CK_SESSION_HANDLE {
        self.handle
    }

    pub(crate) fn get_info(&self) -> Result<CK_SESSION_INFO> {
        self.ctx.get_session_info(self.handle)
    }

    pub(crate) fn login(&self, user_type: UserType, pin: Option<&str>) -> Result<()> {
        self.ctx.login(self.handle, user_type.into(), pin)
    }

    pub(crate) fn finder(&self) -> Finder {
        Finder::new(self.ctx, self)
    }

    pub(crate) fn sign(
        &self,
        mechanism: &'a Mechanism,
        key: &'a Object,
        digest: &[CK_BYTE],
    ) -> Result<Vec<CK_BYTE>> {
        self.ctx
            .sign_init(self.handle, &mechanism.into(), key.get_handle())?;

        self.ctx.sign(self.handle, digest)
    }

    pub(crate) fn digest(self, mechanism: &'a Mechanism, data: &[CK_BYTE]) -> Result<Vec<CK_BYTE>> {
        self.ctx.digest_init(self.handle, &mechanism.into())?;
        self.ctx.digest_update(self.handle, data)?;
        self.ctx.digest_final(self.handle)
    }

    pub(crate) fn logout(&self) -> Result<()> {
        self.ctx.logout(self.handle)
    }

    pub(crate) fn close(&self) -> Result<()> {
        self.ctx.close_session(self.handle)
    }
}
