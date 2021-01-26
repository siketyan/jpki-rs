use pkcs11::types::{CK_FLAGS, CK_NOTIFY, CK_SLOT_ID, CK_SLOT_INFO, CK_TOKEN_INFO, CK_VOID_PTR};
use pkcs11::Ctx;

use crate::pkcs::mechanism::Mechanism;
use crate::pkcs::session::Session;
use crate::pkcs::Result;

#[derive(Debug)]
pub(crate) struct OpenSessionCfg {
    flags: CK_FLAGS,
    application: Option<CK_VOID_PTR>,
    notify: CK_NOTIFY,
}

impl Default for OpenSessionCfg {
    fn default() -> Self {
        Self {
            flags: 0,
            application: None,
            notify: CK_NOTIFY::None,
        }
    }
}

#[derive(Debug)]
pub(crate) struct Slot<'a> {
    ctx: &'a Ctx,
    id: CK_SLOT_ID,
}

impl<'a> Slot<'a> {
    pub(crate) fn new(ctx: &'a Ctx, id: CK_SLOT_ID) -> Self {
        Self { ctx, id }
    }

    pub(crate) fn id(&self) -> CK_SLOT_ID {
        self.id
    }

    pub(crate) fn get_info(&self) -> Result<CK_SLOT_INFO> {
        self.ctx.get_slot_info(self.id)
    }

    pub(crate) fn get_token_info(&self) -> Result<CK_TOKEN_INFO> {
        self.ctx.get_token_info(self.id)
    }

    pub(crate) fn open_session(&self, cfg: OpenSessionCfg) -> Result<Session> {
        Ok(Session::new(
            self.ctx,
            self.ctx
                .open_session(self.id, cfg.flags, cfg.application, cfg.notify)?,
        ))
    }

    pub(crate) fn get_mechanisms(&self) -> Result<Vec<Mechanism>> {
        Ok(self
            .ctx
            .get_mechanism_list(self.id)?
            .into_iter()
            .map(|ty| Mechanism::new(self.ctx, self, ty))
            .collect())
    }

    pub(crate) fn close_all_sessions(&self) -> Result<()> {
        self.ctx.close_all_sessions(self.id)
    }
}
