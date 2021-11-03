use crate::nfc::apdu::{Command, Response};

pub trait Handler<Ctx> {
    fn handle(&self, ctx: Ctx, command: Command) -> Response;
}
