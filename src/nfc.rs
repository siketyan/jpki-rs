//! Communicating with the card using NFC technology

pub use apdu::Error;
pub use apdu::{Command, Response};

/// An handler to handle an APDU command and receive a response
pub trait Handler<Ctx> {
    /// Handles the APDU command.
    /// Implementations must transmit the command to the card through a reader,
    /// then receive the response from them.
    fn handle(&self, ctx: Ctx, command: Command) -> Response;
}

/// A delegate to communicate with the card outside
pub trait Card<Ctx>: Handler<Ctx> {}
