mod nfc;

use std::fs::File;
use std::io::Write;

use jpki::ap::jpki::CertType;
use jpki::nfc::apdu::{Command, Handler, Response};

use crate::nfc::{Context, Initiator, Target};

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("Error occurred on communicating with NFC device: {0}")]
    NFC(#[from] nfc::Error),

    #[error("The card returned an error: {0}")]
    APDU(#[from] jpki::nfc::apdu::Error),
}

type Result<T> = std::result::Result<T, Error>;

type Ctx = ();
struct NfcCard<'a> {
    target: Target<'a>,
}

impl<'a> Handler<Ctx> for NfcCard<'a> {
    fn handle(&self, _: Ctx, command: Command) -> Response {
        let tx = command.into_bytes();
        let rx = self.target.transmit(&tx).unwrap();

        Response::from_bytes(rx)
    }
}

impl<'a> jpki::nfc::Card<Ctx> for NfcCard<'a> {}

fn main() -> Result<()> {
    let ctx = Context::try_new().map_err(Error::NFC)?;
    let device = ctx.open().map_err(Error::NFC)?;
    let initiator = Initiator::try_from(device).map_err(Error::NFC)?;
    let target = initiator.select_dep_target().map_err(Error::NFC)?;

    let nfc_card = NfcCard { target };
    let card = jpki::Card::new(Box::new(nfc_card));
    let jpki_ap = jpki::ap::JpkiAp::open((), Box::new(card)).map_err(Error::APDU)?;

    let certificate = jpki_ap
        .read_certificate((), CertType::Auth, vec![])
        .unwrap();

    let mut file = File::create("foo.crt").unwrap();
    file.write_all(&certificate).unwrap();

    Ok(())
}
