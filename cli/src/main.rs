mod nfc;

use std::fs::File;
use std::io::{stdin, stdout, Read, Write};
use std::path::PathBuf;
use std::process::exit;

use clap::{ArgEnum, Parser, Subcommand};
use dialoguer::Password;
use jpki::nfc::apdu::{Command, Handler, Response};

use crate::nfc::{Context, Initiator, Target};

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("I/O error occurred: {0}")]
    IO(#[from] std::io::Error),

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

#[derive(ArgEnum, Copy, Clone)]
enum CertType {
    Sign,
    SignCA,
    Auth,
    AuthCA,
}

impl Into<jpki::ap::jpki::CertType> for CertType {
    fn into(self) -> jpki::ap::jpki::CertType {
        match self {
            Self::Sign => jpki::ap::jpki::CertType::Sign,
            Self::SignCA => jpki::ap::jpki::CertType::SignCA,
            Self::Auth => jpki::ap::jpki::CertType::Auth,
            Self::AuthCA => jpki::ap::jpki::CertType::AuthCA,
        }
    }
}

#[derive(Subcommand)]
enum SubCommand {
    /// Reads a certificate in the JPKI card.
    ReadCertificate {
        /// Type of the certificate to read.
        #[clap(arg_enum)]
        ty: CertType,
    },
    /// Writes a signature of the document.
    Sign {
        /// Path to write the signature.
        signature_path: PathBuf,
    },
    /// Verifies the signed digest.
    Verify {
        /// Path to the certificate to verify as.
        certificate_path: PathBuf,

        /// Path to signature to verify for.
        signature_path: PathBuf,
    },
}

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: SubCommand,
}

fn prompt_password() -> Result<Vec<u8>> {
    Password::new()
        .with_prompt("PIN")
        .interact()
        .map(|p| p.into_bytes())
        .map_err(Error::IO)
}

fn read_all<R: Read>(mut r: R) -> Result<Vec<u8>> {
    let mut buffer: Vec<u8> = vec![];

    r.read_to_end(&mut buffer).map_err(Error::IO)?;

    Ok(buffer)
}

fn main() -> Result<()> {
    let cli: Cli = Cli::parse();

    let ctx = Context::try_new().map_err(Error::NFC)?;
    let device = ctx.open().map_err(Error::NFC)?;
    let initiator = Initiator::try_from(device).map_err(Error::NFC)?;
    let target = initiator.select_dep_target().map_err(Error::NFC)?;

    let nfc_card = NfcCard { target };
    let card = jpki::Card::new(Box::new(nfc_card));
    let jpki_ap = jpki::ap::JpkiAp::open((), Box::new(card)).map_err(Error::APDU)?;
    match &cli.command {
        SubCommand::ReadCertificate { ty } => {
            let ty: jpki::ap::jpki::CertType = (*ty).into();
            let pin = if ty.is_pin_required() {
                prompt_password()?
            } else {
                vec![]
            };

            let certificate = jpki_ap.read_certificate((), ty, pin).map_err(Error::APDU)?;

            stdout().write_all(&certificate).map_err(Error::IO)?;
        }
        SubCommand::Sign { signature_path } => {
            let signature = jpki_ap.sign(
                (),
                prompt_password()?,
                jpki::digest::calculate(read_all(stdin())?),
            )?;

            let mut signature_file = File::create(signature_path).map_err(Error::IO)?;
            signature_file.write_all(&signature)?;
        }
        SubCommand::Verify {
            certificate_path,
            signature_path,
        } => {
            let certificate = read_all(File::open(certificate_path).map_err(Error::IO)?)?;
            let signature = read_all(File::open(signature_path).map_err(Error::IO)?)?;
            if jpki::digest::verify(certificate, read_all(stdin())?, signature) {
                println!("OK");
            } else {
                println!("NG");
                exit(1);
            }
        }
    }

    Ok(())
}
