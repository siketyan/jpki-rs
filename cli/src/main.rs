mod nfc;

use std::fs::File;
use std::io::{stderr, stdin, stdout, Read, Write};
use std::path::PathBuf;
use std::process::exit;

use clap::{Parser, Subcommand};
use dialoguer::Password;
use jpki::ap::jpki::CertType;
use jpki::nfc::apdu::{Command, Handler, Response};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::nfc::{Context, Initiator, Target};

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("I/O error occurred: {0}")]
    IO(#[from] std::io::Error),

    #[error("Error occurred on communicating with NFC device: {0}")]
    Nfc(#[from] nfc::Error),

    #[error("The card returned an error: {0}")]
    Apdu(#[from] jpki::nfc::apdu::Error),
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

#[derive(Subcommand)]
enum SubCommand {
    /// Reads a certificate in the JPKI card.
    ReadCertificate,
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

    /// Uses the key-pair for user authentication, instead of for digital signature.
    #[clap(short, long, action)]
    auth: bool,

    /// While reading certificates, reads their CA certificate instead.
    #[clap(short, long, action)]
    ca: bool,
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

fn run() -> Result<()> {
    let cli: Cli = Cli::parse();

    let ctx = Context::try_new().map_err(Error::Nfc)?;
    let device = ctx.open().map_err(Error::Nfc)?;
    let initiator = Initiator::from(device);
    let target = initiator.select_dep_target(ctx).map_err(Error::Nfc)?;

    let nfc_card = NfcCard { target };
    let card = jpki::Card::new(Box::new(nfc_card));
    let jpki_ap = jpki::ap::JpkiAp::open((), Box::new(card)).map_err(Error::Apdu)?;

    let ty = match (cli.auth, cli.ca) {
        (true, true) => CertType::AuthCA,
        (true, _) => CertType::Auth,
        (_, true) => CertType::SignCA,
        _ => CertType::Sign,
    };

    match &cli.command {
        SubCommand::ReadCertificate => {
            let pin = if ty.is_pin_required() {
                prompt_password()?
            } else {
                vec![]
            };

            let certificate = jpki_ap.read_certificate((), ty, pin).map_err(Error::Apdu)?;

            stdout().write_all(&certificate).map_err(Error::IO)?;
        }
        SubCommand::Sign { signature_path } => {
            let digest = jpki::digest::calculate(read_all(stdin())?);
            let signature = match cli.auth {
                true => jpki_ap.auth((), prompt_password()?, digest),
                _ => jpki_ap.sign((), prompt_password()?, digest),
            }?;

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
                info!("OK")
            } else {
                error!("NG");
                exit(1);
            }
        }
    }

    Ok(())
}

fn main() {
    tracing_subscriber::fmt::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(stderr)
        .init();

    if let Err(e) = run() {
        error!("{}", e);
    }
}
