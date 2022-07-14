extern crate core;

mod nfc;

use std::fs::File;
use std::io::{stderr, stdin, stdout, Read, Write};
use std::path::PathBuf;
use std::process::exit;
use std::rc::Rc;

use clap::{Parser, Subcommand};
use dialoguer::Password;
use jpki::ap::jpki::CertType;
use jpki::ap::surface::Pin;
use jpki::nfc::{Command, HandlerInCtx, Response};
use tracing::metadata::LevelFilter;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use crate::nfc::{Context, Target};

const PIN_HINT_USER_AUTHENTICATION: &str = "PIN for user authentication (4 digits)";
const PIN_HINT_DIGITAL_SIGNATURE: &str = "PIN for digital signature (max. 16 characters)";
const PIN_HINT_SURFACE: &str =
    "PIN type A (Your my number, 12 digits), or type B (DoB 'YYMMDD' + Expiry 'YYYY' + CVC 'XXXX') alternatively (some information unavailable), for card surface";
const PIN_HINT_SUPPORT: &str = "PIN for text filling support (4 digits)";

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("I/O error occurred: {0}")]
    IO(#[from] std::io::Error),

    #[error("Error occurred on communicating with NFC device: {0}")]
    Nfc(#[from] nfc::Error),

    #[error("The card returned an error: {0}")]
    Apdu(#[from] jpki::nfc::Error),

    #[error("JSON serializing / deserializing failed: {0}")]
    Json(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, Error>;

type Ctx = ();
struct NfcCard<'a> {
    target: Target<'a>,
}

impl<'a> HandlerInCtx<Ctx> for NfcCard<'a> {
    fn handle_in_ctx(&self, _: Ctx, command: Command) -> Response {
        let tx = Vec::from(command);
        let rx = self.target.transmit(&tx).unwrap();

        rx.into()
    }
}

#[derive(Clone, clap::ArgEnum)]
enum SurfaceContentType {
    DateOfBirth,
    Sex,
    PublicKey,
    Name,
    Address,
    Photo,
    Signature,
    ExpiryDate,
    Code,
}

#[derive(Clone, clap::ArgEnum)]
enum SupportContentType {
    MyNumber,
    Attributes,
}

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
    /// Reads the surface information from the card.
    /// Either PIN type A (Your my number, 12 digits), or type B (DoB 'YYMMDD' + Expiry 'YYYY' + CVC 'XXXX')
    /// alternatively (some information unavailable), is required.
    Surface {
        #[clap(arg_enum)]
        ty: SurfaceContentType,
    },
    /// Reads the text information from the card.
    Support {
        #[clap(arg_enum)]
        ty: SupportContentType,
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

    /// Exports pretty-printed JSON instead of minified.
    #[clap(short, long, action)]
    pretty: bool,
}

fn pin_prompt(hint: &'static str) -> Result<Vec<u8>> {
    Password::new()
        .with_prompt(hint)
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
    let target = device.connect(ctx).map_err(Error::Nfc)?;

    let nfc_card = NfcCard { target };
    let card = Rc::new(jpki::Card::new(Box::new(nfc_card)));
    let open_jpki_ap = || jpki::ap::JpkiAp::open((), Rc::clone(&card)).map_err(Error::Apdu);
    let open_surface_ap = || jpki::ap::SurfaceAp::open((), Rc::clone(&card)).map_err(Error::Apdu);
    let open_support_ap = || jpki::ap::SupportAp::open((), Rc::clone(&card)).map_err(Error::Apdu);

    let ty = match (cli.auth, cli.ca) {
        (true, true) => CertType::AuthCA,
        (true, _) => CertType::Auth,
        (_, true) => CertType::SignCA,
        _ => CertType::Sign,
    };

    let to_json = match cli.pretty {
        true => serde_json::to_string_pretty,
        _ => serde_json::to_string,
    };

    match &cli.command {
        SubCommand::ReadCertificate => {
            let jpki_ap = open_jpki_ap()?;
            let pin = if ty.is_pin_required() {
                pin_prompt(PIN_HINT_DIGITAL_SIGNATURE)?
            } else {
                vec![]
            };

            let certificate = jpki_ap.read_certificate((), ty, pin).map_err(Error::Apdu)?;

            stdout().write_all(&certificate).map_err(Error::IO)?;
        }
        SubCommand::Sign { signature_path } => {
            let jpki_ap = open_jpki_ap()?;
            let digest = jpki::digest::calculate(read_all(stdin())?);
            let signature = match cli.auth {
                true => jpki_ap.auth((), pin_prompt(PIN_HINT_USER_AUTHENTICATION)?, digest),
                _ => jpki_ap.sign((), pin_prompt(PIN_HINT_DIGITAL_SIGNATURE)?, digest),
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
        SubCommand::Surface { ty } => {
            use SurfaceContentType::*;

            let surface_ap = open_surface_ap()?;
            let pin = pin_prompt(PIN_HINT_SURFACE)?;
            let pin = match pin.len() {
                12 => Pin::A(pin_prompt(PIN_HINT_SURFACE)?),
                _ => Pin::B(pin_prompt(PIN_HINT_SURFACE)?),
            };

            let surface = surface_ap.read_surface((), pin).map_err(Error::Apdu)?;

            stdout()
                .write_all(match ty {
                    DateOfBirth => &surface.date_of_birth,
                    Sex => &surface.sex,
                    PublicKey => &surface.public_key,
                    Name => &surface.name,
                    Address => &surface.address,
                    Photo => &surface.photo,
                    Signature => &surface.signature,
                    ExpiryDate => &surface.expiry_date,
                    Code => &surface.code,
                })
                .map_err(Error::IO)?;
        }
        SubCommand::Support { ty } => {
            use SupportContentType::*;

            let support_ap = open_support_ap()?;
            let pin = pin_prompt(PIN_HINT_SUPPORT)?;

            match ty {
                MyNumber => {
                    println!(
                        "{}",
                        support_ap.read_my_number((), pin).map_err(Error::Apdu)?,
                    );
                }
                Attributes => {
                    println!(
                        "{}",
                        to_json(&support_ap.read_attributes((), pin).map_err(Error::Apdu)?)
                            .map_err(Error::Json)?,
                    )
                }
            }
        }
    }

    Ok(())
}

fn main() {
    tracing_subscriber::fmt::fmt()
        .with_env_filter(
            EnvFilter::builder()
                .with_default_directive(LevelFilter::INFO.into())
                .from_env_lossy(),
        )
        .with_writer(stderr)
        .init();

    if let Err(e) = run() {
        error!("{}", e);
    }
}
