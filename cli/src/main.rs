mod digest;

use std::env;
use std::fs::File;
use std::io::{stderr, stdin, stdout, Read, Write};
use std::path::PathBuf;
use std::process::exit;
use std::rc::Rc;

use clap::{Parser, Subcommand};
use dialoguer::Password;
use jpki::ap::crypto::CertType;
use jpki::ap::surface::Pin;
use jpki::pcsc::Context;
use rust_i18n::{i18n, set_locale, t};
use tracing::metadata::LevelFilter;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

i18n!("locales");

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("I/O error occurred: {0}")]
    IO(#[from] std::io::Error),

    #[error("Error occurred on communicating with NFC device: {0}")]
    Pcsc(#[from] jpki::pcsc::Error),

    #[error("The card returned an error: {0}")]
    Apdu(#[from] jpki::nfc::Error),

    #[error("JSON serializing / deserializing failed: {0}")]
    Json(#[from] serde_json::Error),
}

type Result<T> = std::result::Result<T, Error>;

#[derive(Clone, clap::ValueEnum)]
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

#[derive(Clone, clap::ValueEnum)]
enum SurfacePinType {
    /// My Number (12 digits).
    /// Information from both front and back is available.
    A,

    /// DoB in 'YYYYMMDD' format + Expiry date in 'YYYY' format + PIN (4 digits).
    /// Information from only front is available.
    B,
}

#[derive(Clone, clap::ValueEnum)]
enum SupportContentType {
    MyNumber,
    Attributes,
}

#[derive(Subcommand)]
enum CryptoApAction {
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

    /// Gets the status of PIN.
    Stat,
}

#[derive(Subcommand)]
enum SurfaceApAction {
    /// Reads the surface information from the card.
    /// Either PIN type A (Your my number, 12 digits), or type B (DoB 'YYMMDD' + Expiry 'YYYY' + CVC 'XXXX')
    /// alternatively (some information unavailable), is required.
    Get {
        #[clap(value_enum)]
        ty: SurfaceContentType,
    },

    /// Gets the status of PIN.
    Stat {
        #[clap(value_enum)]
        ty: SurfacePinType,
    },
}

#[derive(Subcommand)]
enum SupportApAction {
    /// Reads the text information from the card.
    Get {
        #[clap(value_enum)]
        ty: SupportContentType,

        /// Exports pretty-printed JSON instead of minified.
        #[clap(short, long, action)]
        pretty: bool,
    },

    /// Gets the status of PIN.
    Stat,
}

#[derive(Subcommand)]
enum SubCommand {
    /// Read certificates, sign or verify documents.
    Crypto {
        #[clap(subcommand)]
        action: CryptoApAction,

        /// Uses the key-pair for user authentication, instead of for digital signature.
        #[clap(short, long, action)]
        auth: bool,

        /// While reading certificates, reads their CA certificate instead.
        #[clap(short, long, action)]
        ca: bool,
    },

    /// Reads the surface information from the card.
    Surface {
        #[clap(subcommand)]
        action: SurfaceApAction,
    },

    /// Reads the text information from the card.
    Support {
        #[clap(subcommand)]
        action: SupportApAction,
    },
}

#[derive(Parser)]
#[clap(author, version, about, long_about = None)]
#[clap(propagate_version = true)]
struct Cli {
    #[clap(subcommand)]
    command: SubCommand,
}

fn pin_prompt(hint: &str) -> Result<Vec<u8>> {
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

    let ctx = Context::try_new()?;
    let device = ctx.open()?;
    let pcsc_card = device.connect(ctx)?;

    let card = Rc::new(jpki::Card::new(Box::new(pcsc_card)));
    let open_crypto_ap = || jpki::ap::CryptoAp::open((), Rc::clone(&card));
    let open_surface_ap = || jpki::ap::SurfaceAp::open((), Rc::clone(&card));
    let open_support_ap = || jpki::ap::SupportAp::open((), Rc::clone(&card));

    let to_json = |pretty: bool| match pretty {
        true => serde_json::to_string_pretty,
        _ => serde_json::to_string,
    };

    match &cli.command {
        SubCommand::Crypto { action, auth, ca } => {
            let ty = match (auth, ca) {
                (true, true) => CertType::AuthCA,
                (true, _) => CertType::Auth,
                (_, true) => CertType::SignCA,
                _ => CertType::Sign,
            };

            match action {
                CryptoApAction::ReadCertificate => {
                    let crypto_ap = open_crypto_ap()?;
                    let pin = if ty.is_pin_required() {
                        pin_prompt(&t!("messages.pin_hint.signing"))?
                    } else {
                        vec![]
                    };

                    let certificate = crypto_ap.read_certificate((), ty, pin)?;
                    stdout().write_all(&certificate)?;
                }
                CryptoApAction::Sign { signature_path } => {
                    let crypto_ap = open_crypto_ap()?;
                    let digest = digest::calculate(read_all(stdin())?);
                    let signature = match auth {
                        true => crypto_ap.auth(
                            (),
                            pin_prompt(&t!("messages.pin_hint.user_authn"))?,
                            digest,
                        ),
                        _ => crypto_ap.sign(
                            (),
                            pin_prompt(&t!("messages.pin_hint.signing"))?,
                            digest,
                        ),
                    }?;

                    let mut signature_file = File::create(signature_path)?;
                    signature_file.write_all(&signature)?;
                }
                CryptoApAction::Verify {
                    certificate_path,
                    signature_path,
                } => {
                    let certificate = read_all(File::open(certificate_path)?)?;
                    let signature = read_all(File::open(signature_path)?)?;
                    if digest::verify(certificate, read_all(stdin())?, signature) {
                        info!("OK")
                    } else {
                        error!("NG");
                        exit(1);
                    }
                }
                CryptoApAction::Stat => {
                    let crypto_ap = open_crypto_ap()?;
                    let count = match auth {
                        true => crypto_ap.auth_pin_status(()),
                        _ => crypto_ap.sign_pin_status(()),
                    }?;

                    println!("{}", count);
                }
            }
        }
        SubCommand::Surface { action } => match action {
            SurfaceApAction::Get { ty } => {
                use SurfaceContentType::*;

                let surface_ap = open_surface_ap()?;
                let pin = pin_prompt(t!("messages.pin_hint.surface").as_str())?;
                let pin = match pin.len() {
                    12 => Pin::A(pin),
                    _ => Pin::B(pin),
                };

                let surface = surface_ap.read_surface((), pin)?;

                stdout().write_all(match ty {
                    DateOfBirth => &surface.date_of_birth,
                    Sex => &surface.sex,
                    PublicKey => &surface.public_key,
                    Name => &surface.name,
                    Address => &surface.address,
                    Photo => &surface.photo,
                    Signature => &surface.signature,
                    ExpiryDate => &surface.expiry_date,
                    Code => &surface.code,
                })?;
            }
            SurfaceApAction::Stat { ty } => {
                use SurfacePinType::*;

                let surface_ap = open_surface_ap()?;
                let status = match ty {
                    A => surface_ap.pin_a_status(()),
                    B => surface_ap.pin_b_status(()),
                }?;

                println!("{}", status);
            }
        },
        SubCommand::Support { action } => match action {
            SupportApAction::Get { ty, pretty } => {
                use SupportContentType::*;

                let support_ap = open_support_ap()?;
                let pin = pin_prompt(&t!("messages.pin_hint.support"))?;

                match ty {
                    MyNumber => {
                        println!("{}", support_ap.read_my_number((), pin)?,);
                    }
                    Attributes => {
                        println!(
                            "{}",
                            to_json(*pretty)(&support_ap.read_attributes((), pin)?)?,
                        )
                    }
                }
            }
            SupportApAction::Stat => {
                let support_ap = open_support_ap()?;
                let count = support_ap.pin_status(())?;

                println!("{}", count)
            }
        },
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

    match env::var("LOCALE")
        .ok()
        .as_deref()
        .map(|s| s.split_once('.').map(|s| s.0).unwrap_or(s))
    {
        Some("C") => (), // Use default locale
        Some(l) => set_locale(l),
        _ => (),
    };

    if let Err(e) = run() {
        error!("{}", e);
    }
}
