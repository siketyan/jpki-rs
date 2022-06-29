# jpki-cli
[![Rust](https://github.com/siketyan/jpki-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/siketyan/jpki-rs/actions/workflows/rust.yml)

Easy yet simple CLI to access your JPKI card.

## ✅ Prerequisites
All platforms:
- PC/SC supported NFC reader

On GNU/Linux:
- pcsc-lite (libpcsclite)

## 📦 Installation
On macOS or Linux, Homebrew Tap can be used for installation:
```shell
brew tap siketyan/tap
brew install jpki-cli
```

Alternatively, build from source using Cargo:
```shell
cargo install jpki-cli
```

## 💚 Example
```
jpki-cli 0.1.8
Naoki Ikeguchi <me@s6n.jp>
Read certificates, sign and verify documents using your JPKI card.

USAGE:
    jpki-cli [OPTIONS] <SUBCOMMAND>

OPTIONS:
    -a, --auth       Uses the key-pair for user authentication, instead of for digital signature
    -c, --ca         While reading certificates, reads their CA certificate instead
    -h, --help       Print help information
    -V, --version    Print version information

SUBCOMMANDS:
    help                Print this message or the help of the given subcommand(s)
    read-certificate    Reads a certificate in the JPKI card
    sign                Writes a signature of the document
    surface             Reads the surface information from the card. PIN type B (DoB + Expiry +
                            PIN) is required by default
    verify              Verifies the signed digest
```
