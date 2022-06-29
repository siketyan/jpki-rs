# jpki-cli
[![crates.io](https://img.shields.io/crates/v/jpki-cli.svg)](https://crates.io/crates/jpki-cli)
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

## 💚 Examples
### Crypto AP
Dumps the certificate for digital signature:
```shell
jpki-cli read-certificate > certificate.der
```

If you want the certificate for user authentication, append `--auth`:
```shell
jpki-cli read-certificate --auth > certificate.der
```

Signs the data from stdin using key-pair for digital signature:
```shell
cat plain.txt | jpki-cli sign > signature.sig
```

Verifies the signature using the dumped certificate:
```shell
cat plain.txt | jpki-cli verify certificate.der signature.sig
```

### Surface AP
Dumps the photo using PIN B (DoB `YYMMDD` + Expiry `YYYY` + CVC `XXXX`):
```shell
jpki-cli surface photo > photo.jpg
# PIN: YYMMDDYYYYXXXX
```

Using PIN A (My Number) instead:
```shell
jpki-cli surface --all photo > photo.jpg
# PIN: XXXXYYYYZZZZ
```

For list of available data to dump, see the help:
```shell
jpki-cli surface --help
```