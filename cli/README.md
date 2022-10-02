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
jpki-cli crypto read-certificate > certificate.der
```

If you want the certificate for user authentication, insert `--auth`:
```shell
jpki-cli crypto --auth read-certificate > certificate.der
```

Signs the data from stdin using key-pair for digital signature:
```shell
cat plain.txt | jpki-cli crypto sign > signature.sig
```

Verifies the signature using the dumped certificate:
```shell
cat plain.txt | jpki-cli crypto verify certificate.der signature.sig
```

Gets the PIN status:
```shell
jpki-cli crypto stat
jpki-cli crypto --auth stat # Status of PIN for authentication
```

### Surface AP
Dumps the photo using PIN B (DoB `YYMMDD` + Expiry `YYYY` + CVC `XXXX`):
```shell
jpki-cli surface get photo > photo.jpg
# PIN: YYMMDDYYYYXXXX
```

Using PIN A (My Number) instead:
```shell
jpki-cli surface get photo > photo.jpg
# PIN: XXXXYYYYZZZZ
```

For list of available data to dump, see the help:
```shell
jpki-cli surface get --help
```

Gets the PIN status:
```shell
jpki-cli surface stat a # PIN Type A
jpki-cli surface stat b # PIN Type B
```

### Support AP
Reads the "My Number" from the card:
```shell
jpki-cli support get my-number
```

Reads text attributes from the card as JSON:
```shell
jpki-cli support get attributes --pretty
jpki-cli support get attributes | jq # The output is JSON, so you can query it w/ jq
```

Gets the PIN status:
```shell
jpki-cli support stat
```
