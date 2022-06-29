# jpki-rs
[![Rust](https://github.com/siketyan/jpki-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/siketyan/jpki-rs/actions/workflows/rust.yml)

Read certificates, sign and verify documents using your JPKI card.

## 💻 Supported Platforms
These targets are tested continuously:
- x86_64-pc-windows-msvc
- x86_64-apple-darwin
- aarch64-apple-darwin
- x86_64-unknown-linux-gnu
- aarch64-linux-android
- armv7-linux-androideabi

Since this crate is fully cross-platform, we are welcome to add a new platform to this list :)

## 📦 Getting Started
Add to your Cargo.toml as a dependency as follows:
```toml
[dependencies]
jpki = "0.1"
```

## ✨ Features
- **digest**: Utility for calculating digests to sign or verify the data (non-default).

## 💚 Example
See [jpki-cli](./cli) for an example usage of this crate.
