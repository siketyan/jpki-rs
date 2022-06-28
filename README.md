# jpki-rs
Read certificates, sign and verify documents using your JPKI card.

## CLI
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
