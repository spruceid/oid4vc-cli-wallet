# OpenID4VC CLI Wallet

Rust-based CLI wallet used for testing the OpenID4VC protocols.

## Usage

```
Usage: openid4vc-wallet <COMMAND>

Commands:
  handle-mdoc-request  Handle a request of the "mdoc-openid4vp://?request_uri=..." and generate a response
  initiate-issuance    Initiate a OID4VCI flow
  help                 Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

```bash
# To run without installing:
cargo run -- help

# Or to install and then run
cargo install --path .
openid4vc-wallet help
```
