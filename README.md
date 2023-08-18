# VP-Interop CLI Wallet

CLI-based wallet used for testing with https://github.com/spruceid/vp_interop.

## Usage

```
Commands:
  get-mdl         Generate a fresh mDL using the mdl-sideloader
  handle-request  Handle a request of the "openid4vp://?request_uri=..." and generate a response
  help            Print this message or the help of the given subcommand(s)

Options:
  -h, --help  Print help
```

```bash
# To generate an mDL.
cargo run -- get-mdl

# To generate an mDL.
cargo run -- handle-request -r 'openid4vp://?request_uri=...'

# To view help.
cargo run -- help
```
