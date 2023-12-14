mod mdoc_oid4vp;
mod oid4vci;
#[cfg(test)]
mod tests;
mod wallet;

use clap::Parser;
use isomdl180137::isomdl::presentation::device::Document;
use p256::SecretKey;
use tracing::error;
use url::Url;

#[derive(clap::Parser)]
struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(clap::Subcommand)]
enum Action {
    /// Handle a request of the "mdoc-openid4vp://?request_uri=..." and generate a response.
    HandleMdocRequest {
        /// URL with protocol-specific scheme.
        url: Url,
    },
    /// Initiate a OID4VCI flow
    InitiateIssuance {
        /// URL of the issuer
        url: Url,
    },
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_target(false)
        .without_time()
        .try_init();
    match Args::parse().action {
        Action::HandleMdocRequest { url } => {
            if let Err(e) = mdoc_oid4vp::handle_request(url).await {
                error!("Presentment failed: {e:?}")
            }
        }
        Action::InitiateIssuance { url } => {
            if let Err(e) = oid4vci::initiate_oid4vci(url).await {
                error!("Issuance failed: {e:?}")
            }
        }
    }
}

struct Wallet {
    key: SecretKey,
    mdl: Document,
}
