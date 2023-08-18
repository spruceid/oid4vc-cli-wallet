use clap::Parser;
use isomdl180137::isomdl::presentation::{device::Document, Stringify};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{
    fs::{create_dir, remove_dir_all, try_exists, File},
    io::AsyncWriteExt,
};
use url::Url;

#[derive(clap::Parser)]
struct Args {
    #[command(subcommand)]
    action: Action,
}

#[derive(clap::Subcommand)]
enum Action {
    /// Generate a fresh mDL using the mdl-sideloader.
    GetMdl,
    /// Handle a request of the "openid4vp://?request_uri=..." and generate a response.
    GenerateResponse {
        #[arg(short, long)]
        request: Url,
    },
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum SupportedAlgorithm {
    ES256,
}

#[derive(Debug, Clone, clap::ValueEnum)]
enum KeyForm {
    PEM,
    DER,
    JWK,
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    match Args::parse().action {
        Action::GetMdl => get_mdl().await,
        Action::GenerateResponse { request } => handle_request(request).await,
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SideloaderResponse {
    mso_mdoc: String,
    #[serde(flatten)]
    _other: Value,
}

async fn get_mdl() {
    const DIR: &'static str = "/tmp/vp-interop-cli-wallet";
    println!("clearing out old data...");

    match try_exists(DIR).await {
        Ok(true) => {
            remove_dir_all(DIR)
                .await
                .expect("unable to clear out old data");
        }
        _ => (),
    }

    create_dir(DIR).await.expect("unable to create dir");

    println!("generating new key...");
    let key = p256::SecretKey::random(&mut rand::thread_rng());

    let jwk = key.public_key().to_jwk();

    println!("requesting new mDL...");
    let response: SideloaderResponse = reqwest::Client::new()
        .post("https://mdlsideloader.spruceid.xyz/issue")
        .bearer_auth("ca3c118a254ad07c1e216992eaaab5ae5fe89aff50b905dece3adc06a608ae3c")
        .json(&jwk)
        .send()
        .await
        .expect("error making request to mdl-sideloader")
        .json()
        .await
        .expect("error parsing response from mdl-sideloader");

    println!("validating response...");
    Document::parse(response.mso_mdoc.clone()).expect("mdl could not be parsed from response");

    println!("saving key and mDL...");
    let pem = key
        .to_sec1_pem(Default::default())
        .expect("unable to serialize key to pem");

    File::create(DIR.to_string() + "/key.pem")
        .await
        .expect("unable to create pem file")
        .write_all(pem.as_bytes())
        .await
        .expect("unable to write key to file");

    File::create(DIR.to_string() + "/mdl")
        .await
        .expect("unable to create mdl file")
        .write_all(response.mso_mdoc.as_bytes())
        .await
        .expect("unable to write mdl to file");

    println!("DONE!")
}

async fn handle_request(_request: Url) {
    todo!()
}
