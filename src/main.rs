use anyhow::{bail, Context, Result};
use clap::Parser;
use isomdl180137::{
    isomdl::{
        definitions::helpers::NonEmptyMap,
        presentation::{
            device::{Document, PreparedDeviceResponse},
            Stringify,
        },
    },
    present::{
        complete_mdl_response, OID4VPHandover, State, UnattendedSessionManager,
        UnattendedSessionTranscript,
    },
};
use josekit::jwk::Jwk;
use oidc4vp::{
    mdl_request::{MetaData, RequestObject},
    presentment::Present,
};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    SecretKey,
};
use reqwest::redirect::Policy;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use tokio::{
    fs::{create_dir, read_to_string, remove_dir_all, try_exists, File},
    io::AsyncWriteExt,
};
use url::Url;

const DIR: &'static str = "/tmp/vp-interop-cli-wallet";
const KEYFILE: &'static str = "/key.pem";
const MDLFILE: &'static str = "/mdl";

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
    HandleRequest {
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
        Action::HandleRequest { request } => {
            if let Err(e) = handle_request(request).await {
                println!("ERROR: {e:?}")
            }
        }
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

    File::create(DIR.to_string() + KEYFILE)
        .await
        .expect("unable to create pem file")
        .write_all(pem.as_bytes())
        .await
        .expect("unable to write key to file");

    File::create(DIR.to_string() + MDLFILE)
        .await
        .expect("unable to create mdl file")
        .write_all(response.mso_mdoc.as_bytes())
        .await
        .expect("unable to write mdl to file");

    println!("DONE!")
}

struct Loaded {
    key: SecretKey,
    mdl: Document,
}

async fn load_credential() -> Result<Loaded> {
    let key_pem = read_to_string(DIR.to_string() + KEYFILE)
        .await
        .context("unable to load keyfile")?;
    let key = SecretKey::from_sec1_pem(&key_pem)
        .context("unable to parse keyfile as a p256 secret key")?;

    let mdl_string = read_to_string(DIR.to_string() + MDLFILE)
        .await
        .context("unable to load mdlfile")?;
    let mdl = Document::parse(mdl_string).context("unable to parse mdlfile")?;

    Ok(Loaded { key, mdl })
}

struct AuthorizationRequest {
    request_uri: Url,
    client_id: Option<String>,
}

fn validate_authz_request(request: Url) -> Result<AuthorizationRequest> {
    const SCHEME: &'static str = "mdoc-openid4vp";
    let scheme = request.scheme();
    if scheme != SCHEME {
        println!("WARNING: Request scheme was invalid: '{scheme}'")
    }
    let client_id = request
        .query_pairs()
        .find(|qp| qp.0 == "client_id")
        .map(|qp| qp.1.to_string());
    if client_id.is_none() {
        println!("WARNING: Authorization Request did not contain 'client_id'");
    }

    let request_uri = request
        .query_pairs()
        .find(|qp| qp.0 == "request_uri")
        .map(|qp| qp.1)
        .context("Authorization Request did not contain 'request_uri'")?;

    let request_uri = Url::parse(&request_uri).context("Could not parse request_uri as a URL")?;

    Ok(AuthorizationRequest {
        request_uri,
        client_id,
    })
}

async fn get_request_object(request_uri: Url) -> Result<RequestObject> {
    let res = reqwest::get(request_uri.clone())
        .await
        .context(format!("could not GET @ {request_uri}"))?;

    let status = res.status();
    let body = res
        .text()
        .await
        .context(format!("couldn't parse response body for error '{status}'"))?;
    if !status.is_success() {
        bail!("'{status}' error GETing '{request_uri}': {body}")
    }

    ssi::jwt::decode_unverified(&body).context("unable to decode JWT")
}

fn request_object_to_handover(req: &RequestObject, mdoc_nonce: String) -> Result<OID4VPHandover> {
    let req = req.clone();
    let client_id = req.client_id;
    let response_uri = req
        .response_uri
        .context("response_uri missing from request")?;
    let nonce = req.nonce.context("nonce missing from request")?.clone();
    Ok(OID4VPHandover(mdoc_nonce, client_id, response_uri, nonce))
}

fn construct_state(request: RequestObject, mdoc_nonce: String) -> Result<State> {
    const SUPPORTED_ALG: &'static str = "ECDH-ES";
    const SUPPORTED_ENC: &'static str = "A256GCM";
    const SUPPORTED_CRV: &'static str = "P-256";

    let MetaData::ClientMetadata {client_metadata} = request.client_metadata.clone() else { bail!("Expected 'client_metadata' in request object, received 'client_metadata_uri'") };

    let alg = client_metadata.authorization_encrypted_response_alg;
    let enc = client_metadata.authorization_encrypted_response_enc;

    if alg != SUPPORTED_ALG {
        bail!("unsupported algorithm '{alg}'")
    };
    if enc != SUPPORTED_ENC {
        bail!("unsupported encryption '{enc}'")
    };

    let Value::Array(keys) = client_metadata.jwks.get("keys")
        .context("missing field 'keys' in 'jwks'")?
        else { bail!("expected an array of JWKs") };

    let jwk = keys
        .iter()
        .cloned()
        .filter_map(|v| {
            let jwk: Result<Jwk, serde_json::Error> = serde_json::from_value(v);
            match jwk {
                Ok(jwk) => Some(jwk),
                Err(e) => {
                    println!("WARNING: unable to parse a JWK in keyset: {e}");
                    None
                }
            }
        })
        .find(|jwk| {
            let Some(crv) = jwk.curve() else {
                println!("WARNING: jwk in keyset was missing 'crv'");
                return false
            };
            crv == SUPPORTED_CRV
        })
        .context("no P-256 keys found in JWK keyset")?;

    Ok(State {
        mdoc_nonce,
        request_object: request,
        verifier_epk: jwk,
    })
}

fn parse_request(
    req: RequestObject,
    client_id: Option<String>,
    mdl: Document,
) -> Result<(UnattendedSessionManager, State)> {
    if let Some(id) = client_id {
        if req.client_id != id {
            println!("WARNING: client_id from AuthorizationRequest did not match client_id in request object");
        }
    }

    let doc_type = String::from("org.iso.18013.5.1.mDL");
    let documents = NonEmptyMap::new(doc_type, mdl);

    let mdoc_nonce = isomdl180137::utils::gen_nonce();
    let handover = request_object_to_handover(&req, mdoc_nonce.clone())?;
    let session_transcript = UnattendedSessionTranscript(handover);
    let session_manager = UnattendedSessionManager {
        session_transcript,
        documents,
    };
    let state = construct_state(req, mdoc_nonce)?;

    Ok((session_manager, state))
}

async fn prepare_response(
    session_manager: &UnattendedSessionManager,
    request: RequestObject,
) -> Result<PreparedDeviceResponse> {
    session_manager
        .prepare_mdl_response(request)
        .await
        .context("failure occurred when preparing response")
}

async fn finish(key: SecretKey, prepared: PreparedDeviceResponse, state: State) -> Result<String> {
    let signer: SigningKey = key.into();
    let (_, tbs) = prepared
        .get_next_signature_payload()
        .context("expected at least one document to sign")?;
    let signature: Signature = signer.sign(tbs);

    complete_mdl_response(prepared, state, signature.to_vec())
        .await
        .context("failed to complete and encrypt response")
}

async fn send(response_uri: String, jwe: String) -> Result<String> {
    let mut body = Map::new();
    body.insert("response".to_string(), serde_json::Value::String(jwe));
    let client = reqwest::Client::builder()
        .redirect(Policy::none())
        .build()
        .context("unable to build http client")?;
    let response = client
        .post(response_uri)
        .form(&body)
        .send()
        .await
        .context("failed to submit response")?;
    let status = response.status();
    let location = response
        .headers()
        .get("location")
        .map(|v| v.to_str().map(|s| s.to_string()));
    let body = response
        .text()
        .await
        .context("response could not be parsed as text")?;
    if status.is_server_error() || status.is_client_error() {
        bail!("'{status}': {body}")
    }
    if !status.is_redirection() {
        println!("WARNING: response was not a redirection '{status}': {body}");
    }
    location
        .context("'location' header was missing in redirect")?
        .context("could not parse 'location' header as a UTF8 string")
}

async fn handle_request(request: Url) -> Result<()> {
    println!("loading mDL and key...");
    let loaded = load_credential().await?;

    println!("validating authorization request...");
    let authz_req = validate_authz_request(request)?;

    println!("getting request...");
    let request = get_request_object(authz_req.request_uri).await?;

    println!("parsing request...");
    let response_uri = request
        .response_uri
        .clone()
        .context("response_uri missing from request")?;
    let (session_manager, state) = parse_request(request.clone(), authz_req.client_id, loaded.mdl)?;

    println!("preparing response...");
    let prepared_response = prepare_response(&session_manager, request).await?;

    println!("signing and encrypting response...");
    let jwe = finish(loaded.key, prepared_response, state).await?;

    println!("POSTing response to {response_uri}...");
    let redirect = send(response_uri, jwe).await?;

    println!("SUCCESS! Redirecting to {redirect}");
    open::that(redirect).context("failed to open redirect in default browser")?;

    Ok(())
}
