use anyhow::{bail, Context, Result};
use didkit::{
    ssi::{
        jwk::{ECParams, Params, JWK},
        vc::Credential,
    },
    ContextLoader, ResolutionInputMetadata, Source, DID_METHODS,
};
use inquire::{Confirm, Text};
use oid4vci::{
    core::{client::Client, metadata::IssuerMetadata},
    credential::ResponseEnum,
    credential_profiles::{
        CoreProfilesAuthorizationDetails, CoreProfilesResponse, CredentialMetadataProfile,
    },
    metadata::AuthorizationMetadata,
    openidconnect::{
        reqwest::async_http_client, AuthorizationCode, ClientId, CsrfToken, IssuerUrl,
        OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl,
    },
    proof_of_possession::{
        Proof, ProofOfPossession, ProofOfPossessionController, ProofOfPossessionParams,
    },
};
use time::Duration;
use url::{Position, Url};

use crate::load_credential;

pub async fn initiate_oid4vci(base_url: Url) -> Result<()> {
    println!("Loading mDL and key...");
    let loaded = load_credential().await?;

    let issuer_metadata = IssuerMetadata::discover_async(
        IssuerUrl::new(base_url.to_string()).unwrap(),
        async_http_client,
    )
    .await
    .context("Issuer metadata discovery failed")?;
    let authorization_metadata =
        AuthorizationMetadata::discover_async(&issuer_metadata, async_http_client)
            .await
            .context("Authorization server discovery failed")?;
    let client = Client::from_issuer_metadata(
        issuer_metadata.clone(),
        authorization_metadata,
        ClientId::new("test_wallet".into()),
        RedirectUrl::new("https://httpbin.org/get?human_message_for_you=👉👉👉👉👉👉👉👉👉👉👉%2F!%20%20YAY%2C%20NOW%20COPY%20THE%20URL%20AND%20PASTE%20IT%20IN%20THE%20TERMINAL%20%20%2F!👈👈👈👈👈👈👈👈👈👈👈👈👈👈".into()).unwrap(),
    );
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let (authorize_url, csrf_token) = client
        .authorize_url::<_, CoreProfilesAuthorizationDetails>(CsrfToken::new_random)
        .set_pkce_challenge(pkce_challenge)
        .url()
        .context("Authorization URL building failed")?;

    let redirect_confirm = Confirm::new(&format!(
        "Starting authorization phase: you will be redirected to {}... Continue?",
        &authorize_url[..Position::BeforeQuery]
    ))
    .with_default(true)
    .prompt()
    .context("Error getting confirmation")?;

    match redirect_confirm {
        true => println!("Opening in the browser..."),
        false => bail!("Aborting."),
    }

    open::that(authorize_url.to_string()).context("failed to open redirect in default browser")?;

    let url: Url = Text::new("Paste the callback URL from the browser:")
        .prompt()
        .context("Error getting callback URL")?
        .parse()
        .context("Failed to parse callback URL")?;

    let code = url
        .query_pairs()
        .find(|k| k.0 == "code")
        .unwrap()
        .1
        .to_string();
    let state = url
        .query_pairs()
        .find(|k| k.0 == "state")
        .unwrap()
        .1
        .to_string();
    assert_eq!(csrf_token.secret(), &state);

    let token_response = client
        .exchange_code(AuthorizationCode::new(code))
        .set_pkce_verifier(pkce_verifier)
        .request_async(async_http_client)
        .await
        .context("Token exchange failed")?;

    let jwk = JWK::from(Params::EC(ECParams::try_from(&loaded.key).unwrap()));
    let did_key = DID_METHODS.get("key").unwrap();
    let did = did_key.generate(&Source::Key(&jwk)).unwrap();
    let vm = did_key
        .to_resolver()
        .resolve(&did, &ResolutionInputMetadata::default())
        .await
        .1
        .unwrap()
        .verification_method
        .unwrap()[0]
        .get_id(&did)
        .parse()
        .unwrap();

    let pop_params = ProofOfPossessionParams {
        audience: base_url,
        issuer: "Credible".to_string(),
        nonce: token_response.extra_fields().c_nonce.clone(),
        controller: ProofOfPossessionController { vm: Some(vm), jwk },
    };
    let pop = ProofOfPossession::generate(&pop_params, Duration::minutes(5));
    let credential_response = client
        .request_credential(
            token_response.access_token().clone(),
            issuer_metadata.credentials_supported()[1]
                .additional_fields()
                .to_request(),
        )
        .set_proof(Some(Proof::JWT {
            jwt: pop.to_jwt().unwrap(),
        }))
        .request_async(async_http_client)
        .await
        .context("Credential request failed")?;
    let res = match credential_response.additional_profile_fields() {
        ResponseEnum::Immedate(c) => match c {
            CoreProfilesResponse::JWTVC(c) => {
                Credential::verify_jwt(
                    c.credential(),
                    None,
                    DID_METHODS.to_resolver(),
                    &mut ContextLoader::default(),
                )
                .await
            }
            CoreProfilesResponse::JWTLDVC(_) => todo!(),
            CoreProfilesResponse::LDVC(c) => {
                c.credential()
                    .verify(
                        None,
                        DID_METHODS.to_resolver(),
                        &mut ContextLoader::default(),
                    )
                    .await
            }
            CoreProfilesResponse::ISOmDL(_) => todo!(),
        },
        ResponseEnum::Deferred { .. } => panic!("Should be immediate"),
    };
    if !res.errors.is_empty() {
        bail!("Error verifying credential: {:?}", res.errors);
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&credential_response).unwrap()
    );
    Ok(())
}
