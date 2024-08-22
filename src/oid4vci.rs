use anyhow::{bail, Context, Result};
use did_method_key::DIDKey;
use inquire::{Confirm, Text};
use oid4vci::{
    core::{
        client::Client,
        metadata::CredentialIssuerMetadata,
        profiles::{CoreProfilesAuthorizationDetails, CoreProfilesResponse},
    },
    credential::ResponseEnum,
    metadata::AuthorizationMetadata,
    openidconnect::{
        reqwest::ClientBuilder, AuthorizationCode, ClientId, CsrfToken, IssuerUrl,
        OAuth2TokenResponse, PkceCodeChallenge, RedirectUrl,
    },
    profiles::CredentialMetadataProfile,
    proof_of_possession::{
        Proof, ProofOfPossession, ProofOfPossessionController, ProofOfPossessionParams,
    },
};
use ssi_claims::{vc::v1::data_integrity::any_credential_from_json_str, VerificationParameters};
use ssi_dids::AnyDidMethod;
use ssi_dids_core::{DIDResolver, VerificationMethodDIDResolver};
use ssi_jwk::{ECParams, Params, JWK};
use ssi_jwt::ToDecodedJWT;
use ssi_verification_methods::AnyMethod;
use time::Duration;
use tracing::info;
use url::{Position, Url};

use crate::wallet::generate_credential;

pub async fn initiate_oid4vci(base_url: Url) -> Result<()> {
    info!("Loading mDL and key...");
    let wallet = generate_credential();

    let async_http_client = ClientBuilder::new().build()?;

    let issuer_metadata = CredentialIssuerMetadata::discover_async(
        IssuerUrl::new(base_url.to_string()).unwrap(),
        &async_http_client,
    )
    .await
    .context("Issuer metadata discovery failed")?;
    let authorization_metadata =
        AuthorizationMetadata::discover_async(&issuer_metadata, None, &async_http_client)
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
        true => info!("Opening in the browser..."),
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
        .request_async(&async_http_client)
        .await
        .context("Token exchange failed")?;

    let jwk = JWK::from(Params::EC(ECParams::from(&wallet.key)));

    let did = DIDKey::generate(&jwk).unwrap();

    let vm_resolver: VerificationMethodDIDResolver<AnyDidMethod, AnyMethod> =
        AnyDidMethod::default().into_vm_resolver();

    let vm = vm_resolver
        .resolve(&did)
        .await
        .unwrap()
        .document
        .verification_method[0]
        .id
        .clone();

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
            issuer_metadata.credential_configurations_supported()[0]
                .additional_fields()
                .to_request(),
        )
        .set_proof(Some(Proof::JWT {
            jwt: pop.to_jwt().unwrap(),
        }))
        .request_async(&async_http_client)
        .await
        .context("Credential request failed")?;

    let vm_resolver = AnyDidMethod::default().into_vm_resolver();
    let params = VerificationParameters::from_resolver(vm_resolver);

    let res = match credential_response.additional_profile_fields() {
        ResponseEnum::Immediate(c) => match c {
            CoreProfilesResponse::JWTVC(c) => c.credential().verify_jwt(&params).await,
            CoreProfilesResponse::JWTLDVC(_) => todo!(),
            CoreProfilesResponse::LDVC(c) => {
                any_credential_from_json_str(&serde_json::to_string(c.credential()).unwrap())
                    .unwrap()
                    .verify(&params)
                    .await
            }
            CoreProfilesResponse::ISOmDL(_) => todo!(),
        },
        ResponseEnum::Deferred { .. } => panic!("Should be immediate"),
    };
    if let Err(err) = res {
        bail!("Error verifying credential: {:?}", err);
    }
    info!(
        "{}",
        serde_json::to_string_pretty(&credential_response).unwrap()
    );
    Ok(())
}
