//! Automatic homeserver signup for identities with no homeserver record.

use pubky::pkarr::{errors::ResolveError, ResolvePolicy};
use pubky::{Method, Pubky, PubkySigner, PublicKey, StatusCode};
use serde::Deserialize;

use crate::Error;

/// Homegate issues homeserver signup codes limited per IP address.
const SIGNUP_CODE_URL: &str = "https://homegate.pubky.app/ip_verification";

/// Homegate's response to `POST /ip_verification`.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct IpVerificationResponse {
    signup_code: String,
    homeserver_pubky: String,
}

/// A validated signup code and the homeserver it belongs to.
pub(crate) struct SignupCode {
    pub(crate) code: String,
    pub(crate) homeserver: PublicKey,
}

/// Sign up the identity if, and only if, no homeserver record for it can be
/// found.
///
/// Signup force-publishes the homeserver record, so running it for an identity
/// that has one would point that identity away from its data. The decision
/// comes from the record, never from a failed sign-in, which does not show that
/// no account exists. An identity with a record continues to sign-in unchanged.
pub(crate) async fn ensure_homeserver(
    pubky: &Pubky,
    signer: &PubkySigner,
    owner: &PublicKey,
) -> Result<(), Error> {
    if has_record(pubky, owner).await? {
        return Ok(());
    }
    let signup_code = request_signup_code(pubky).await?;
    create_account(signer, &signup_code).await
}

async fn has_record(pubky: &Pubky, owner: &PublicKey) -> Result<bool, Error> {
    if pubky
        .get_homeserver_of(owner)
        .await
        .map_err(Error::SignUp)?
        .is_some()
    {
        return Ok(true);
    }
    // "Not found" above is weak evidence, because that lookup reports an expired
    // record as not found. Ask the network directly, then the relay caches, which
    // keep expired records. Any failure stops here, because only a real answer
    // shows that there is no record.
    let pkarr = pubky.client().pkarr();
    for policy in [ResolvePolicy::NetworkOnly, ResolvePolicy::CacheOnly] {
        match pkarr.resolve(owner, policy).await {
            Ok(_) => return Ok(true),
            Err(ResolveError::NotFound) => {}
            Err(error) => return Err(Error::SignUp(error.into())),
        }
    }
    Ok(false)
}

async fn create_account(signer: &PubkySigner, signup_code: &SignupCode) -> Result<(), Error> {
    let homeserver = &signup_code.homeserver;
    match signer.signup(homeserver, Some(&signup_code.code)).await {
        // The account exists, so an earlier call failed before publishing its record.
        Err(pubky::Error::Request(pubky::errors::RequestError::Server { status, .. }))
            if status == StatusCode::CONFLICT =>
        {
            signer
                .pkdns()
                .publish_homeserver_force(Some(homeserver))
                .await
                .map_err(Error::SignUp)
        }
        result => result.map_err(Error::SignUp),
    }
}

async fn request_signup_code(pubky: &Pubky) -> Result<SignupCode, Error> {
    let response = pubky
        .client()
        .request(Method::POST, &SIGNUP_CODE_URL)
        .send()
        .await
        .map_err(|error| Error::Homegate(error.to_string()))?;
    let status = response.status();
    let body = response
        .text()
        .await
        .map_err(|error| Error::Homegate(error.to_string()))?;
    parse_signup_code(status, &body)
}

/// Validate Homegate's answer. Errors never quote the body, which may hold a
/// signup code.
pub(crate) fn parse_signup_code(status: StatusCode, body: &str) -> Result<SignupCode, Error> {
    if status == StatusCode::TOO_MANY_REQUESTS {
        return Err(Error::SignUpRateLimited);
    }
    if !status.is_success() {
        return Err(Error::Homegate(format!("unexpected status {status}")));
    }
    let invalid = || Error::Homegate("invalid response".to_owned());
    let response: IpVerificationResponse = serde_json::from_str(body).map_err(|_| invalid())?;
    if response.signup_code.is_empty() {
        return Err(invalid());
    }
    let homeserver = PublicKey::try_from_z32(&response.homeserver_pubky).map_err(|_| invalid())?;
    if homeserver.z32() != response.homeserver_pubky {
        return Err(invalid());
    }
    Ok(SignupCode {
        code: response.signup_code,
        homeserver,
    })
}
