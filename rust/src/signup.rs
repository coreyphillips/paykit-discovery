//! Automatic homeserver signup for identities with no homeserver record.

use std::time::Duration;

use pubky::errors::RequestError;
use pubky::pkarr::{
    errors::ResolveError, ResolvePolicy, DEFAULT_RELAYS, DEFAULT_RELAY_REQUEST_TIMEOUT,
};
use pubky::{Method, Pubky, PubkySigner, PublicKey, StatusCode};
use serde::Deserialize;

use crate::Error;

/// Homegate issues homeserver signup codes limited per IP address.
const SIGNUP_CODE_URL: &str = "https://homegate.pubky.app/ip_verification";
/// Generous, because a request that times out may still have used a signup code.
const HOMEGATE_TIMEOUT: Duration = Duration::from_secs(30);

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
    let record = pubky
        .get_homeserver_of(owner)
        .await
        .map_err(|error| Error::SignUp(error.to_string()))?;
    if record.is_some() {
        return Ok(true);
    }
    // "Not found" above is weak evidence, because that lookup reports an expired
    // record as not found. Ask the network directly, then each relay's cache,
    // which keeps expired records.
    match pubky
        .client()
        .pkarr()
        .resolve(owner, ResolvePolicy::NetworkOnly)
        .await
    {
        Ok(_) => return Ok(true),
        Err(ResolveError::NotFound) => {}
        Err(error) => return Err(Error::SignUp(error.to_string())),
    }
    // pkarr reports "not found" if any relay does, even when another failed, so
    // ask each relay. Stop at a record, because the rest cannot change the answer.
    let key = owner.z32();
    let mut statuses = Vec::with_capacity(DEFAULT_RELAYS.len());
    for relay in DEFAULT_RELAYS {
        let url = format!("{relay}/{key}?policy=CacheOnly");
        let status = relay_status(pubky, &url).await;
        statuses.push(status);
        if status == Some(StatusCode::OK) {
            break;
        }
    }
    record_on_relays(&statuses)
}

async fn relay_status(pubky: &Pubky, url: &str) -> Option<StatusCode> {
    let response = pubky
        .client()
        .request(Method::GET, &url)
        .timeout(DEFAULT_RELAY_REQUEST_TIMEOUT)
        .send()
        .await
        .ok()?;
    Some(response.status())
}

/// Decide from each relay's answer, or `None` for no answer.
///
/// Relays do not all hold the same records, and signing up over one costs far
/// more than a retry, so one relay holding a record settles it and "no record"
/// needs every relay to say so.
pub(crate) fn record_on_relays(statuses: &[Option<StatusCode>]) -> Result<bool, Error> {
    if statuses.contains(&Some(StatusCode::OK)) {
        return Ok(true);
    }
    if statuses
        .iter()
        .all(|status| *status == Some(StatusCode::NOT_FOUND))
    {
        return Ok(false);
    }
    Err(Error::SignUp(
        "a Pkarr relay did not answer the homeserver lookup".to_owned(),
    ))
}

async fn create_account(signer: &PubkySigner, signup_code: &SignupCode) -> Result<(), Error> {
    let homeserver = &signup_code.homeserver;
    match signer.signup(homeserver, Some(&signup_code.code)).await {
        Ok(()) => Ok(()),
        // The account exists, so an earlier call failed before publishing its record.
        Err(pubky::Error::Request(RequestError::Server { status, .. }))
            if status == StatusCode::CONFLICT =>
        {
            signer
                .pkdns()
                .publish_homeserver_force(Some(homeserver))
                .await
                .map_err(|error| Error::SignUp(error.to_string()))
        }
        Err(error) => Err(signup_failure(&error)),
    }
}

/// Keep only the status: the SDK sends the signup code in the URL, and its errors
/// can quote that URL.
pub(crate) fn signup_failure(error: &pubky::Error) -> Error {
    Error::SignUp(match error {
        pubky::Error::Request(RequestError::Server { status, .. }) => {
            format!("the homeserver returned status {status}")
        }
        _ => "the signup request failed".to_owned(),
    })
}

async fn request_signup_code(pubky: &Pubky) -> Result<SignupCode, Error> {
    let response = pubky
        .client()
        .request(Method::POST, &SIGNUP_CODE_URL)
        .timeout(HOMEGATE_TIMEOUT)
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
