//! Publishing a Payment List from an identity secret or a Pubky session.

use std::collections::BTreeMap;

use paykit_lib::{
    PaykitApp, PaykitAppCapabilities, PaykitAppId, PaykitAppRegistry, PaykitError,
    PaymentEndpointIdentifier, PaymentEndpointPayload, PAYKIT_APP_REGISTRY_MAX_APPS,
    PAYKIT_APP_REGISTRY_PATH, PAYMENT_ENDPOINT_PAYLOAD_MAX_BYTES,
};
use pubky::{
    Capability, ClientId, Keypair, Pubky, PubkySession, PublicKey, PublicStorage, StatusCode,
    StoragePath,
};
use pubky_common::capabilities::Action;
use zeroize::Zeroizing;

use crate::{
    encrypted, endpoint_prefix, Error, PaymentEndpoint, PublishedPaymentList, MAX_ENDPOINTS,
    MAX_PAYLOAD_BYTES,
};

/// Shown in the identity's session list on its homeserver.
pub(crate) const CLIENT_ID: &str = "paykit-discovery";

/// Validated endpoints grouped by App, both levels sorted by ID.
pub(crate) struct ValidatedList {
    pub(crate) apps: Vec<(
        PaykitAppId,
        Vec<(PaymentEndpointIdentifier, PaymentEndpointPayload)>,
    )>,
}

impl ValidatedList {
    /// The endpoints as plain records, sorted by App ID and identifier.
    pub(crate) fn endpoints(&self) -> Vec<PaymentEndpoint> {
        self.apps
            .iter()
            .flat_map(|(app_id, endpoints)| {
                endpoints
                    .iter()
                    .map(|(identifier, payload)| PaymentEndpoint {
                        app_id: app_id.as_str().to_owned(),
                        identifier: identifier.as_str().to_owned(),
                        payload: payload.as_str().to_owned(),
                    })
            })
            .collect()
    }
}

/// Check a Payment List against the rules discovery enforces when reading it.
///
/// Messages are static so they never echo caller data.
pub(crate) fn validate_endpoints(
    endpoints: &[PaymentEndpoint],
) -> Result<ValidatedList, &'static str> {
    if endpoints.is_empty() {
        return Err("expected at least one Payment Endpoint");
    }
    if endpoints.len() > MAX_ENDPOINTS {
        return Err("at most 256 Payment Endpoints are allowed");
    }
    let mut grouped: BTreeMap<&str, BTreeMap<&str, &str>> = BTreeMap::new();
    let mut total_bytes = 0usize;
    for endpoint in endpoints {
        PaykitAppId::new(endpoint.app_id.as_str()).map_err(|_| "invalid App ID")?;
        PaymentEndpointIdentifier::new(endpoint.identifier.as_str())
            .map_err(|_| "invalid Payment Endpoint Identifier")?;
        if endpoint.payload.is_empty() {
            return Err("Payment Endpoint payloads must not be empty");
        }
        if endpoint.payload.len() > PAYMENT_ENDPOINT_PAYLOAD_MAX_BYTES {
            return Err("a Payment Endpoint payload exceeds 64 KiB");
        }
        total_bytes += endpoint.payload.len();
        if grouped
            .entry(endpoint.app_id.as_str())
            .or_default()
            .insert(endpoint.identifier.as_str(), endpoint.payload.as_str())
            .is_some()
        {
            return Err("an App ID and Payment Endpoint Identifier pair is repeated");
        }
    }
    if total_bytes > MAX_PAYLOAD_BYTES {
        return Err("Payment Endpoint payloads exceed 4 MiB in total");
    }
    if grouped.len() > PAYKIT_APP_REGISTRY_MAX_APPS {
        return Err("at most 64 Apps are allowed");
    }
    let mut apps = Vec::with_capacity(grouped.len());
    for (app_id, endpoints) in grouped {
        let app_id = PaykitAppId::new(app_id).map_err(|_| "invalid App ID")?;
        let mut typed = Vec::with_capacity(endpoints.len());
        for (identifier, payload) in endpoints {
            let identifier = PaymentEndpointIdentifier::new(identifier)
                .map_err(|_| "invalid Payment Endpoint Identifier")?;
            typed.push((identifier, PaymentEndpointPayload::new(payload)));
        }
        apps.push((app_id, typed));
    }
    Ok(ValidatedList { apps })
}

/// Register every App in `list` that the registry does not list yet.
///
/// New Apps use their ID as the display name and advertise no capabilities.
/// Existing Apps, the Noise key, and every default are left unchanged.
/// Returns whether the registry changed.
pub(crate) fn register_missing_apps(
    registry: &mut PaykitAppRegistry,
    list: &ValidatedList,
) -> Result<bool, Error> {
    let missing: Vec<&PaykitAppId> = list
        .apps
        .iter()
        .map(|(app_id, _)| app_id)
        .filter(|app_id| !registry.apps().contains_key(*app_id))
        .collect();
    if registry.apps().len() + missing.len() > PAYKIT_APP_REGISTRY_MAX_APPS {
        return Err(Error::ResourceLimit);
    }
    let capabilities = PaykitAppCapabilities {
        private_payments: false,
        payment_requests: false,
        receipts: false,
        outgoing_payments: false,
    };
    for app_id in &missing {
        let app = PaykitApp::new(app_id.as_str(), capabilities).map_err(Error::Publish)?;
        registry
            .register_app((*app_id).clone(), app)
            .map_err(Error::Publish)?;
    }
    Ok(!missing.is_empty())
}

/// Sign in as the identity and publish an already validated list.
///
/// `document` is the serialized plaintext for encrypted mode, or `None` for
/// public mode. The session is signed out afterward on a best-effort basis.
pub(crate) async fn publish(
    pubky: &Pubky,
    secret: &Zeroizing<[u8; 32]>,
    list: &ValidatedList,
    document: Option<&[u8]>,
) -> Result<PublishedPaymentList, Error> {
    let keypair = Keypair::from_secret(secret);
    let owner = keypair.public_key();
    let client_id = ClientId::new(CLIENT_ID).expect("the static client ID is valid");
    let session = pubky
        .signer(keypair)
        .signin(client_id)
        .await
        .map_err(Error::Auth)?;
    let result = match document {
        Some(document) => publish_encrypted(&session, secret, &owner, document)
            .await
            .map(Some),
        None => publish_public(&session, &pubky.public_storage(), &owner, list)
            .await
            .map(|()| None),
    };
    // A failed sign-out leaves the session to expire; it never changes the result.
    let _ = session.signout().await;
    result.map(|access| PublishedPaymentList {
        pubky: owner.z32(),
        access,
    })
}

/// Publish an already validated list in public mode with the caller's session.
///
/// The session stays the caller's: it is borrowed and never signed out.
pub(crate) async fn publish_with_session(
    session: &PubkySession,
    storage: &PublicStorage,
    list: &ValidatedList,
) -> Result<PublishedPaymentList, Error> {
    let owner = session.public_key();
    publish_public(session, storage, &owner, list).await?;
    Ok(PublishedPaymentList {
        pubky: owner.z32(),
        access: None,
    })
}

/// Whether `capabilities` allow writing `path`, by Pubky's own scope rules.
pub(crate) fn can_write(capabilities: &[Capability], path: &str) -> bool {
    let Ok(path) = StoragePath::new(path) else {
        return false;
    };
    capabilities.iter().any(|capability| {
        capability.actions().contains(&Action::Write) && capability.scope_covers_path(&path)
    })
}

fn require_write(capabilities: &[Capability], path: &str) -> Result<(), Error> {
    if can_write(capabilities, path) {
        Ok(())
    } else {
        Err(Error::SessionScope)
    }
}

fn endpoint_path(app_id: &PaykitAppId, identifier: &PaymentEndpointIdentifier) -> String {
    format!("{}{}", endpoint_prefix(app_id), identifier.as_str())
}

fn is_auth_failure(error: &pubky::Error) -> bool {
    match error {
        pubky::Error::Authentication(_) => true,
        pubky::Error::Request(pubky::errors::RequestError::Server { status, .. }) => {
            *status == StatusCode::UNAUTHORIZED || *status == StatusCode::FORBIDDEN
        }
        _ => false,
    }
}

/// Report a write the homeserver refused as [`Error::Auth`], not a transport failure.
pub(crate) fn write_error(error: PaykitError) -> Error {
    match error {
        PaykitError::Transport { context, source } => match source.downcast::<pubky::Error>() {
            Ok(error) if is_auth_failure(&error) => Error::Auth(error),
            Ok(error) => Error::Publish(PaykitError::Transport {
                context,
                source: error.into(),
            }),
            Err(source) => Error::Publish(PaykitError::Transport { context, source }),
        },
        error => Error::Publish(error),
    }
}

async fn publish_public(
    session: &PubkySession,
    storage: &PublicStorage,
    owner: &PublicKey,
    list: &ValidatedList,
) -> Result<(), Error> {
    // Fail before any write when a scoped session cannot finish the job.
    let info = session.info();
    let capabilities = info.capabilities();
    for (app_id, endpoints) in &list.apps {
        for (identifier, _) in endpoints {
            require_write(capabilities, &endpoint_path(app_id, identifier))?;
        }
    }

    // Register Apps first so every endpoint written below is discoverable.
    // paykit-lib checks the registry revision under a write lock, so a
    // concurrent registry change fails instead of being overwritten.
    match paykit_lib::get_paykit_app_registry_with_revision(storage, owner)
        .await
        .map_err(Error::Publish)?
    {
        None => {
            let mut registry = PaykitAppRegistry::new(None);
            register_missing_apps(&mut registry, list)?;
            require_write(capabilities, PAYKIT_APP_REGISTRY_PATH)?;
            paykit_lib::create_paykit_app_registry(session, &registry)
                .await
                .map_err(write_error)?;
        }
        Some((mut registry, revision)) => {
            if register_missing_apps(&mut registry, list)? {
                require_write(capabilities, PAYKIT_APP_REGISTRY_PATH)?;
                paykit_lib::update_paykit_app_registry(session, &registry, &revision)
                    .await
                    .map_err(write_error)?;
            }
        }
    }

    // Replace each named App's endpoints; Apps not in the list are untouched.
    for (app_id, endpoints) in &list.apps {
        let existing = paykit_lib::list_payment_endpoint_identifiers(storage, owner, app_id)
            .await
            .map_err(Error::Publish)?;
        let stale: Vec<_> = existing
            .into_iter()
            .filter(|identifier| !endpoints.iter().any(|(kept, _)| kept == identifier))
            .collect();
        for identifier in &stale {
            require_write(capabilities, &endpoint_path(app_id, identifier))?;
        }
        for (identifier, payload) in endpoints {
            paykit_lib::set_payment_endpoint(session, app_id, identifier.clone(), payload.clone())
                .await
                .map_err(write_error)?;
        }
        for identifier in stale {
            paykit_lib::remove_payment_endpoint(session, app_id, identifier)
                .await
                .map_err(write_error)?;
        }
    }
    Ok(())
}

async fn publish_encrypted(
    session: &PubkySession,
    secret: &[u8; 32],
    owner: &PublicKey,
    document: &[u8],
) -> Result<String, Error> {
    let id = encrypted::new_document_id();
    let path = encrypted::document_path(&id);
    let key = encrypted::derive_key(secret, &path)
        .ok_or(Error::InvalidInput("could not derive the encryption key"))?;
    let nonce = pubky_common::crypto::random_bytes::<12>();
    let sealed = encrypted::seal(&key, &nonce, owner, &path, document)?;
    // Create-only: an existing document at this path is never overwritten.
    paykit_lib::put_resource_if_revision(session, &path, sealed, None, encrypted::MAX_SEALED_BYTES)
        .await
        .map_err(write_error)?;
    Ok(encrypted::format_access(&id, &key))
}
