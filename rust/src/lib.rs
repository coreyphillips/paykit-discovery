//! Get and set a Pubky identity's Paykit Payment Endpoints.
//!
//! [`get_payment_list`] reads public Payment Endpoints. It needs no account,
//! session, private key, or Paykit SDK configuration. [`set_payment_list`]
//! publishes a Payment List from the identity's BIP39 mnemonic or hex secret,
//! either as public Paykit endpoints or as one encrypted document that
//! [`get_encrypted_payment_list`] opens with the returned access string.
//!
//! The wallet interprets and validates each opaque payload before paying it.
//! This crate does not handle Paykit Private Payment Lists or execute payments.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::{HashMap, HashSet};

use paykit_lib::{PaykitAppId, PaykitAppRegistry, PaymentEndpointIdentifier, PaymentList};
use pubky::{PubkyResource, PublicKey, PublicStorage};

mod encrypted;
mod publish;
mod secret;

const MAX_ENDPOINTS: usize = 256;
const MAX_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
const MAX_REQUESTS: usize = 512;
const PAGE_SIZE: u16 = 100;
const Z32_ALPHABET: &[u8] = b"ybndrfg8ejkmcpqxot1uwisza345h769";

/// One public Payment Endpoint published by one Paykit App.
///
/// Different Apps may publish the same identifier. Keep `app_id` with the
/// endpoint when displaying or selecting it; never deduplicate by identifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PaymentEndpoint {
    /// Paykit App that published these receiving details, for example `bitkit`.
    pub app_id: String,
    /// Payment Endpoint Identifier, for example `btc-lightning-bolt12`.
    pub identifier: String,
    /// Opaque UTF-8 receiving details. The wallet must validate this payload.
    pub payload: String,
}

/// A lookup or publishing failure. No partial Payment List is returned on error.
///
/// Messages never include a secret, mnemonic, or access key.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The input is not a bare Pubky identity in a supported form.
    #[error("expected a Pubky public key, pubky<key>, or pubky://<key> without a resource path")]
    InvalidPubky,
    /// The secret is not a BIP39 English mnemonic or a 64-character hex identity secret.
    #[error("expected a BIP39 English mnemonic or a 64-character hex identity secret")]
    InvalidSecret,
    /// The Payment Endpoints or the access string are invalid.
    #[error("invalid input: {0}")]
    InvalidInput(&'static str),
    /// Signing in failed, for example because the identity has no homeserver.
    #[error("could not sign in to the identity's homeserver: {0}")]
    Auth(#[source] pubky::Error),
    /// Reading the current state or writing the Payment List failed.
    ///
    /// A concurrent App Registry change also lands here; read again and retry.
    #[error("could not publish the Payment List: {0}")]
    Publish(#[source] paykit_lib::PaykitError),
    /// The default Pubky client could not be initialized.
    #[error("could not initialize Pubky: {0}")]
    Client(#[source] pubky::Error),
    /// Public discovery failed, returned invalid data, or exceeded resource limits.
    #[error("could not retrieve the Payment List: {0}")]
    Discovery(#[from] paykit_lib::PaykitError),
    /// The lookup exceeded its endpoint, request, or payload budget.
    #[error("Payment List exceeds the discovery resource limits")]
    ResourceLimit,
}

/// Get all public Payment Endpoints advertised by a Pubky identity.
///
/// Accepts a lowercase z-base-32 public key, `pubky<key>`, or `pubky://<key>`.
/// Surrounding whitespace is ignored; paths, queries, and fragments are rejected.
/// Run this async function inside a Tokio runtime.
///
/// The identity-wide Paykit App Registry determines which Apps are read. Results
/// retain every App's endpoints and place the registry's preferred App for each
/// identifier first, followed by deterministic App ID and identifier ordering.
/// An absent registry or absent endpoint directories produce an empty vector.
/// Empty endpoint files and files removed during discovery are omitted.
///
/// Reads are a best-effort snapshot, not an atomic view. Up to 256 endpoint
/// attempts, 4 MiB of endpoint payloads, and 512 listing/endpoint requests are
/// allowed across all Apps. The canonical Paykit Library enforces per-document
/// and registry limits. These are accepted-data limits: Pubky buffers listing
/// responses before validation, and one endpoint can be read before an aggregate
/// byte-limit failure. This function uses Pubky's default transport settings;
/// it adds no deadline. Applications can cancel or time-limit the returned future.
/// No session or capabilities are needed; identity and key management remain
/// the application's responsibility.
///
/// # Errors
///
/// Returns [`Error::InvalidPubky`] before any network access for invalid input.
/// Client initialization, transport, invalid remote data, and resource limits
/// return errors. A failed App lookup fails the complete call, so an incomplete
/// lookup is never reported as an empty or complete Payment List.
///
/// # Examples
///
/// ```no_run
/// use paykit_discovery::get_payment_list;
///
/// # async fn example() -> Result<(), paykit_discovery::Error> {
/// let payments = get_payment_list(
///     "pubky5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo",
/// ).await?;
/// for payment in payments {
///     println!("{}: {}", payment.app_id, payment.identifier);
///     // Validate payment.payload with the wallet's implementation of this identifier.
/// }
/// # Ok(())
/// # }
/// ```
pub async fn get_payment_list(pubky: &str) -> Result<Vec<PaymentEndpoint>, Error> {
    let owner = parse_identity(pubky)?;
    let storage = pubky::PublicStorage::new().map_err(Error::Client)?;
    discover(&storage, &owner).await
}

async fn discover(
    storage: &PublicStorage,
    owner: &PublicKey,
) -> Result<Vec<PaymentEndpoint>, Error> {
    let Some(registry) = paykit_lib::get_paykit_app_registry(storage, owner).await? else {
        return Ok(Vec::new());
    };

    // Only registered, validated App IDs reach the canonical path builders.
    // Keep one budget across Apps so a publisher cannot multiply the work limit.
    let mut app_ids: Vec<_> = registry.apps().keys().collect();
    app_ids.sort_by(|a, b| a.as_str().cmp(b.as_str()));
    let mut budget = Budget::default();
    let mut endpoints = Vec::new();
    for app_id in app_ids {
        let list = read_app_payment_list(storage, owner, app_id, &mut budget).await?;
        append_payment_list(&mut endpoints, &registry, app_id, list);
    }
    Ok(order_endpoints(endpoints))
}

/// What [`set_payment_list`] published.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublishedPaymentList {
    /// The identity that owns the list, as a bare z-base-32 public key.
    pub pubky: String,
    /// `None` for public mode. In encrypted mode, the access string to give to
    /// the people who may read the list. It contains the decryption key.
    pub access: Option<String>,
}

/// Publish a Payment List as the identity behind `secret`.
///
/// `secret` is a BIP39 English mnemonic or the 32-byte identity secret as
/// 64 hex characters. A mnemonic resolves the way Pubky Ring does: the first
/// 32 bytes of its BIP39 seed (no passphrase) are the identity secret.
/// Whitespace and letter case in the phrase are normalized. The identity must
/// already have a homeserver; this function signs in but never signs up.
///
/// With `encrypted == false`, every App in `endpoints` is added to the Paykit
/// App Registry if missing, each endpoint is written to its public Paykit path,
/// and that App's other published endpoints are removed. Apps not named in
/// `endpoints` are untouched. [`get_payment_list`] then returns the records.
///
/// With `encrypted == true`, nothing public changes. The whole list is written
/// as one AES-256-GCM document at a new random path under
/// `/pub/paykit-discovery/v1/encrypted/`, keyed with the Pubky hierarchical
/// key for that path. The result's `access` string opens it with
/// [`get_encrypted_payment_list`]. Every call creates a new document with its
/// own path and key, so each recipient can get their own list. Earlier
/// documents stay readable to anyone holding their access strings.
///
/// Endpoints use the same rules discovery enforces: 1 to 256 records, App IDs
/// of lowercase letters, digits, and `-`, valid Payment Endpoint Identifiers,
/// non-empty payloads of at most 64 KiB (4 MiB in total), at most 64 Apps, and
/// no repeated App ID and identifier pair. Run this inside a Tokio runtime.
///
/// # Errors
///
/// Returns [`Error::InvalidSecret`] or [`Error::InvalidInput`] before any
/// network access. Sign-in failures return [`Error::Auth`], and failed reads,
/// writes, or a concurrent App Registry change return [`Error::Publish`]. The
/// call is not atomic: after an error some writes may have landed, and calling
/// again with the same arguments is safe.
///
/// # Examples
///
/// ```no_run
/// use paykit_discovery::{get_encrypted_payment_list, set_payment_list, PaymentEndpoint};
///
/// # async fn example(mnemonic: &str) -> Result<(), paykit_discovery::Error> {
/// let endpoints = [PaymentEndpoint {
///     app_id: "my-wallet".into(),
///     identifier: "btc-lightning-bolt11".into(),
///     payload: "lnbc1...".into(),
/// }];
/// let published = set_payment_list(mnemonic, &endpoints, true).await?;
/// let access = published.access.expect("encrypted mode returns an access string");
/// let payments = get_encrypted_payment_list(&published.pubky, &access).await?;
/// assert_eq!(payments, endpoints);
/// # Ok(())
/// # }
/// ```
pub async fn set_payment_list(
    secret: &str,
    endpoints: &[PaymentEndpoint],
    encrypted: bool,
) -> Result<PublishedPaymentList, Error> {
    let secret = secret::parse_secret(secret)?;
    let list = publish::validate_endpoints(endpoints).map_err(Error::InvalidInput)?;
    let document = if encrypted {
        Some(encrypted::serialize_document(&list.endpoints())?)
    } else {
        None
    };
    let pubky = pubky::Pubky::new().map_err(Error::Client)?;
    publish::publish(&pubky, &secret, &list, document.as_deref()).await
}

/// Open an encrypted Payment List published by [`set_payment_list`].
///
/// `pubky` accepts the same forms as [`get_payment_list`]. `access` is the
/// string returned by the encrypted publish. No login is needed. A missing
/// document returns an empty vector. Endpoints are sorted by App ID and
/// identifier. Run this inside a Tokio runtime.
///
/// # Errors
///
/// Returns [`Error::InvalidPubky`] or [`Error::InvalidInput`] before any
/// network access. A wrong access string, a document moved to another path or
/// identity, tampering, or a malformed document returns [`Error::Discovery`]
/// with invalid data. Transport failures and oversized documents also fail.
pub async fn get_encrypted_payment_list(
    pubky: &str,
    access: &str,
) -> Result<Vec<PaymentEndpoint>, Error> {
    let owner = parse_identity(pubky)?;
    let access = encrypted::parse_access(access)?;
    let storage = pubky::PublicStorage::new().map_err(Error::Client)?;
    encrypted::read(&storage, &owner, &access).await
}

fn parse_identity(input: &str) -> Result<PublicKey, Error> {
    let input = input.trim();
    let raw = if input.len() == 52 {
        input
    } else {
        input
            .strip_prefix("pubky://")
            .or_else(|| input.strip_prefix("pubky"))
            .unwrap_or(input)
    };
    if raw.len() != 52 || !raw.bytes().all(|byte| Z32_ALPHABET.contains(&byte)) {
        return Err(Error::InvalidPubky);
    }
    let key = PublicKey::try_from_z32(raw).map_err(|_| Error::InvalidPubky)?;
    // The underlying parser also accepts URL forms and may normalize encodings.
    // Never silently reinterpret a pasted resource URL or a noncanonical key.
    if key.z32() != raw {
        return Err(Error::InvalidPubky);
    }
    Ok(key)
}

struct Budget {
    endpoints: usize,
    requests: usize,
    bytes: usize,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            endpoints: MAX_ENDPOINTS,
            requests: MAX_REQUESTS,
            bytes: MAX_PAYLOAD_BYTES,
        }
    }
}

impl Budget {
    fn request(&mut self) -> Result<(), Error> {
        self.requests = self.requests.checked_sub(1).ok_or(Error::ResourceLimit)?;
        Ok(())
    }

    fn endpoint(&mut self) -> Result<(), Error> {
        self.endpoints = self.endpoints.checked_sub(1).ok_or(Error::ResourceLimit)?;
        self.request()
    }

    fn payload(&mut self, bytes: usize) -> Result<(), Error> {
        self.bytes = self.bytes.checked_sub(bytes).ok_or(Error::ResourceLimit)?;
        Ok(())
    }
}

fn endpoint_prefix(app_id: &PaykitAppId) -> String {
    // Paykit's concrete per-App helper is private. Build its published layout
    // from the canonical public prefix and a constructor-validated App ID.
    format!(
        "{}apps/{}/endpoints/",
        paykit_lib::PAYKIT_PATH_PREFIX,
        app_id.as_str()
    )
}

fn invalid_data(message: &str) -> Error {
    paykit_lib::PaykitError::InvalidData {
        context: message.to_owned(),
        source: None,
    }
    .into()
}

fn listing_error(error: pubky::Error) -> Error {
    match error {
        pubky::Error::Parse(_)
        | pubky::Error::Request(pubky::errors::RequestError::Validation { .. }) => {
            paykit_lib::PaykitError::InvalidData {
                context: "invalid public Payment Endpoint listing".into(),
                source: Some(error.into()),
            }
        }
        _ => paykit_lib::PaykitError::Transport {
            context: "list public Payment Endpoints".into(),
            source: error.into(),
        },
    }
    .into()
}

fn is_missing(error: &pubky::Error) -> bool {
    matches!(error, pubky::Error::Request(pubky::errors::RequestError::Server { status, .. })
        if *status == pubky::StatusCode::NOT_FOUND || *status == pubky::StatusCode::GONE)
}

fn listed_identifier(
    resource: &PubkyResource,
    owner: &PublicKey,
    prefix: &str,
) -> Result<Option<PaymentEndpointIdentifier>, Error> {
    // A directory listing is untrusted. A different owner or App must never be
    // relabeled as the requested payee. Fetch only reconstructed canonical paths.
    if resource.owner != *owner {
        return Err(invalid_data(
            "listing entry belongs to a different Pubky identity",
        ));
    }
    let suffix = resource
        .path
        .as_str()
        .strip_prefix(prefix)
        .ok_or_else(|| invalid_data("listing entry is outside the requested Paykit App"))?;
    let name = suffix.strip_suffix('/').unwrap_or(suffix);
    if name.is_empty() || name.contains('/') {
        return Err(invalid_data(
            "listing entry is not a direct child of the endpoint directory",
        ));
    }
    let identifier = PaymentEndpointIdentifier::new(name)
        .map_err(|_| invalid_data("listing returned an invalid Payment Endpoint Identifier"))?;
    Ok((!suffix.ends_with('/')).then_some(identifier))
}

fn advance_cursor(cursor: &mut Option<String>, resource: &PubkyResource) -> Result<(), Error> {
    let next = format!("{}{}", resource.owner.z32(), resource.path.as_str());
    if cursor.as_ref().is_some_and(|previous| next <= *previous) {
        return Err(invalid_data(
            "listing resources are repeated or out of order",
        ));
    }
    *cursor = Some(next);
    Ok(())
}

async fn read_app_payment_list(
    storage: &PublicStorage,
    owner: &PublicKey,
    app_id: &PaykitAppId,
    budget: &mut Budget,
) -> Result<PaymentList, Error> {
    let prefix = endpoint_prefix(app_id);
    let address = format!("{owner}{prefix}");
    let mut cursor = None::<String>;
    let mut seen = HashSet::new();
    let mut identifiers = Vec::new();
    loop {
        let mut request = storage
            .list(&address)
            .map_err(listing_error)?
            .shallow(true)
            .limit(PAGE_SIZE);
        if let Some(cursor) = &cursor {
            request = request.cursor(cursor);
        }
        budget.request()?;
        let page = match request.send().await {
            Ok(page) => page,
            Err(error) if is_missing(&error) => break,
            Err(error) => return Err(listing_error(error)),
        };
        if page.len() > usize::from(PAGE_SIZE) || seen.len() + page.len() > MAX_ENDPOINTS {
            return Err(Error::ResourceLimit);
        }
        for resource in &page {
            if let Some(identifier) = listed_identifier(resource, owner, &prefix)? {
                identifiers.push(identifier);
            }
            if !seen.insert(resource.path.as_str().to_owned()) {
                return Err(invalid_data("listing repeated a resource"));
            }
            advance_cursor(&mut cursor, resource)?;
        }
        if page.len() < usize::from(PAGE_SIZE) {
            break;
        }
    }

    let mut payment_endpoints = HashMap::new();
    for identifier in identifiers {
        budget.endpoint()?;
        if let Some(payload) =
            paykit_lib::get_payment_endpoint(storage, owner, app_id, &identifier).await?
        {
            budget.payload(payload.as_str().len())?;
            payment_endpoints.insert(identifier, payload);
        }
    }
    Ok(PaymentList { payment_endpoints })
}

fn append_payment_list(
    endpoints: &mut Vec<(bool, PaymentEndpoint)>,
    registry: &PaykitAppRegistry,
    app_id: &PaykitAppId,
    list: PaymentList,
) {
    endpoints.extend(
        list.payment_endpoints
            .into_iter()
            .map(|(identifier, payload)| {
                let nonpreferred = registry.preferred_app_for_endpoint(&identifier) != Some(app_id);
                (
                    nonpreferred,
                    PaymentEndpoint {
                        app_id: app_id.as_str().to_owned(),
                        identifier: identifier.as_str().to_owned(),
                        payload: payload.into_inner(),
                    },
                )
            }),
    );
}

fn order_endpoints(mut endpoints: Vec<(bool, PaymentEndpoint)>) -> Vec<PaymentEndpoint> {
    endpoints.sort_by(|(rank_a, a), (rank_b, b)| {
        (rank_a, &a.app_id, &a.identifier).cmp(&(rank_b, &b.app_id, &b.identifier))
    });
    endpoints
        .into_iter()
        .map(|(_, endpoint)| endpoint)
        .collect()
}

#[cfg(test)]
mod tests;
