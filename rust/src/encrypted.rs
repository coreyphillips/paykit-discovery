//! Encrypted Payment List documents.
//!
//! This is a format specific to this package, not a Paykit Private Payment List.
//! Each document lives at `/pub/paykit-discovery/v1/encrypted/{id}`, where `id` is
//! 128 random bits written as lowercase hex. Its AES-256-GCM key is the Pubky
//! hierarchical keys v1 file key for that path, derived from the owner's identity
//! secret with `pubky-common`. The stored bytes are a 12-byte nonce followed by the
//! ciphertext and tag. The associated data is `pubky://{owner z32}{path}`, so a
//! document copied to another owner or path fails authentication.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Key, Nonce,
};
use pubky::{PublicKey, PublicStorage, StoragePath};
use pubky_common::encryption_keys::ScopedEncryptionKeyBundle;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{invalid_data, is_missing, publish::validate_endpoints, Error, PaymentEndpoint};

/// Directory that holds encrypted Payment List documents.
pub(crate) const ENCRYPTED_PATH_PREFIX: &str = "/pub/paykit-discovery/v1/encrypted/";
const DOCUMENT_VERSION: u8 = 1;
const DOCUMENT_KIND: &str = "paykit-discovery.encrypted_payment_list";
const ACCESS_PREFIX: &str = "v1.";
const NONCE_BYTES: usize = 12;
const TAG_BYTES: usize = 16;
/// Largest serialized plaintext document.
pub(crate) const MAX_DOCUMENT_BYTES: usize = 4 * 1024 * 1024;
/// Largest stored document: nonce, ciphertext, and tag.
pub(crate) const MAX_SEALED_BYTES: usize = NONCE_BYTES + MAX_DOCUMENT_BYTES + TAG_BYTES;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DocumentWire {
    version: u8,
    kind: String,
    endpoints: Vec<EndpointWire>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EndpointWire {
    app_id: String,
    identifier: String,
    payload: String,
}

/// A parsed access string: the document ID and its content key.
pub(crate) struct Access {
    pub(crate) id: String,
    pub(crate) key: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for Access {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Access")
            .field("id", &self.id)
            .field("key", &"<redacted>")
            .finish()
    }
}

/// Parse `v1.{32 hex id}.{64 hex key}`. Surrounding whitespace is ignored.
pub(crate) fn parse_access(input: &str) -> Result<Access, Error> {
    let invalid = || Error::InvalidInput("expected an encrypted Payment List access string");
    let (id, key_hex) = input
        .trim()
        .strip_prefix(ACCESS_PREFIX)
        .and_then(|rest| rest.split_once('.'))
        .ok_or_else(invalid)?;
    if !is_lower_hex(id, 32) || !is_lower_hex(key_hex, 64) {
        return Err(invalid());
    }
    let mut key = Zeroizing::new([0u8; 32]);
    hex::decode_to_slice(key_hex, key.as_mut()).map_err(|_| invalid())?;
    Ok(Access {
        id: id.to_owned(),
        key,
    })
}

/// Format the access string returned to the publisher.
pub(crate) fn format_access(id: &str, key: &[u8; 32]) -> String {
    let key_hex = Zeroizing::new(hex::encode(key));
    format!("{ACCESS_PREFIX}{id}.{}", key_hex.as_str())
}

fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// A fresh 128-bit document ID, so every call gets its own path and key.
pub(crate) fn new_document_id() -> String {
    hex::encode(pubky_common::crypto::random_bytes::<16>())
}

/// The storage path of one encrypted document.
pub(crate) fn document_path(id: &str) -> String {
    format!("{ENCRYPTED_PATH_PREFIX}{id}")
}

/// Derive the Pubky hierarchical keys v1 file key for a canonical file path.
pub(crate) fn derive_key(secret: &[u8; 32], path: &str) -> Option<Zeroizing<[u8; 32]>> {
    let path = StoragePath::new(path).ok()?;
    ScopedEncryptionKeyBundle::from_identity_secret(secret, [&path])
        .derive_for_path(&path)
        .ok()
}

/// Serialize sorted endpoints as the versioned plaintext document.
pub(crate) fn serialize_document(endpoints: &[PaymentEndpoint]) -> Result<Vec<u8>, Error> {
    let document = DocumentWire {
        version: DOCUMENT_VERSION,
        kind: DOCUMENT_KIND.to_owned(),
        endpoints: endpoints
            .iter()
            .map(|endpoint| EndpointWire {
                app_id: endpoint.app_id.clone(),
                identifier: endpoint.identifier.clone(),
                payload: endpoint.payload.clone(),
            })
            .collect(),
    };
    let bytes = serde_json::to_vec(&document)
        .map_err(|_| Error::InvalidInput("could not serialize the Payment List"))?;
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(Error::InvalidInput(
            "the encrypted Payment List document exceeds 4 MiB",
        ));
    }
    Ok(bytes)
}

/// Parse and validate a decrypted document. Endpoints come back sorted.
pub(crate) fn parse_document(bytes: &[u8]) -> Result<Vec<PaymentEndpoint>, Error> {
    let invalid = || invalid_data("the encrypted Payment List document is malformed");
    let document: DocumentWire = serde_json::from_slice(bytes).map_err(|_| invalid())?;
    if document.version != DOCUMENT_VERSION || document.kind != DOCUMENT_KIND {
        return Err(invalid());
    }
    let endpoints: Vec<PaymentEndpoint> = document
        .endpoints
        .into_iter()
        .map(|endpoint| PaymentEndpoint {
            app_id: endpoint.app_id,
            identifier: endpoint.identifier,
            payload: endpoint.payload,
        })
        .collect();
    let list = validate_endpoints(&endpoints).map_err(|_| invalid())?;
    Ok(list.endpoints())
}

fn associated_data(owner: &PublicKey, path: &str) -> String {
    format!("pubky://{}{path}", owner.z32())
}

/// Encrypt a document for `owner` at `path` with an explicit nonce.
pub(crate) fn seal(
    key: &[u8; 32],
    nonce: &[u8; NONCE_BYTES],
    owner: &PublicKey,
    path: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, Error> {
    let aad = associated_data(owner, path);
    let ciphertext = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| Error::InvalidInput("could not encrypt the Payment List"))?;
    let mut sealed = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
    sealed.extend_from_slice(nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

/// Decrypt a stored document. A wrong key, owner, or path, or any tampering, fails.
pub(crate) fn open(
    key: &[u8; 32],
    owner: &PublicKey,
    path: &str,
    sealed: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    if sealed.len() < NONCE_BYTES + TAG_BYTES {
        return Err(invalid_data(
            "the encrypted Payment List document is truncated",
        ));
    }
    let (nonce, ciphertext) = sealed.split_at(NONCE_BYTES);
    let aad = associated_data(owner, path);
    Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key))
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: aad.as_bytes(),
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| {
            invalid_data(
                "the encrypted Payment List could not be authenticated with this access string",
            )
        })
}

/// Read, authenticate, and parse one encrypted document. Absence is [`Error::NotFound`].
pub(crate) async fn read(
    storage: &PublicStorage,
    owner: &PublicKey,
    access: &Access,
) -> Result<Vec<PaymentEndpoint>, Error> {
    let path = document_path(&access.id);
    let mut response = storage
        .get(format!("{owner}{path}"))
        .await
        .map_err(read_error)?;
    if response
        .content_length()
        .is_some_and(|length| length > MAX_SEALED_BYTES as u64)
    {
        return Err(Error::ResourceLimit);
    }
    let mut sealed = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(transport)? {
        if sealed.len() + chunk.len() > MAX_SEALED_BYTES {
            return Err(Error::ResourceLimit);
        }
        sealed.extend_from_slice(&chunk);
    }
    let plaintext = open(&access.key, owner, &path, &sealed)?;
    parse_document(&plaintext)
}

/// Map a failed read. Missing is an error here: an access string means a list should exist.
pub(crate) fn read_error(error: pubky::Error) -> Error {
    if is_missing(&error) {
        Error::NotFound
    } else {
        transport(error)
    }
}

fn transport<E: std::error::Error + Send + Sync + 'static>(source: E) -> Error {
    paykit_lib::PaykitError::Transport {
        context: "read the encrypted Payment List".into(),
        source: source.into(),
    }
    .into()
}
