//! Identity secret parsing shared by the publishing functions.
//!
//! Pubky Ring and `pubky-core-ffi` turn a BIP39 English mnemonic into an
//! identity with `Mnemonic::to_seed("")` (no BIP39 passphrase) and use the first
//! 32 bytes of the 64-byte seed as the Ed25519 secret. Raw secrets are the same
//! 32 bytes written as hex. Matching both keeps a mnemonic and its hex secret on
//! the same Pubky.

use bip39::{Language, Mnemonic};
use zeroize::Zeroizing;

use crate::Error;

/// Parse a BIP39 English mnemonic or a 64-character hex identity secret.
///
/// Whitespace runs collapse to one space and ASCII letters are lowercased, so
/// pasted phrases with line breaks or capitals resolve to the same identity.
/// Every intermediate copy is zeroized; errors never include the input.
pub(crate) fn parse_secret(input: &str) -> Result<Zeroizing<[u8; 32]>, Error> {
    let mut normalized = Zeroizing::new(String::with_capacity(input.len()));
    for word in input.split_whitespace() {
        if !normalized.is_empty() {
            normalized.push(' ');
        }
        normalized.push_str(word);
    }
    normalized.make_ascii_lowercase();

    let mut secret = Zeroizing::new([0u8; 32]);
    if normalized.len() == 64 && normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        hex::decode_to_slice(normalized.as_bytes(), secret.as_mut())
            .map_err(|_| Error::InvalidSecret)?;
        return Ok(secret);
    }

    // bip39's `zeroize` feature clears the parsed word indices on drop.
    let mnemonic = Mnemonic::parse_in(Language::English, normalized.as_str())
        .map_err(|_| Error::InvalidSecret)?;
    let seed = Zeroizing::new(mnemonic.to_seed(""));
    secret.copy_from_slice(&seed[..32]);
    Ok(secret)
}
