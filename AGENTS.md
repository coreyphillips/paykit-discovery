# Paykit Discovery

This project gets and sets Paykit Payment Endpoints for a Pubky identity. Keep
the integration small: in TypeScript, `getPaymentList(pubky, access?)` and
`setPaymentList(secret, paymentDetails, encrypted?)`; in Rust,
`get_payment_list(pubky)`, `get_encrypted_payment_list(pubky, access)`, and
`set_payment_list(secret, endpoints, encrypted)`.

- Return an array/vector of endpoint records. Preserve the publishing App ID,
  Payment Endpoint Identifier, and opaque UTF-8 Payment Endpoint Payload.
- Identifiers are open strings. `Identifier` and `identifiers` only name common
  values; never reject or drop an endpoint because its identifier is unlisted.
  Keep both lists equal to `known_identifiers` in `fixtures/discovery.json`.
- Discovery does not require a login, identity secret, database, Encrypted
  Link, or payment execution adapter. Only the set functions take a secret.
- A secret is a BIP39 English mnemonic or a 32-byte identity secret (64 hex
  characters, or bytes in TypeScript). Resolve mnemonics as Pubky Ring does
  (`pubky-core-ffi`): the first 32 bytes of the BIP39 seed with no passphrase.
  Never log secrets, mnemonics, derived keys, or access keys, or put them in
  error messages or causes. Zero derived buffers when done.
- Missing public data is empty. A missing encrypted document is an error,
  because an access string means a list should exist. Network, malformed-data,
  and resource-limit failures are errors; never return a silently incomplete
  list. A failed set rejects even if some writes landed.
- Discover Apps through the identity-wide Paykit App Registry. Never merge
  endpoints from different Apps by identifier alone. Public sets register
  missing Apps, preserve every other registry field, refuse to overwrite a
  malformed or concurrently changed registry, and replace only the named
  Apps' endpoints.
- Encrypted Payment Lists are this package's own format, not Paykit Private
  Payment Lists. Each document lives at a new random path under
  `/pub/paykit-discovery/v1/encrypted/`, uses AES-256-GCM with the Pubky
  hierarchical keys v1 file key for that path, and binds the owner and path as
  associated data. Keep them out of Paykit's reserved paths.
- Keep Rust and TypeScript behavior aligned, including the shared fixtures in
  `fixtures/`. Wire formats (App Registry writes, encrypted documents, access
  strings) must match byte for byte.
- Rust uses the canonical `paykit-lib` APIs and `pubky-common` key derivation.
  TypeScript uses the official `@synonymdev/pubky` SDK, WebCrypto, and
  `@scure/bip39`, and follows the same Paykit wire format.
- Do not add alternate network backends, private messaging, payment execution,
  signup, or wallet-specific payload interpretation to this package.
- Keep package examples runnable and distinguish GitHub installation from
  unpublished npm/crates.io packages.
- Commit generated `typescript/dist` files with their source changes. GitHub
  installs must work without install scripts or a TypeScript compiler; CI
  checks that the generated output is current.

Run `npm ci`, `npm run check`, `npm test`, and `npm run build` for TypeScript.
Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
`cargo test --workspace`, and `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`
for Rust.
