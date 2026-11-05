# Paykit Discovery

**A Pubky identity in, payment details out. A mnemonic in, payment details published.**

Discover every public Payment Endpoint published by the registered Paykit Apps
on a Pubky identity, with no sign-in, private key, database, or SDK setup.
Publish your own Payment Endpoints from your Pubky mnemonic or secret, either
publicly or as an encrypted list that you share with an access string.

## TypeScript

Install from GitHub with Node.js 22 or newer:

```sh
npm install github:coreyphillips/paykit-discovery
```

Compiled JavaScript and type declarations are included; installation does not
run build scripts or require a TypeScript compiler.

```ts
import { getPaymentList } from "@coreyphillips/paykit-discovery";

const payments = await getPaymentList(recipientPubky);
// [{ appId: "bitkit", identifier: "btc-lightning-bolt12", payload: "lno1..." }]
```

The result is a plain array:

```ts
type PaymentEndpoint = {
  appId: string;
  identifier: string;
  payload: string;
};
```

### Publish your payment details

```ts
import { getPaymentList, setPaymentList } from "@coreyphillips/paykit-discovery";

const details = [
  { appId: "my-wallet", identifier: "btc-lightning-bolt12", payload: "lno1..." },
  { appId: "my-wallet", identifier: "btc-bitcoin-p2tr", payload: "bc1p..." },
];

// Public: anyone can discover these with getPaymentList(pubky).
const { pubky } = await setPaymentList(mnemonic, details);

// Encrypted: share `access` with whoever should read this list. Your own
// mnemonic and Pubky apps granted `e` on this path can also decrypt it.
const result = await setPaymentList(mnemonic, details, true);
const shared = await getPaymentList(result.pubky, result.access);
```

The secret is a BIP39 English mnemonic, the 32-byte identity secret as 64 hex
characters, or those 32 bytes as a `Uint8Array`. The identity must already
have a homeserver (for example, one created in Pubky Ring).

```ts
type SetPaymentListResult =
  | { pubky: string; encrypted: false }
  | { pubky: string; encrypted: true; access: string };
```

Use it in Node.js or a browser application with an ESM-capable bundler. Pubky's
JavaScript SDK provides the underlying WebAssembly and public storage client.
React Native is not a tested target for this package.

## Rust

With Rust 1.91.1 or newer, add the GitHub dependency and Tokio to your
application's `Cargo.toml`:

```toml
[dependencies]
paykit-discovery = { git = "https://github.com/coreyphillips/paykit-discovery" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust,no_run
use paykit_discovery::get_payment_list;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let recipient_pubky = std::env::args().nth(1).expect("provide a Pubky identity");
    let payments = get_payment_list(&recipient_pubky).await?;
    for payment in payments {
        println!("{} {} {}", payment.app_id, payment.identifier, payment.payload);
    }
    Ok(())
}
```

The result is `Vec<PaymentEndpoint>`, with public `String` fields `app_id`,
`identifier`, and `payload`. Run it inside a Tokio runtime. Rust is a native
library; use the TypeScript package for browser applications.

Publishing takes a mnemonic or 64-character hex secret:

```rust,no_run
use paykit_discovery::{get_encrypted_payment_list, set_payment_list, PaymentEndpoint};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mnemonic = std::env::var("PUBKY_MNEMONIC")?;
    let details = [PaymentEndpoint {
        app_id: "my-wallet".into(),
        identifier: "btc-lightning-bolt12".into(),
        payload: "lno1...".into(),
    }];

    // Public: `access` is None.
    set_payment_list(&mnemonic, &details, false).await?;

    // Encrypted: share `access` with the people who may read the list.
    let published = set_payment_list(&mnemonic, &details, true).await?;
    let access = published.access.expect("encrypted mode returns an access string");
    let shared = get_encrypted_payment_list(&published.pubky, &access).await?;
    println!("{} encrypted endpoints", shared.len());
    Ok(())
}
```

These instructions install from this repository. The packages have not yet
been published to npm or crates.io. Pin a Git commit in production for
reproducible installations.

## Contract

- **Input:** a bare Pubky public key, `pubky<key>`, or `pubky://<key>`.
  Surrounding whitespace is ignored. Resource URLs, paths, queries, and
  fragments are rejected.
- **Output:** the published Payment Endpoint Identifier and opaque UTF-8
  payload, plus the App that published them. Two Apps can publish the same
  identifier; both records are retained.
- **Ordering:** endpoints from the payee's preferred App for that identifier
  come first, then records are ordered by App ID and identifier. An
  endpoint-specific App preference takes precedence over the identity default.
- **Empty:** a missing App Registry or no published endpoints returns `[]`.
  Missing endpoint directories/files are tolerated, including files removed
  during discovery. Empty endpoint files are treated as absent.
- **Errors:** invalid input, malformed public data, unavailable storage, and
  exceeded resource limits reject the TypeScript promise or return Rust `Err`.
  A failed lookup never returns a silently incomplete list.
- **Limits:** at most 64 registered Apps, 256 endpoint files across Apps,
  64 KiB per document, 4 MiB of aggregate endpoint payloads, and 512 directory
  listing/endpoint read requests. The App Registry read is separate.
- **Scope:** public App-scoped Paykit endpoints and this package's encrypted
  lists. Paykit Private Payment Lists require an Encrypted Link and the full
  Paykit SDK. Legacy unscoped endpoint directories are not searched.

The function reads the Paykit App Registry, lists each registered App's
endpoint directory, and reads the published payloads. Reads are a best-effort
snapshot, not an atomic view. Transport and timeouts are handled by the Pubky
SDK; this package does not add its own deadline.
The limits bound accepted documents and discovery work; the underlying Pubky
SDK buffers directory listing responses before this package can inspect them.

"Available" means published: the wallet must recognize the identifier,
validate the payload, and handle expiry or amount constraints before paying.
For example, select BOLT12 endpoints using
`payments.filter(p => p.identifier === "btc-lightning-bolt12")` in TypeScript.
This package does not generate invoices or execute payments.

## Publishing contract

- **Secret:** a BIP39 English mnemonic (12 to 24 words), a 64-character hex
  identity secret, or 32 bytes (TypeScript only). A mnemonic resolves the way
  Pubky Ring does: the first 32 bytes of its BIP39 seed, with no BIP39
  passphrase, are the identity secret. Whitespace runs and letter case in the
  phrase are normalized. The identity must already have a homeserver;
  publishing signs in (client ID `paykit-discovery`) and signs out afterward,
  but never signs up.
- **Input:** 1 to 256 records. App IDs use lowercase letters, digits, and `-`
  (1 to 64 characters); identifiers follow the Payment Endpoint Identifier
  rules; payloads are non-empty, at most 64 KiB each and 4 MiB in total; at
  most 64 Apps; no repeated App ID and identifier pair. Invalid secrets and
  input fail before any network access.
- **Public mode:** every App in the input is added to the Paykit App Registry
  if missing, with its ID as display name and no capabilities. Every other
  registry field is preserved. Each endpoint is written to
  `/pub/paykit/v0/apps/{appId}/endpoints/{identifier}`, and that App's other
  endpoints are removed. Apps not in the input are untouched. A malformed
  registry is never overwritten, and a registry changed by someone else during
  the update fails the call instead of being overwritten.
- **Encrypted mode:** nothing public changes. The whole list is written as one
  document at a new random path, and the result's `access` string opens it.
  Every call creates a new document with its own path and key, so a merchant
  can hand each customer their own list without overlap.
- **Errors:** TypeScript rejects with `INVALID_SECRET`, `INVALID_INPUT`,
  `AUTH` (sign-in failed, for example no homeserver), `INVALID_DATA`,
  `RESOURCE_LIMIT`, or `TRANSPORT` (failed writes and concurrent registry
  changes). Rust returns the matching `Error` variants. A publish is not
  atomic: after a failure some writes may have landed, and calling again with
  the same arguments is safe. No error message or cause includes the secret,
  mnemonic, or access key.

`PaymentListErrorCode` gained `INVALID_SECRET`, `INVALID_INPUT`, and `AUTH` in
this release. Exhaustive `switch` statements over it need cases for them.

## Encrypted Payment Lists

This is a format specific to this package, not a Paykit Private Payment List.

- **Path:** `/pub/paykit-discovery/v1/encrypted/{id}`, where `id` is 128
  random bits as 32 lowercase hex characters.
- **Key:** the Pubky hierarchical keys v1 file key for that path, derived from
  the identity secret (HKDF-SHA256, the same derivation `pubky-common` uses
  for scoped `e` grants). The owner can re-derive it from the mnemonic, and a
  Pubky app granted `e` on that path or a parent directory can decrypt it.
- **Document:** a 12-byte nonce, then AES-256-GCM ciphertext and tag. The
  associated data is `pubky://{owner}{path}`, so a copy at another path or
  identity fails to decrypt. The plaintext is
  `{"version":1,"kind":"paykit-discovery.encrypted_payment_list","endpoints":[{"app_id","identifier","payload"}]}`,
  sorted by App ID and identifier, at most 4 MiB.
- **Access string:** `v1.{id}.{key as 64 lowercase hex characters}`. Anyone
  with it can read that one list; treat it like a secret.
- **Reading:** `getPaymentList(pubky, access)` or
  `get_encrypted_payment_list(pubky, access)` returns only that list. A
  missing document returns `[]`. A wrong key or a tampered or moved document
  fails with invalid data.

Everything under `/pub/` can be listed publicly, so others can see how many
encrypted documents exist and when they were written, but not their contents.
Documents stay until deleted, and earlier documents remain readable to anyone
holding their access strings; this package does not revoke or clean them up.

## For AI coding assistants

To read payment details, use `getPaymentList(pubky)` or
`get_payment_list(pubky)`; never ask for a secret to read. To publish the
user's own payment details, use `setPaymentList(secret, details, encrypted?)`
or `set_payment_list(secret, details, encrypted)`, and only with a secret the
user provides for that purpose. Never log, store, or display the secret or an
access string beyond handing the access string to its intended recipient. Keep
`appId`/`app_id` attached to the selected endpoint. Treat `payload` as receiving
details for that `identifier`; interpret it with the wallet's existing payment
implementation. Show lookup errors separately from an empty array. See
[AGENTS.md](AGENTS.md) for maintenance instructions.

## Development

```sh
npm ci
npm run check
npm test
npm run build

cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

Both implementations use shared [discovery](fixtures/discovery.json) and
[publishing](fixtures/publishing.json) fixtures, so registry writes, encrypted
documents, and access strings match byte for byte. Rust delegates protocol
reads and writes to [Paykit Library](https://github.com/pubky/paykit-rs) and
key derivation to `pubky-common`. TypeScript uses the official
[Pubky SDK](https://pubky.org/sdk/), WebCrypto, and `@scure/bip39`, and follows
the same wire format. Fixture secrets are test-only; never use them for real
identities. The fixture payloads are test data, not payable addresses or offers.

MIT licensed. Independent integration helper maintained by Corey Phillips.
