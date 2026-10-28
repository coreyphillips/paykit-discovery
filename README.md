# Paykit Discovery

**One function. A Pubky identity in, public payment details out.**

Discover every public Payment Endpoint published by the registered Paykit Apps
on a Pubky identity. No sign-in, private key, database, or SDK setup.

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
- **Scope:** public App-scoped Paykit endpoints only. Private Payment Lists
  require an Encrypted Link and the full Paykit SDK. Legacy unscoped endpoint
  directories are not searched.

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

## For AI coding assistants

Use `getPaymentList(pubky)` or `get_payment_list(pubky)`. Do not create a Pubky
session or ask the user for a secret key. Keep `appId`/`app_id` attached to the
selected endpoint. Treat `payload` as receiving details for that `identifier`;
interpret it with the wallet's existing payment implementation. Show lookup
errors separately from an empty array. See [AGENTS.md](AGENTS.md) for maintenance
instructions.

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

Both implementations use [shared discovery fixtures](fixtures/discovery.json).
Rust delegates protocol reads to [Paykit Library](https://github.com/pubky/paykit-rs).
TypeScript uses the official [Pubky SDK](https://pubky.org/sdk/) and follows the
same public wire format. The fixture payloads are test data, not payable
addresses or offers.

MIT licensed. Independent integration helper maintained by Corey Phillips.
