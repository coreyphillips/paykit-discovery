# Paykit Discovery for Rust

Get a Pubky identity's public Payment Endpoints, and publish your own from a
mnemonic or secret, publicly or as an encrypted list.

```toml
[dependencies]
paykit-discovery = { git = "https://github.com/coreyphillips/paykit-discovery" }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

```rust,no_run
use paykit_discovery::get_payment_list;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let payments = get_payment_list("pubky5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo").await?;
    for payment in payments {
        println!("{} {} {}", payment.app_id, payment.identifier, payment.payload);
    }
    Ok(())
}
```

The key above is a syntax example, not a guarantee of published endpoints.

Accepts a bare public key, `pubky<key>`, or `pubky://<key>`. Each result has
`app_id`, `identifier`, and `payload` strings. No login or keys are needed.

An absent App Registry or empty public Payment List returns an empty vector.
Lookup failures, malformed data, and resource limits return `Error`; the
function never returns partial results. It retains separate Apps' endpoints,
orders preferred Apps first, and uses Pubky's default transport settings.
Run it in Tokio; the caller can wrap the future in `tokio::time::timeout` if a
deadline is needed.

## Publishing

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
    let published = set_payment_list(&mnemonic, &details, true).await?;
    let access = published.access.expect("encrypted mode returns an access string");
    let shared = get_encrypted_payment_list(&published.pubky, &access).await?;
    println!("{} encrypted endpoints", shared.len());
    Ok(())
}
```

`set_payment_list` takes a BIP39 English mnemonic or the 32-byte identity
secret as 64 hex characters. A mnemonic resolves the way Pubky Ring does. The
identity must already have a homeserver. With `encrypted == false` it registers
missing Apps and replaces the named Apps' public endpoints; with `true` it
writes one encrypted document at a new random path and returns the access
string that opens it. Errors never include the secret or access key.

Payloads are opaque receiving details. Your wallet validates them, determines
which identifiers it supports, and executes payments. Paykit Private Payment
Lists require the full Paykit SDK and are outside this package.

See the [project README](https://github.com/coreyphillips/paykit-discovery)
for the matching TypeScript API, the publishing contract, the encrypted format,
protocol limits, and development commands.
