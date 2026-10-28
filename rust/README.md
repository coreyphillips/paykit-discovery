# Paykit Discovery for Rust

One function retrieves a Pubky identity's public Payment Endpoints.

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

Payloads are opaque receiving details. Your wallet validates them, determines
which identifiers it supports, and executes payments. Private Payment Lists
require the full Paykit SDK and are outside this package.

See the [project README](https://github.com/coreyphillips/paykit-discovery)
for the matching TypeScript API, protocol limits, and development commands.
