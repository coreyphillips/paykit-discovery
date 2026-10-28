# Paykit Discovery

This project has one job: return public Paykit Payment Endpoints for a Pubky
identity. Keep the integration to one async function in each language:
`getPaymentList(pubky)` in TypeScript and `get_payment_list(pubky)` in Rust.

- Return an array/vector of endpoint records. Preserve the publishing App ID,
  Payment Endpoint Identifier, and opaque UTF-8 Payment Endpoint Payload.
- Public discovery does not require a login, identity secret, database,
  Encrypted Link, or payment execution adapter.
- Missing public data is empty. Network, malformed-data, and resource-limit
  failures are errors; never return a silently incomplete list.
- Discover Apps through the identity-wide Paykit App Registry. Never merge
  endpoints from different Apps by identifier alone.
- Keep Rust and TypeScript behavior aligned, including the shared fixtures.
- Rust uses the canonical `paykit-lib` APIs. TypeScript uses the official
  `@synonymdev/pubky` SDK and follows the same public Paykit wire format.
- Do not add alternate network backends, private messaging, payment execution,
  or wallet-specific payload interpretation to this package.
- Keep package examples runnable and distinguish GitHub installation from
  unpublished npm/crates.io packages.
- Commit generated `typescript/dist` files with their source changes. GitHub
  installs must work without install scripts or a TypeScript compiler; CI
  checks that the generated output is current.

Run `npm ci`, `npm run check`, `npm test`, and `npm run build` for TypeScript.
Run `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets --all-features -- -D warnings`,
`cargo test --workspace`, and `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`
for Rust.
