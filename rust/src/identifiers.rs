//! Common Payment Endpoint Identifiers from Paykit's naming convention.
//!
//! These are a convenience, not a limit. Identifiers are open strings: new ones
//! appear by being published, and any valid identifier can be read or published.
//! Keep this list equal to `known_identifiers` in `fixtures/discovery.json`.

/// Bitcoin on-chain to a Taproot address.
pub const BTC_BITCOIN_P2TR: &str = "btc-bitcoin-p2tr";
/// Bitcoin on-chain to a native SegWit address.
pub const BTC_BITCOIN_P2WPKH: &str = "btc-bitcoin-p2wpkh";
/// Bitcoin over Lightning with a BOLT 11 invoice.
pub const BTC_LIGHTNING_BOLT11: &str = "btc-lightning-bolt11";
/// Bitcoin over Lightning with a BOLT 12 offer.
pub const BTC_LIGHTNING_BOLT12: &str = "btc-lightning-bolt12";
/// Euros over SEPA to an IBAN.
pub const EUR_SEPA_IBAN: &str = "eur-sepa-iban";
/// British pounds over Faster Payments to a sort code.
pub const GBP_FPS_SORTCODE: &str = "gbp-fps-sortcode";
/// US dollars through Revolut to a tag.
pub const USD_REVOLUT_TAG: &str = "usd-revolut-tag";
/// USDC on Solana to an address.
pub const USDC_SOLANA_ADDRESS: &str = "usdc-solana-address";
/// USDT on Ethereum to an address.
pub const USDT_ETHEREUM_ADDRESS: &str = "usdt-ethereum-address";
/// USDT on Tron to an address.
pub const USDT_TRON_ADDRESS: &str = "usdt-tron-address";
