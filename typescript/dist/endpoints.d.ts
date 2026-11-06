import { type PaymentListErrorCode } from "./errors.js";
/**
 * Common Payment Endpoint Identifiers from Paykit's naming convention.
 *
 * These are a convenience, not a limit. Identifiers are open strings: new ones
 * appear by being published, and any valid identifier can be read or published.
 * Keep this list equal to `known_identifiers` in `fixtures/discovery.json`.
 */
export declare const Identifier: {
    readonly BtcBitcoinP2tr: "btc-bitcoin-p2tr";
    readonly BtcBitcoinP2wpkh: "btc-bitcoin-p2wpkh";
    readonly BtcLightningBolt11: "btc-lightning-bolt11";
    readonly BtcLightningBolt12: "btc-lightning-bolt12";
    readonly EurSepaIban: "eur-sepa-iban";
    readonly GbpFpsSortcode: "gbp-fps-sortcode";
    readonly UsdRevolutTag: "usd-revolut-tag";
    readonly UsdcSolanaAddress: "usdc-solana-address";
    readonly UsdtEthereumAddress: "usdt-ethereum-address";
    readonly UsdtTronAddress: "usdt-tron-address";
};
/** One of the common identifiers in `Identifier`. */
export type KnownIdentifier = (typeof Identifier)[keyof typeof Identifier];
/** Any identifier. Editors suggest the known ones; `string & {}` keeps every other string valid. */
export type PaymentIdentifier = KnownIdentifier | (string & {});
/** One Payment Endpoint. The wallet interprets and validates its payload. */
export interface PaymentEndpoint {
    /** Paykit App that published this endpoint. */
    appId: string;
    /** Payment Endpoint Identifier, for example `btc-lightning-bolt12`. */
    identifier: PaymentIdentifier;
    /** Opaque receiving details, preserved exactly as published. */
    payload: string;
}
/** A BIP39 English mnemonic, a 64-character hex identity secret, or its 32 bytes. */
export type PaymentSecret = string | Uint8Array;
/** What `setPaymentList` published. `access` opens an encrypted list. */
export type SetPaymentListResult = {
    pubky: string;
    encrypted: false;
} | {
    pubky: string;
    encrypted: true;
    access: string;
};
/** Endpoints of one App, sorted by identifier. */
export interface AppEndpoints {
    appId: string;
    endpoints: {
        identifier: string;
        payload: string;
    }[];
}
export declare const MAX_DOCUMENT_BYTES: number;
export declare const MAX_ENDPOINTS = 256;
export declare const MAX_APPS = 64;
export declare const MAX_PAYLOAD_BYTES: number;
export declare function compare(left: string, right: string): number;
export declare function isAppId(value: unknown): value is string;
export declare function isIdentifier(value: unknown): value is string;
export declare function validateIdentifier(value: string): void;
/**
 * Check a Payment List against the rules discovery enforces when reading it,
 * then group it by App with both levels sorted. `code` is `INVALID_INPUT` for
 * caller input and `INVALID_DATA` for a decrypted document.
 */
export declare function validateEndpoints(input: unknown, code: PaymentListErrorCode): AppEndpoints[];
/** Flatten grouped endpoints back to records, sorted by App ID and identifier. */
export declare function flattenEndpoints(apps: AppEndpoints[]): PaymentEndpoint[];
