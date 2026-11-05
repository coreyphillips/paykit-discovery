import { type PaymentListErrorCode } from "./errors.js";
/** One Payment Endpoint. The wallet interprets and validates its payload. */
export interface PaymentEndpoint {
    /** Paykit App that published this endpoint. */
    appId: string;
    /** Payment Endpoint Identifier, for example `btc-lightning-bolt12`. */
    identifier: string;
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
