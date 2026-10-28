export { PaymentListError, type PaymentListErrorCode } from "./errors.js";
/** One public Payment Endpoint. The wallet interprets and validates its payload. */
export interface PaymentEndpoint {
    /** Paykit App that published this endpoint. */
    appId: string;
    /** Payment Endpoint Identifier, for example `btc-lightning-bolt12`. */
    identifier: string;
    /** Opaque receiving details, preserved exactly as published. */
    payload: string;
}
/**
 * Discover all registered Apps' public Payment Endpoints for a Pubky identity.
 *
 * Accepts a bare z-base32 key, `pubky<key>`, or `pubky://<key>` (without a path).
 * No login, private key, or SDK setup is needed. Missing public data returns `[]`.
 * Errors reject the promise, including when one App cannot be read. Results are
 * a best-effort snapshot ordered by published App preferences, App ID, and
 * endpoint identifier. Private Payment Lists and payment execution are excluded.
 * Session creation, capabilities, and key rotation remain the caller's concern
 * for separate authenticated workflows; this function only reads public data.
 * Transport deadlines follow the underlying Pubky client's defaults.
 */
export declare function getPaymentList(pubky: string): Promise<PaymentEndpoint[]>;
