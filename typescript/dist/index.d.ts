import { type PaymentEndpoint, type PaymentSecret, type SetPaymentListResult } from "./endpoints.js";
export { PaymentListError, type PaymentListErrorCode } from "./errors.js";
export { Identifier } from "./endpoints.js";
export type { KnownIdentifier, PaymentEndpoint, PaymentIdentifier, PaymentSecret, SetPaymentListResult } from "./endpoints.js";
/**
 * Discover all registered Apps' public Payment Endpoints for a Pubky identity.
 *
 * Accepts a bare z-base32 key, `pubky<key>`, or `pubky://<key>` (without a path).
 * No login, private key, or SDK setup is needed. Missing public data returns `[]`.
 * Errors reject the promise, including when one App cannot be read. Results are
 * a best-effort snapshot ordered by published App preferences, App ID, and
 * endpoint identifier. Paykit Private Payment Lists and payment execution are
 * excluded. Transport deadlines follow the underlying Pubky client's defaults.
 *
 * With `access`, the string returned by an encrypted `setPaymentList`, this
 * instead opens that one encrypted Payment List and returns only its records,
 * sorted by App ID and identifier. A missing document rejects with `NOT_FOUND`,
 * because an access string means a list should exist. A wrong access string or
 * a tampered or moved document rejects with `INVALID_DATA`.
 */
export declare function getPaymentList(pubky: string, access?: string): Promise<PaymentEndpoint[]>;
/**
 * Publish a Payment List as the identity behind `secret`.
 *
 * `secret` is a BIP39 English mnemonic, the 32-byte identity secret as 64 hex
 * characters, or those 32 bytes. A mnemonic resolves the way Pubky Ring does:
 * the first 32 bytes of its BIP39 seed (no passphrase) are the identity secret.
 * Whitespace and letter case in the phrase are normalized. The identity must
 * already have a homeserver; this function signs in but never signs up.
 *
 * Public mode (`encrypted` omitted or `false`) adds every App in
 * `paymentDetails` to the Paykit App Registry if missing, writes each endpoint
 * to its public Paykit path, and removes that App's other published endpoints.
 * Apps not named in `paymentDetails` are untouched. `getPaymentList(pubky)`
 * then returns the records.
 *
 * Encrypted mode (`encrypted === true`) changes nothing public. The whole list
 * is written as one AES-256-GCM document at a new random path under
 * `/pub/paykit-discovery/v1/encrypted/`, keyed with the Pubky hierarchical key
 * for that path. Pass the returned `access` string to
 * `getPaymentList(pubky, access)` to read it. Every call creates a new document
 * with its own path and key, so each recipient can get their own list. Earlier
 * documents stay readable to anyone holding their access strings.
 *
 * Endpoints follow the rules discovery enforces: 1 to 256 records, App IDs of
 * lowercase letters, digits, and `-`, valid Payment Endpoint Identifiers,
 * non-empty payloads of at most 64 KiB (4 MiB in total), at most 64 Apps, and
 * no repeated App ID and identifier pair.
 *
 * Invalid secrets and input reject with `INVALID_SECRET` or `INVALID_INPUT`
 * before any network access. Sign-in failures reject with `AUTH`; failed writes
 * and concurrent App Registry changes reject with `TRANSPORT`. The call is not
 * atomic: after a rejection some writes may have landed, and calling again
 * with the same arguments is safe. Errors never include the secret.
 */
export declare function setPaymentList(secret: PaymentSecret, paymentDetails: PaymentEndpoint[], encrypted?: boolean): Promise<SetPaymentListResult>;
