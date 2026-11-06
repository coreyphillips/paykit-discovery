import { PaymentListError, type PaymentListErrorCode } from "./errors.js";

/**
 * Common Payment Endpoint Identifiers from Paykit's naming convention.
 *
 * These are a convenience, not a limit. Identifiers are open strings: new ones
 * appear by being published, and any valid identifier can be read or published.
 * Keep this list equal to `known_identifiers` in `fixtures/discovery.json`.
 */
export const Identifier = {
  BtcBitcoinP2tr: "btc-bitcoin-p2tr",
  BtcBitcoinP2wpkh: "btc-bitcoin-p2wpkh",
  BtcLightningBolt11: "btc-lightning-bolt11",
  BtcLightningBolt12: "btc-lightning-bolt12",
  EurSepaIban: "eur-sepa-iban",
  GbpFpsSortcode: "gbp-fps-sortcode",
  UsdRevolutTag: "usd-revolut-tag",
  UsdcSolanaAddress: "usdc-solana-address",
  UsdtEthereumAddress: "usdt-ethereum-address",
  UsdtTronAddress: "usdt-tron-address",
} as const;

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

/**
 * A Pubky SDK `Session`, for example from `flow.awaitApproval()`.
 *
 * Declared by shape so a session from your own copy of the SDK is accepted,
 * even if it is a different version from the one this package installs.
 */
export interface PaymentSession {
  readonly info: { readonly capabilities: string[]; readonly publicKey: { z32(): string } };
  readonly storage: object;
}

/** What `setPaymentList` published. `access` opens an encrypted list. */
export type SetPaymentListResult =
  | { pubky: string; encrypted: false }
  | { pubky: string; encrypted: true; access: string };

/** Endpoints of one App, sorted by identifier. */
export interface AppEndpoints {
  appId: string;
  endpoints: { identifier: string; payload: string }[];
}

export const MAX_DOCUMENT_BYTES = 64 * 1024;
export const MAX_ENDPOINTS = 256;
export const MAX_APPS = 64;
export const MAX_PAYLOAD_BYTES = 4 * 1024 * 1024;

const encoder = new TextEncoder();

export function compare(left: string, right: string): number {
  return left < right ? -1 : left > right ? 1 : 0;
}

export function isAppId(value: unknown): value is string {
  return typeof value === "string" && /^[a-z0-9-]{1,64}$/.test(value);
}

export function isIdentifier(value: unknown): value is string {
  return typeof value === "string" && /^[A-Za-z0-9_.-]{1,64}$/.test(value)
    && !/^\.+$/.test(value) && value !== "private";
}

export function validateIdentifier(value: string): void {
  if (!isIdentifier(value)) throw new PaymentListError("INVALID_DATA", "Invalid Payment Endpoint Identifier");
}

/**
 * Check a Payment List against the rules discovery enforces when reading it,
 * then group it by App with both levels sorted. `code` is `INVALID_INPUT` for
 * caller input and `INVALID_DATA` for a decrypted document.
 */
export function validateEndpoints(input: unknown, code: PaymentListErrorCode): AppEndpoints[] {
  const fail = (message: string): never => { throw new PaymentListError(code, message); };
  if (!Array.isArray(input) || input.length === 0) fail("Expected at least one Payment Endpoint");
  const list = input as unknown[];
  if (list.length > MAX_ENDPOINTS) fail("At most 256 Payment Endpoints are allowed");
  const grouped = new Map<string, Map<string, string>>();
  let totalBytes = 0;
  for (const item of list) {
    if (typeof item !== "object" || item === null) fail("Expected Payment Endpoint objects");
    const { appId, identifier, payload } = item as Record<string, unknown>;
    if (!isAppId(appId)) fail("Invalid App ID");
    if (!isIdentifier(identifier)) fail("Invalid Payment Endpoint Identifier");
    if (typeof payload !== "string" || payload.length === 0) fail("Payment Endpoint payloads must be non-empty strings");
    // Lone surrogates have no UTF-8 encoding; they would be replaced, not preserved.
    if (/[\uD800-\uDFFF]/u.test(payload as string)) fail("Payment Endpoint payloads must be well-formed Unicode");
    const bytes = encoder.encode(payload as string).byteLength;
    if (bytes > MAX_DOCUMENT_BYTES) fail("A Payment Endpoint payload exceeds 64 KiB");
    totalBytes += bytes;
    let app = grouped.get(appId as string);
    if (!app) grouped.set(appId as string, app = new Map());
    if (app.has(identifier as string)) fail("An App ID and Payment Endpoint Identifier pair is repeated");
    app.set(identifier as string, payload as string);
  }
  if (totalBytes > MAX_PAYLOAD_BYTES) fail("Payment Endpoint payloads exceed 4 MiB in total");
  if (grouped.size > MAX_APPS) fail("At most 64 Apps are allowed");
  return [...grouped.keys()].sort(compare).map((appId) => {
    const app = grouped.get(appId)!;
    return {
      appId,
      endpoints: [...app.keys()].sort(compare).map((identifier) => ({ identifier, payload: app.get(identifier)! })),
    };
  });
}

/** Flatten grouped endpoints back to records, sorted by App ID and identifier. */
export function flattenEndpoints(apps: AppEndpoints[]): PaymentEndpoint[] {
  return apps.flatMap(({ appId, endpoints }) => endpoints.map(({ identifier, payload }) => ({ appId, identifier, payload })));
}
