/**
 * Encrypted Payment List documents.
 *
 * This is a format specific to this package, not a Paykit Private Payment List.
 * Each document lives at `/pub/paykit-discovery/v1/encrypted/{id}`, where `id` is
 * 128 random bits written as lowercase hex. Its AES-256-GCM key is the Pubky
 * hierarchical keys v1 file key for that path, derived from the owner's identity
 * secret. The stored bytes are a 12-byte nonce followed by the ciphertext and tag.
 * The associated data is `pubky://{owner z32}{path}`, so a document copied to
 * another owner or path fails authentication. The Rust crate uses `pubky-common`
 * for the same derivation; shared fixtures keep both byte-for-byte equal.
 */
import { PublicStorage } from "@synonymdev/pubky";
import { flattenEndpoints, validateEndpoints, type PaymentEndpoint } from "./endpoints.js";
import { PaymentListError } from "./errors.js";
import { address, readBytes } from "./io.js";
import { validateJsonTokens } from "./registry.js";

export const ENCRYPTED_PATH_PREFIX = "/pub/paykit-discovery/v1/encrypted/";
const DOCUMENT_KIND = "paykit-discovery.encrypted_payment_list";
const ROOT_LABEL = "pubky/hierarchical-keys/v1/root";
const DIRECTORY_LABEL = "pubky/hierarchical-keys/v1/directory";
const FILE_LABEL = "pubky/hierarchical-keys/v1/file-content";
const NONCE_BYTES = 12;
const TAG_BYTES = 16;
export const MAX_ENCRYPTED_DOCUMENT_BYTES = 4 * 1024 * 1024;
export const MAX_SEALED_BYTES = NONCE_BYTES + MAX_ENCRYPTED_DOCUMENT_BYTES + TAG_BYTES;

const encoder = new TextEncoder();

/** A parsed access string: the document ID and its content key. */
export interface Access { id: string; key: Uint8Array<ArrayBuffer> }

export function toHex(bytes: Uint8Array): string {
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return hex;
}

function fromHex(hex: string): Uint8Array<ArrayBuffer> {
  const bytes = new Uint8Array(hex.length / 2);
  for (let index = 0; index < bytes.length; index++) bytes[index] = parseInt(hex.slice(index * 2, index * 2 + 2), 16);
  return bytes;
}

function concat(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(parts.reduce((total, part) => total + part.byteLength, 0));
  let offset = 0;
  for (const part of parts) { out.set(part, offset); offset += part.byteLength; }
  return out;
}

/** Parse `v1.{32 hex id}.{64 hex key}`. Surrounding whitespace is ignored. */
export function parseAccess(input: unknown): Access {
  const match = typeof input === "string"
    ? /^v1\.([0-9a-f]{32})\.([0-9a-f]{64})$/.exec(input.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, ""))
    : null;
  if (!match) throw new PaymentListError("INVALID_INPUT", "Expected an encrypted Payment List access string");
  return { id: match[1]!, key: fromHex(match[2]!) };
}

export function formatAccess(id: string, key: Uint8Array): string { return `v1.${id}.${toHex(key)}`; }

/** A fresh 128-bit document ID, so every call gets its own path and key. */
export function newDocumentId(): string { return toHex(crypto.getRandomValues(new Uint8Array(16))); }

export function documentPath(id: string): string { return ENCRYPTED_PATH_PREFIX + id; }

async function hmacSha256(key: Uint8Array<ArrayBuffer>, data: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>> {
  const cryptoKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", cryptoKey, data));
}

/**
 * Derive the Pubky hierarchical keys v1 file key for a canonical file path.
 *
 * Root: HKDF-SHA256 extract and one expand block with the root label. Each
 * child: one HKDF-Expand block keyed by its parent with `label || 0x00 ||
 * segment || 0x01`, using the directory label for directory segments and the
 * file-content label for the last segment. Matches `pubky-common`.
 */
export async function deriveKey(secret: Uint8Array<ArrayBuffer>, path: string): Promise<Uint8Array<ArrayBuffer>> {
  if (!path.startsWith("/") || path.endsWith("/")) throw new PaymentListError("INVALID_INPUT", "Expected a file path");
  const prk = await hmacSha256(new Uint8Array(32), secret);
  let seed = await hmacSha256(prk, concat(encoder.encode(ROOT_LABEL), Uint8Array.of(1)));
  prk.fill(0);
  const segments = path.slice(1).split("/");
  for (const [index, segment] of segments.entries()) {
    const label = index === segments.length - 1 ? FILE_LABEL : DIRECTORY_LABEL;
    const next = await hmacSha256(seed, concat(encoder.encode(label), Uint8Array.of(0), encoder.encode(segment), Uint8Array.of(1)));
    seed.fill(0);
    seed = next;
  }
  return seed;
}

/** Serialize sorted endpoints as the versioned plaintext document. */
export function serializeDocument(endpoints: PaymentEndpoint[]): Uint8Array<ArrayBuffer> {
  const bytes = encoder.encode(JSON.stringify({
    version: 1,
    kind: DOCUMENT_KIND,
    endpoints: endpoints.map(({ appId, identifier, payload }) => ({ app_id: appId, identifier, payload })),
  }));
  if (bytes.byteLength > MAX_ENCRYPTED_DOCUMENT_BYTES) {
    throw new PaymentListError("INVALID_INPUT", "The encrypted Payment List document exceeds 4 MiB");
  }
  return bytes;
}

/** Parse and validate a decrypted document. Endpoints come back sorted. */
export function parseDocument(bytes: Uint8Array): PaymentEndpoint[] {
  const invalid = (): never => { throw new PaymentListError("INVALID_DATA", "The encrypted Payment List document is malformed"); };
  let text = "";
  try { text = new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes); } catch { invalid(); }
  let value: unknown;
  try { value = JSON.parse(text); } catch { invalid(); }
  const topLevel = validateJsonTokens(text, invalid);
  const exact = (candidate: unknown, keys: string[]): Record<string, unknown> => {
    if (typeof candidate !== "object" || candidate === null || Array.isArray(candidate)) invalid();
    const record = candidate as Record<string, unknown>;
    const present = Object.keys(record);
    if (present.length !== keys.length || keys.some((key) => !Object.hasOwn(record, key))) invalid();
    return record;
  };
  const document = exact(value, ["version", "kind", "endpoints"]);
  if (topLevel.get("version") !== "1" || document.kind !== DOCUMENT_KIND || !Array.isArray(document.endpoints)) invalid();
  const endpoints = (document.endpoints as unknown[]).map((item) => {
    const record = exact(item, ["app_id", "identifier", "payload"]);
    if (typeof record.app_id !== "string" || typeof record.identifier !== "string" || typeof record.payload !== "string") invalid();
    return { appId: record.app_id as string, identifier: record.identifier as string, payload: record.payload as string };
  });
  return flattenEndpoints(validateEndpoints(endpoints, "INVALID_DATA"));
}

function associatedData(owner: string, path: string): Uint8Array<ArrayBuffer> {
  return encoder.encode(`pubky://${owner}${path}`);
}

/** Encrypt a document for `owner` at `path` with an explicit nonce. */
export async function seal(
  key: Uint8Array<ArrayBuffer>,
  nonce: Uint8Array<ArrayBuffer>,
  owner: string,
  path: string,
  plaintext: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const cryptoKey = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["encrypt"]);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: associatedData(owner, path), tagLength: 128 },
    cryptoKey,
    plaintext,
  );
  return concat(nonce, new Uint8Array(ciphertext));
}

/** Decrypt a stored document. A wrong key, owner, or path, or any tampering, fails. */
export async function open(
  key: Uint8Array<ArrayBuffer>,
  owner: string,
  path: string,
  sealed: Uint8Array,
): Promise<Uint8Array<ArrayBuffer>> {
  if (sealed.byteLength < NONCE_BYTES + TAG_BYTES) {
    throw new PaymentListError("INVALID_DATA", "The encrypted Payment List document is truncated");
  }
  const cryptoKey = await crypto.subtle.importKey("raw", key, "AES-GCM", false, ["decrypt"]);
  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: sealed.slice(0, NONCE_BYTES), additionalData: associatedData(owner, path), tagLength: 128 },
      cryptoKey,
      sealed.slice(NONCE_BYTES),
    ));
  } catch {
    throw new PaymentListError("INVALID_DATA", "The encrypted Payment List could not be authenticated with this access string");
  }
}

/** Read, authenticate, and parse one encrypted document. Absence is `[]`. */
export async function readEncrypted(owner: string, access: Access): Promise<PaymentEndpoint[]> {
  const path = documentPath(access.id);
  let storage: PublicStorage | undefined;
  try {
    storage = new PublicStorage();
    const sealed = await readBytes(() => storage!.get(address(owner, path)), MAX_SEALED_BYTES);
    if (sealed === null) return [];
    const plaintext = await open(access.key, owner, path, sealed);
    try { return parseDocument(plaintext); } finally { plaintext.fill(0); }
  } catch (cause) {
    if (cause instanceof PaymentListError) throw cause;
    throw new PaymentListError("TRANSPORT", "Could not read the encrypted Payment List", { cause });
  } finally {
    storage?.free();
  }
}
