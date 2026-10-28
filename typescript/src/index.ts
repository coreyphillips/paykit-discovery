import { PublicKey, PublicStorage, type Address } from "@synonymdev/pubky";
import { parseRegistry } from "./registry.js";
import { PaymentListError } from "./errors.js";
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

const REGISTRY_PATH = "/pub/paykit/v0/app-registry.json";
const MAX_DOCUMENT_BYTES = 64 * 1024;
const MAX_ENDPOINTS = 256;
const MAX_PAYLOAD_BYTES = 4 * 1024 * 1024;
const MAX_REQUESTS = 512;
const PAGE_SIZE = 100;

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
export async function getPaymentList(pubky: string): Promise<PaymentEndpoint[]> {
  const owner = normalizePubky(pubky);
  let storage: PublicStorage | undefined;
  try {
    storage = new PublicStorage();
    const rawRegistry = await readText(storage, address(owner, REGISTRY_PATH), MAX_DOCUMENT_BYTES);
    if (rawRegistry === null) return [];
    const registry = parseRegistry(rawRegistry);
    const endpoints: PaymentEndpoint[] = [];
    let requests = MAX_REQUESTS;
    let remainingEndpoints = MAX_ENDPOINTS;
    let remainingBytes = MAX_PAYLOAD_BYTES;
    const request = (): void => {
      if (requests-- <= 0) throw new PaymentListError("RESOURCE_LIMIT", "Payment List request limit exceeded");
    };

    // Each App owns its endpoints. Do not collapse matching identifiers from
    // different Apps or follow arbitrary resources returned by a homeserver.
    for (const appId of [...registry.apps].sort(compare)) {
      const prefix = `/pub/paykit/v0/apps/${appId}/endpoints/`;
      let cursor: string | undefined;
      const identifiers: string[] = [];
      let resourceCount = 0;
      const seen = new Set<string>();
      while (true) {
        request();
        let page: string[];
        try {
          page = await storage.list(address(owner, prefix), cursor, false, PAGE_SIZE, true);
        } catch (cause) {
          if (isMissing(cause)) break;
          throw new PaymentListError("TRANSPORT", "Could not list public Payment Endpoints", { cause });
        }
        if (!Array.isArray(page) || page.length > PAGE_SIZE) {
          throw new PaymentListError("INVALID_DATA", "Invalid Payment Endpoint directory listing");
        }
        if (page.length === 0) break;
        resourceCount += page.length;
        if (resourceCount > MAX_ENDPOINTS) {
          throw new PaymentListError("RESOURCE_LIMIT", "Payment Endpoint directory limit exceeded");
        }
        let nextCursor = cursor;
        for (const resource of page) {
          const path = listingPath(resource, owner, prefix);
          const canonical = owner + path;
          if ((nextCursor !== undefined && canonical <= nextCursor) || seen.has(canonical)) {
            throw new PaymentListError("INVALID_DATA", "Payment Endpoint directory cursor did not advance");
          }
          seen.add(canonical);
          nextCursor = canonical;
          if (path.endsWith("/")) continue;
          const identifier = path.slice(prefix.length);
          validateIdentifier(identifier);
          identifiers.push(identifier);
        }
        cursor = nextCursor;
        if (identifiers.length > remainingEndpoints) {
          throw new PaymentListError("RESOURCE_LIMIT", "Payment List endpoint limit exceeded");
        }
        if (page.length < PAGE_SIZE) break;
      }
      for (const identifier of identifiers) {
        request();
        remainingEndpoints--;
        const payload = await readText(storage, address(owner, prefix + identifier), Math.min(MAX_DOCUMENT_BYTES, remainingBytes));
        if (payload === null || payload.length === 0) continue;
        remainingBytes -= new TextEncoder().encode(payload).byteLength;
        endpoints.push({ appId, identifier, payload });
      }
    }
    return endpoints.sort((left, right) => {
      const rank = (endpoint: PaymentEndpoint): number =>
        (registry.defaults.get(endpoint.identifier) ?? registry.defaultApp) === endpoint.appId ? 0 : 1;
      return rank(left) - rank(right) || compare(left.appId, right.appId) || compare(left.identifier, right.identifier);
    });
  } catch (cause) {
    if (cause instanceof PaymentListError) throw cause;
    throw new PaymentListError("TRANSPORT", "Could not read the public Payment List", { cause });
  } finally {
    storage?.free();
  }
}

function normalizePubky(input: string): string {
  if (typeof input !== "string") throw new PaymentListError("INVALID_PUBKY", "Expected a Pubky identity string");
  const trimmed = input.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, "");
  const key = trimmed.length === 52 ? trimmed : trimmed.replace(/^(?:pubky:\/\/|pubky)/, "");
  if (!/^[ybndrfg8ejkmcpqxot1uwisza345h769]{52}$/.test(key)) {
    throw new PaymentListError("INVALID_PUBKY", "Expected a Pubky identity without a resource path");
  }
  try {
    const parsed = PublicKey.from(key);
    try {
      if (parsed.z32() !== key) throw new Error("Noncanonical key");
      return key;
    } finally { parsed.free(); }
  } catch (cause) {
    throw new PaymentListError("INVALID_PUBKY", "Invalid Pubky public key", { cause });
  }
}

function address(owner: string, path: string): Address { return `pubky://${owner}${path}` as Address; }
function compare(left: string, right: string): number { return left < right ? -1 : left > right ? 1 : 0; }

// Validate the exact raw path, before any URL parser can normalize dot segments.
function listingPath(resource: unknown, owner: string, prefix: string): string {
  if (typeof resource !== "string") throw new PaymentListError("INVALID_DATA", "Invalid directory resource");
  const bases = [`pubky://${owner}`, `pubky${owner}`];
  const base = bases.find((value) => resource.startsWith(value + "/"));
  const path = base === undefined ? "" : resource.slice(base.length);
  const suffix = path.slice(prefix.length);
  if (!path.startsWith(prefix) || !suffix || /[%?#\\]/.test(path)
      || suffix.replace(/\/$/, "").includes("/")) {
    throw new PaymentListError("INVALID_DATA", "Directory returned a resource outside the requested App");
  }
  // Directories are skipped, but their names still must be safe before use as cursors.
  validateIdentifier(suffix.replace(/\/$/, ""));
  return path;
}

function validateIdentifier(value: string): void {
  if (!/^[A-Za-z0-9_.-]{1,64}$/.test(value) || /^\.+$/.test(value) || value === "private") {
    throw new PaymentListError("INVALID_DATA", "Invalid Payment Endpoint Identifier");
  }
}

function isMissing(error: unknown): boolean {
  if (typeof error !== "object" || error === null) return false;
  const candidate = error as { name?: unknown; data?: { statusCode?: unknown } };
  return candidate.name === "RequestError" && [404, 410].includes(candidate.data?.statusCode as number);
}

async function readText(storage: PublicStorage, location: Address, limit: number): Promise<string | null> {
  let response: Response;
  try { response = await storage.get(location); }
  catch (cause) {
    if (isMissing(cause)) return null;
    throw new PaymentListError("TRANSPORT", "Could not read a public Paykit document", { cause });
  }
  if (response.status === 404 || response.status === 410) {
    await response.body?.cancel();
    return null;
  }
  if (!response.ok) {
    await response.body?.cancel();
    throw new PaymentListError("TRANSPORT", "Public Paykit document request failed");
  }
  const reader = response.body?.getReader();
  if (!reader) return "";
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > limit) {
        await reader.cancel();
        throw new PaymentListError("RESOURCE_LIMIT", "Public Paykit document byte limit exceeded");
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  try { return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch (cause) { throw new PaymentListError("INVALID_DATA", "Public Paykit document is not UTF-8", { cause }); }
}
