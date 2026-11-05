import type { Address, PublicStorage } from "@synonymdev/pubky";
import { MAX_ENDPOINTS, validateIdentifier } from "./endpoints.js";
import { PaymentListError } from "./errors.js";

const PAGE_SIZE = 100;

export function address(owner: string, path: string): Address { return `pubky://${owner}${path}` as Address; }

export function endpointPrefix(appId: string): string { return `/pub/paykit/v0/apps/${appId}/endpoints/`; }

/** HTTP status carried by a Pubky SDK `RequestError`, if any. */
export function statusOf(error: unknown): number | undefined {
  if (typeof error !== "object" || error === null) return undefined;
  const candidate = error as { name?: unknown; data?: { statusCode?: unknown } };
  const status = candidate.data?.statusCode;
  return candidate.name === "RequestError" && typeof status === "number" ? status : undefined;
}

export function isMissing(error: unknown): boolean {
  const status = statusOf(error);
  return status === 404 || status === 410;
}

/**
 * Read a response body with a hard streaming bound. Missing (404/410) is `null`.
 * Works for public and session storage, which both reject missing files.
 */
export async function readBytes(fetch: () => Promise<Response>, limit: number): Promise<Uint8Array | null> {
  let response: Response;
  try { response = await fetch(); }
  catch (cause) {
    if (isMissing(cause)) return null;
    throw new PaymentListError("TRANSPORT", "Could not read a Paykit document", { cause });
  }
  if (response.status === 404 || response.status === 410) {
    await response.body?.cancel();
    return null;
  }
  if (!response.ok) {
    await response.body?.cancel();
    throw new PaymentListError("TRANSPORT", "Paykit document request failed");
  }
  const reader = response.body?.getReader();
  if (!reader) return new Uint8Array(0);
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > limit) {
        await reader.cancel();
        throw new PaymentListError("RESOURCE_LIMIT", "Paykit document byte limit exceeded");
      }
      chunks.push(value);
    }
  } finally { reader.releaseLock(); }
  const bytes = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
  return bytes;
}

export function decodeUtf8(bytes: Uint8Array): string {
  try { return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(bytes); }
  catch (cause) { throw new PaymentListError("INVALID_DATA", "Paykit document is not UTF-8", { cause }); }
}

export async function readText(storage: PublicStorage, location: Address, limit: number): Promise<string | null> {
  const bytes = await readBytes(() => storage.get(location), limit);
  return bytes === null ? null : decodeUtf8(bytes);
}

/**
 * List one App's published Payment Endpoint Identifiers.
 *
 * The listing is untrusted: entries must be direct children of the App's
 * endpoint directory on the requested identity, in strictly increasing order.
 * `request` is charged once per page; at most `limit` identifiers are accepted.
 */
export async function listIdentifiers(
  storage: PublicStorage,
  owner: string,
  appId: string,
  request: () => void,
  limit: number,
): Promise<string[]> {
  const prefix = endpointPrefix(appId);
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
    if (identifiers.length > limit) {
      throw new PaymentListError("RESOURCE_LIMIT", "Payment List endpoint limit exceeded");
    }
    if (page.length < PAGE_SIZE) break;
  }
  return identifiers;
}

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
