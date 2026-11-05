import type { Address, PublicStorage } from "@synonymdev/pubky";
export declare function address(owner: string, path: string): Address;
export declare function endpointPrefix(appId: string): string;
/** HTTP status carried by a Pubky SDK `RequestError`, if any. */
export declare function statusOf(error: unknown): number | undefined;
export declare function isMissing(error: unknown): boolean;
/**
 * Read a response body with a hard streaming bound. Missing (404/410) is `null`.
 * Works for public and session storage, which both reject missing files.
 */
export declare function readBytes(fetch: () => Promise<Response>, limit: number): Promise<Uint8Array | null>;
export declare function decodeUtf8(bytes: Uint8Array): string;
export declare function readText(storage: PublicStorage, location: Address, limit: number): Promise<string | null>;
/**
 * List one App's published Payment Endpoint Identifiers.
 *
 * The listing is untrusted: entries must be direct children of the App's
 * endpoint directory on the requested identity, in strictly increasing order.
 * `request` is charged once per page; at most `limit` identifiers are accepted.
 */
export declare function listIdentifiers(storage: PublicStorage, owner: string, appId: string, request: () => void, limit: number): Promise<string[]>;
