import { type PaymentEndpoint } from "./endpoints.js";
export declare const ENCRYPTED_PATH_PREFIX = "/pub/paykit-discovery/v1/encrypted/";
export declare const MAX_ENCRYPTED_DOCUMENT_BYTES: number;
export declare const MAX_SEALED_BYTES: number;
/** A parsed access string: the document ID and its content key. */
export interface Access {
    id: string;
    key: Uint8Array<ArrayBuffer>;
}
export declare function toHex(bytes: Uint8Array): string;
/** Parse `v1.{32 hex id}.{64 hex key}`. Surrounding whitespace is ignored. */
export declare function parseAccess(input: unknown): Access;
export declare function formatAccess(id: string, key: Uint8Array): string;
/** A fresh 128-bit document ID, so every call gets its own path and key. */
export declare function newDocumentId(): string;
export declare function documentPath(id: string): string;
/**
 * Derive the Pubky hierarchical keys v1 file key for a canonical file path.
 *
 * Root: HKDF-SHA256 extract and one expand block with the root label. Each
 * child: one HKDF-Expand block keyed by its parent with `label || 0x00 ||
 * segment || 0x01`, using the directory label for directory segments and the
 * file-content label for the last segment. Matches `pubky-common`.
 */
export declare function deriveKey(secret: Uint8Array<ArrayBuffer>, path: string): Promise<Uint8Array<ArrayBuffer>>;
/** Serialize sorted endpoints as the versioned plaintext document. */
export declare function serializeDocument(endpoints: PaymentEndpoint[]): Uint8Array<ArrayBuffer>;
/** Parse and validate a decrypted document. Endpoints come back sorted. */
export declare function parseDocument(bytes: Uint8Array): PaymentEndpoint[];
/** Encrypt a document for `owner` at `path` with an explicit nonce. */
export declare function seal(key: Uint8Array<ArrayBuffer>, nonce: Uint8Array<ArrayBuffer>, owner: string, path: string, plaintext: Uint8Array<ArrayBuffer>): Promise<Uint8Array<ArrayBuffer>>;
/** Decrypt a stored document. A wrong key, owner, or path, or any tampering, fails. */
export declare function open(key: Uint8Array<ArrayBuffer>, owner: string, path: string, sealed: Uint8Array): Promise<Uint8Array<ArrayBuffer>>;
/** Read, authenticate, and parse one encrypted document. Absence is `[]`. */
export declare function readEncrypted(owner: string, access: Access): Promise<PaymentEndpoint[]>;
