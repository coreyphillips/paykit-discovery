import { type AppEndpoints, type PaymentSession, type SetPaymentListResult } from "./endpoints.js";
/**
 * Sign in as the identity and publish an already validated list.
 * `document` is the serialized plaintext for encrypted mode.
 */
export declare function publish(secret: Uint8Array<ArrayBuffer>, apps: AppEndpoints[], document: Uint8Array<ArrayBuffer> | undefined): Promise<SetPaymentListResult>;
/**
 * Publish an already validated list in public mode with the caller's session.
 * The session stays the caller's: it is never signed out or freed here. Only
 * the `info` and `storage` handles read from it are released.
 */
export declare function publishWithSession(session: PaymentSession, apps: AppEndpoints[]): Promise<SetPaymentListResult>;
/**
 * Whether `capabilities` allow writing `path`, by Pubky's scope rules: a scope
 * ending in `/` covers everything inside that directory, and any other scope
 * covers only that exact file.
 */
export declare function canWrite(capabilities: string[], path: string): boolean;
