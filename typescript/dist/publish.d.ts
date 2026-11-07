import { type AppEndpoints, type SetPaymentListResult } from "./endpoints.js";
/**
 * Sign in as the identity and publish an already validated list, signing the
 * identity up first when it has no homeserver record.
 * `document` is the serialized plaintext for encrypted mode.
 */
export declare function publish(secret: Uint8Array<ArrayBuffer>, apps: AppEndpoints[], document: Uint8Array<ArrayBuffer> | undefined): Promise<SetPaymentListResult>;
