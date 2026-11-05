import { PaymentListError } from "./errors.js";
export const MAX_DOCUMENT_BYTES = 64 * 1024;
export const MAX_ENDPOINTS = 256;
export const MAX_APPS = 64;
export const MAX_PAYLOAD_BYTES = 4 * 1024 * 1024;
const encoder = new TextEncoder();
export function compare(left, right) {
    return left < right ? -1 : left > right ? 1 : 0;
}
export function isAppId(value) {
    return typeof value === "string" && /^[a-z0-9-]{1,64}$/.test(value);
}
export function isIdentifier(value) {
    return typeof value === "string" && /^[A-Za-z0-9_.-]{1,64}$/.test(value)
        && !/^\.+$/.test(value) && value !== "private";
}
export function validateIdentifier(value) {
    if (!isIdentifier(value))
        throw new PaymentListError("INVALID_DATA", "Invalid Payment Endpoint Identifier");
}
/**
 * Check a Payment List against the rules discovery enforces when reading it,
 * then group it by App with both levels sorted. `code` is `INVALID_INPUT` for
 * caller input and `INVALID_DATA` for a decrypted document.
 */
export function validateEndpoints(input, code) {
    const fail = (message) => { throw new PaymentListError(code, message); };
    if (!Array.isArray(input) || input.length === 0)
        fail("Expected at least one Payment Endpoint");
    const list = input;
    if (list.length > MAX_ENDPOINTS)
        fail("At most 256 Payment Endpoints are allowed");
    const grouped = new Map();
    let totalBytes = 0;
    for (const item of list) {
        if (typeof item !== "object" || item === null)
            fail("Expected Payment Endpoint objects");
        const { appId, identifier, payload } = item;
        if (!isAppId(appId))
            fail("Invalid App ID");
        if (!isIdentifier(identifier))
            fail("Invalid Payment Endpoint Identifier");
        if (typeof payload !== "string" || payload.length === 0)
            fail("Payment Endpoint payloads must be non-empty strings");
        // Lone surrogates have no UTF-8 encoding; they would be replaced, not preserved.
        if (/[\uD800-\uDFFF]/u.test(payload))
            fail("Payment Endpoint payloads must be well-formed Unicode");
        const bytes = encoder.encode(payload).byteLength;
        if (bytes > MAX_DOCUMENT_BYTES)
            fail("A Payment Endpoint payload exceeds 64 KiB");
        totalBytes += bytes;
        let app = grouped.get(appId);
        if (!app)
            grouped.set(appId, app = new Map());
        if (app.has(identifier))
            fail("An App ID and Payment Endpoint Identifier pair is repeated");
        app.set(identifier, payload);
    }
    if (totalBytes > MAX_PAYLOAD_BYTES)
        fail("Payment Endpoint payloads exceed 4 MiB in total");
    if (grouped.size > MAX_APPS)
        fail("At most 64 Apps are allowed");
    return [...grouped.keys()].sort(compare).map((appId) => {
        const app = grouped.get(appId);
        return {
            appId,
            endpoints: [...app.keys()].sort(compare).map((identifier) => ({ identifier, payload: app.get(identifier) })),
        };
    });
}
/** Flatten grouped endpoints back to records, sorted by App ID and identifier. */
export function flattenEndpoints(apps) {
    return apps.flatMap(({ appId, endpoints }) => endpoints.map(({ identifier, payload }) => ({ appId, identifier, payload })));
}
//# sourceMappingURL=endpoints.js.map