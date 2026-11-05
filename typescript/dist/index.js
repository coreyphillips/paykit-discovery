import { PublicKey, PublicStorage } from "@synonymdev/pubky";
import { compare, flattenEndpoints, MAX_DOCUMENT_BYTES, MAX_ENDPOINTS, MAX_PAYLOAD_BYTES, validateEndpoints, } from "./endpoints.js";
import { parseAccess, readEncrypted, serializeDocument } from "./encrypted.js";
import { PaymentListError } from "./errors.js";
import { address, endpointPrefix, listIdentifiers, readText } from "./io.js";
import { publish, publishWithSession } from "./publish.js";
import { parseRegistry } from "./registry.js";
import { parseSecret } from "./secret.js";
export { PaymentListError } from "./errors.js";
export { Identifier } from "./endpoints.js";
const REGISTRY_PATH = "/pub/paykit/v0/app-registry.json";
const MAX_REQUESTS = 512;
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
export async function getPaymentList(pubky, access) {
    const owner = normalizePubky(pubky);
    if (access !== undefined)
        return readEncrypted(owner, parseAccess(access));
    let storage;
    try {
        storage = new PublicStorage();
        const rawRegistry = await readText(storage, address(owner, REGISTRY_PATH), MAX_DOCUMENT_BYTES);
        if (rawRegistry === null)
            return [];
        const registry = parseRegistry(rawRegistry);
        const endpoints = [];
        let requests = MAX_REQUESTS;
        let remainingEndpoints = MAX_ENDPOINTS;
        let remainingBytes = MAX_PAYLOAD_BYTES;
        const request = () => {
            if (requests-- <= 0)
                throw new PaymentListError("RESOURCE_LIMIT", "Payment List request limit exceeded");
        };
        // Each App owns its endpoints. Do not collapse matching identifiers from
        // different Apps or follow arbitrary resources returned by a homeserver.
        for (const appId of [...registry.apps].sort(compare)) {
            const prefix = endpointPrefix(appId);
            const identifiers = await listIdentifiers(storage, owner, appId, request, remainingEndpoints);
            for (const identifier of identifiers) {
                request();
                remainingEndpoints--;
                const payload = await readText(storage, address(owner, prefix + identifier), Math.min(MAX_DOCUMENT_BYTES, remainingBytes));
                if (payload === null || payload.length === 0)
                    continue;
                remainingBytes -= new TextEncoder().encode(payload).byteLength;
                endpoints.push({ appId, identifier, payload });
            }
        }
        return endpoints.sort((left, right) => {
            const rank = (endpoint) => (registry.defaults.get(endpoint.identifier) ?? registry.defaultApp) === endpoint.appId ? 0 : 1;
            return rank(left) - rank(right) || compare(left.appId, right.appId) || compare(left.identifier, right.identifier);
        });
    }
    catch (cause) {
        if (cause instanceof PaymentListError)
            throw cause;
        throw new PaymentListError("TRANSPORT", "Could not read the public Payment List", { cause });
    }
    finally {
        storage?.free();
    }
}
/**
 * Publish a Payment List as the identity behind `secret`.
 *
 * `secret` is a BIP39 English mnemonic, the 32-byte identity secret as 64 hex
 * characters, or those 32 bytes. A mnemonic resolves the way Pubky Ring does:
 * the first 32 bytes of its BIP39 seed (no passphrase) are the identity secret.
 * Whitespace and letter case in the phrase are normalized. The identity must
 * already have a homeserver; this function signs in but never signs up.
 *
 * Apps that should not hold the secret can pass a Pubky `Session` instead, for
 * example from a Pubky Ring approval of `/pub/paykit/:rw`. That works in public
 * mode only, because the encrypted key derives from the identity secret. The
 * session stays yours: it is never signed out or freed. If its capabilities do
 * not cover a path this list has to write, the call rejects with `AUTH` before
 * writing any endpoint.
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
 * before any network access. Sign-in failures and sessions the homeserver
 * refuses reject with `AUTH`; other failed writes and concurrent App Registry
 * changes reject with `TRANSPORT`. The call is not atomic: after a rejection
 * some writes may have landed, and calling again with the same arguments is
 * safe. Errors never include the secret.
 */
export async function setPaymentList(secret, paymentDetails, encrypted = false) {
    if (isSession(secret)) {
        const apps = validateEndpoints(paymentDetails, "INVALID_INPUT");
        if (encrypted !== false) {
            throw new PaymentListError("INVALID_INPUT", "Encrypted mode needs the identity secret, not a session");
        }
        return publishWithSession(secret, apps);
    }
    const identitySecret = parseSecret(secret);
    try {
        const apps = validateEndpoints(paymentDetails, "INVALID_INPUT");
        if (typeof encrypted !== "boolean")
            throw new PaymentListError("INVALID_INPUT", "Expected encrypted to be a boolean");
        const document = encrypted ? serializeDocument(flattenEndpoints(apps)) : undefined;
        return await publish(identitySecret, apps, document);
    }
    finally {
        identitySecret.fill(0);
    }
}
// By shape, not `instanceof`: the session may come from the app's own SDK copy.
function isSession(value) {
    return typeof value === "object" && value !== null && !(value instanceof Uint8Array)
        && "storage" in value && "info" in value;
}
function normalizePubky(input) {
    if (typeof input !== "string")
        throw new PaymentListError("INVALID_PUBKY", "Expected a Pubky identity string");
    const trimmed = input.replace(/^\p{White_Space}+|\p{White_Space}+$/gu, "");
    const key = trimmed.length === 52 ? trimmed : trimmed.replace(/^(?:pubky:\/\/|pubky)/, "");
    if (!/^[ybndrfg8ejkmcpqxot1uwisza345h769]{52}$/.test(key)) {
        throw new PaymentListError("INVALID_PUBKY", "Expected a Pubky identity without a resource path");
    }
    try {
        const parsed = PublicKey.from(key);
        try {
            if (parsed.z32() !== key)
                throw new Error("Noncanonical key");
            return key;
        }
        finally {
            parsed.free();
        }
    }
    catch (cause) {
        throw new PaymentListError("INVALID_PUBKY", "Invalid Pubky public key", { cause });
    }
}
//# sourceMappingURL=index.js.map