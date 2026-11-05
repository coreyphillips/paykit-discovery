import { Keypair, Pubky, PublicStorage, } from "@synonymdev/pubky";
import { MAX_DOCUMENT_BYTES, MAX_ENDPOINTS } from "./endpoints.js";
import { deriveKey, documentPath, formatAccess, MAX_SEALED_BYTES, newDocumentId, seal } from "./encrypted.js";
import { PaymentListError } from "./errors.js";
import { address, endpointPrefix, isMissing, listIdentifiers, readBytes, readText, statusOf } from "./io.js";
import { emptyRegistry, parseRegistry, registerMissingApps, serializeRegistry } from "./registry.js";
/** Shown in the identity's session list on its homeserver. */
const CLIENT_ID = "paykit-discovery";
const REGISTRY_PATH = "/pub/paykit/v0/app-registry.json";
const MAX_REQUESTS = 512;
const LOCK_SECONDS = 60;
const LOCK_ATTEMPTS = 8;
const encoder = new TextEncoder();
/**
 * Sign in as the identity and publish an already validated list.
 * `document` is the serialized plaintext for encrypted mode.
 */
export async function publish(secret, apps, document) {
    let pubky;
    let keypair;
    let signer;
    let session;
    let storage;
    let publicStorage;
    try {
        keypair = Keypair.fromSecret(secret);
        const ownerKey = keypair.publicKey;
        const owner = ownerKey.z32();
        ownerKey.free();
        pubky = new Pubky();
        signer = pubky.signer(keypair);
        try {
            session = await signer.signin(CLIENT_ID);
        }
        catch (cause) {
            throw new PaymentListError("AUTH", "Could not sign in to the identity's homeserver", { cause });
        }
        storage = session.storage;
        if (document !== undefined) {
            return { pubky: owner, encrypted: true, access: await publishEncrypted(storage, secret, owner, document) };
        }
        publicStorage = new PublicStorage();
        await publishPublic(storage, publicStorage, owner, apps);
        return { pubky: owner, encrypted: false };
    }
    catch (cause) {
        if (cause instanceof PaymentListError)
            throw cause;
        throw new PaymentListError("TRANSPORT", "Could not publish the Payment List", { cause });
    }
    finally {
        // A failed sign-out leaves the session to expire; it never changes the result.
        if (session) {
            try {
                await session.signout();
            }
            catch { /* best effort */ }
        }
        for (const owned of [publicStorage, storage, session, signer, keypair, pubky])
            owned?.free();
    }
}
async function publishPublic(storage, publicStorage, owner, apps) {
    // Register Apps first so every endpoint written below is discoverable. A
    // malformed registry is never overwritten, and a concurrent change fails.
    const raw = await readText(publicStorage, address(owner, REGISTRY_PATH), MAX_DOCUMENT_BYTES);
    const registry = raw === null ? emptyRegistry() : parseRegistry(raw);
    if (registerMissingApps(registry, apps.map(({ appId }) => appId))) {
        await putIfUnchanged(storage, REGISTRY_PATH, serializeRegistry(registry), raw === null ? null : encoder.encode(raw), MAX_DOCUMENT_BYTES);
    }
    // Replace each named App's endpoints; Apps not in the list are untouched.
    let requests = MAX_REQUESTS;
    const request = () => {
        if (requests-- <= 0)
            throw new PaymentListError("RESOURCE_LIMIT", "Payment List request limit exceeded");
    };
    for (const { appId, endpoints } of apps) {
        const existing = await listIdentifiers(publicStorage, owner, appId, request, MAX_ENDPOINTS);
        for (const { identifier, payload } of endpoints) {
            await withLock(storage, endpointPrefix(appId) + identifier, (lock) => storage.putTextLocked(lock, payload));
        }
        const kept = new Set(endpoints.map(({ identifier }) => identifier));
        for (const identifier of existing) {
            if (kept.has(identifier))
                continue;
            await withLock(storage, endpointPrefix(appId) + identifier, async (lock) => {
                try {
                    await storage.deleteLocked(lock);
                }
                catch (cause) {
                    if (!isMissing(cause))
                        throw cause;
                }
            });
        }
    }
}
async function publishEncrypted(storage, secret, owner, document) {
    const id = newDocumentId();
    const path = documentPath(id);
    const key = await deriveKey(secret, path);
    try {
        const sealed = await seal(key, crypto.getRandomValues(new Uint8Array(12)), owner, path, document);
        // Create-only: an existing document at this path is never overwritten.
        await putIfUnchanged(storage, path, sealed, null, MAX_SEALED_BYTES);
        return formatAccess(id, key);
    }
    finally {
        key.fill(0);
    }
}
/**
 * Run a write under an exclusive Pubky lock, like Paykit Library's
 * `with_write_lock`: contended locks are retried with bounded backoff, and the
 * lock is released afterward. Writes here are short, so the 60-second lock is
 * not renewed.
 */
async function withLock(storage, path, operation) {
    let lock;
    for (let attempt = 1; lock === undefined; attempt++) {
        try {
            lock = await storage.lock(path, LOCK_SECONDS);
        }
        catch (cause) {
            if (statusOf(cause) !== 423 || attempt >= LOCK_ATTEMPTS) {
                throw new PaymentListError("TRANSPORT", "Could not lock a Paykit document for writing", { cause });
            }
            await new Promise((resolve) => setTimeout(resolve, 50 * attempt));
        }
    }
    try {
        return await operation(lock);
    }
    catch (cause) {
        if (cause instanceof PaymentListError)
            throw cause;
        throw new PaymentListError("TRANSPORT", "Could not write a Paykit document", { cause });
    }
    finally {
        try {
            await storage.unlock(lock);
        }
        catch { /* the lock expires on its own */ }
        lock.free();
    }
}
/**
 * Replace a document only if it still holds `expected` (`null` means absent),
 * checked under the write lock, like Paykit Library's `put_resource_if_revision`.
 */
async function putIfUnchanged(storage, path, body, expected, limit) {
    await withLock(storage, path, async (lock) => {
        const current = await readBytes(() => storage.get(path), limit);
        if (!sameBytes(current, expected)) {
            throw new PaymentListError("TRANSPORT", "A Paykit document changed during the update; read it again and retry");
        }
        if (typeof body === "string")
            await storage.putTextLocked(lock, body);
        else
            await storage.putBytesLocked(lock, body);
    });
}
function sameBytes(left, right) {
    if (left === null || right === null)
        return left === right;
    return left.byteLength === right.byteLength && left.every((byte, index) => byte === right[index]);
}
//# sourceMappingURL=publish.js.map