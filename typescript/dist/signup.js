import { PublicKey } from "@synonymdev/pubky";
import { PaymentListError } from "./errors.js";
import { statusOf } from "./io.js";
/** Homegate issues homeserver signup codes limited per IP address. */
const SIGNUP_CODE_URL = "https://homegate.pubky.app/ip_verification";
/** The Pkarr relays the Pubky SDK resolves through by default. */
const PKARR_RELAYS = ["https://pkarr.pubky.app", "https://pkarr.pubky.org"];
/**
 * Sign up the identity if, and only if, no homeserver record for it can be found.
 *
 * Signup force-publishes the homeserver record, so running it for an identity
 * that has one would point that identity away from its data. The decision comes
 * from the record, never from a failed sign-in, which does not show that no
 * account exists. An identity with a record continues to sign-in unchanged.
 */
export async function ensureHomeserver(pubky, signer, owner) {
    if (await hasRecord(pubky, owner))
        return;
    const { signupCode, homeserver } = await requestSignupCode();
    try {
        await createAccount(signer, homeserver, signupCode);
    }
    finally {
        homeserver.free();
    }
}
async function hasRecord(pubky, owner) {
    let homeserver;
    try {
        homeserver = await pubky.getHomeserverOf(owner);
    }
    catch (cause) {
        throw new PaymentListError("TRANSPORT", "Could not look up the identity's homeserver", { cause });
    }
    if (homeserver) {
        homeserver.free();
        return true;
    }
    // "Not found" above is weak evidence, because that lookup reports an expired
    // record as not found. Relays keep expired records, so ask them directly. The
    // SDK does not expose this policy. A record no reachable relay holds counts as
    // none, but with no relay answering nothing is known, so stop.
    const key = owner.z32();
    const statuses = await Promise.all(PKARR_RELAYS.map((relay) => relayStatus(`${relay}/${key}?policy=CacheOnly`)));
    if (statuses.includes(200))
        return true;
    if (statuses.includes(404))
        return false;
    throw new PaymentListError("TRANSPORT", "Could not look up the identity's homeserver");
}
async function relayStatus(url) {
    try {
        const response = await fetch(url);
        await response.body?.cancel();
        return response.status;
    }
    catch {
        return undefined;
    }
}
async function createAccount(signer, homeserver, signupCode) {
    try {
        await signer.signup(homeserver, signupCode);
        return;
    }
    catch (cause) {
        if (statusOf(cause) !== 409)
            throw new PaymentListError("AUTH", "Could not sign up on the homeserver", { cause });
    }
    // The account exists, so an earlier call failed before publishing its record.
    const pkdns = signer.pkdns;
    try {
        await pkdns.publishHomeserverForce(homeserver);
    }
    finally {
        pkdns.free();
    }
}
async function requestSignupCode() {
    let response;
    let body;
    try {
        response = await fetch(SIGNUP_CODE_URL, { method: "POST" });
        body = await response.text();
    }
    catch (cause) {
        throw new PaymentListError("TRANSPORT", "Could not reach Homegate", { cause });
    }
    if (response.status === 429) {
        throw new PaymentListError("RATE_LIMITED", "Homegate's signup limit for this IP address has been reached");
    }
    if (!response.ok)
        throw new PaymentListError("TRANSPORT", `Homegate returned status ${response.status}`);
    return parseSignupCode(body);
}
function parseSignupCode(body) {
    // No cause here: a JSON parse error can quote the body, which may hold a signup code.
    const invalid = () => new PaymentListError("INVALID_DATA", "Homegate returned an invalid response");
    let parsed;
    try {
        parsed = JSON.parse(body);
    }
    catch {
        throw invalid();
    }
    const signupCode = parsed?.signupCode;
    const homeserverPubky = parsed?.homeserverPubky;
    if (typeof signupCode !== "string" || signupCode.length === 0 || typeof homeserverPubky !== "string")
        throw invalid();
    let homeserver;
    try {
        homeserver = PublicKey.from(homeserverPubky);
    }
    catch {
        throw invalid();
    }
    if (homeserver.z32() !== homeserverPubky) {
        homeserver.free();
        throw invalid();
    }
    return { signupCode, homeserver };
}
//# sourceMappingURL=signup.js.map