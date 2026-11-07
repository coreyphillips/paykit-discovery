import { PublicKey, type Pubky, type Signer } from "@synonymdev/pubky";
import { PaymentListError } from "./errors.js";
import { statusOf } from "./io.js";

/** Homegate issues homeserver signup codes limited per IP address. */
const SIGNUP_CODE_URL = "https://homegate.pubky.app/ip_verification";
/** The Pkarr relays the Pubky SDK resolves through by default. */
const PKARR_RELAYS = ["https://pkarr.pubky.app", "https://pkarr.pubky.org"];
/** How long relays get to answer, matching the SDK's own relay requests. */
const RELAY_TIMEOUT_MS = 5_000;
/** Generous, because a request that times out may still have used a signup code. */
const HOMEGATE_TIMEOUT_MS = 30_000;

/**
 * Sign up the identity if, and only if, no homeserver record for it can be found.
 *
 * Signup force-publishes the homeserver record, so running it for an identity
 * that has one would point that identity away from its data. The decision comes
 * from the record, never from a failed sign-in, which does not show that no
 * account exists. An identity with a record continues to sign-in unchanged.
 */
export async function ensureHomeserver(pubky: Pubky, signer: Signer, owner: PublicKey): Promise<void> {
  if (await hasRecord(pubky, owner)) return;
  const { signupCode, homeserver } = await requestSignupCode();
  try { await createAccount(signer, homeserver, signupCode); }
  finally { homeserver.free(); }
}

async function hasRecord(pubky: Pubky, owner: PublicKey): Promise<boolean> {
  let homeserver: PublicKey | undefined;
  try { homeserver = await pubky.getHomeserverOf(owner); }
  catch (cause) { throw new PaymentListError("TRANSPORT", "Could not look up the identity's homeserver", { cause }); }
  if (homeserver) {
    homeserver.free();
    return true;
  }
  // "Not found" above is weak evidence, because that lookup reports an expired
  // record as not found. Relays keep expired records, so ask them directly. The
  // SDK does not expose this policy. Relays do not all hold the same records, and
  // signing up over one costs far more than a retry, so one relay holding a record
  // settles it and "no record" needs every relay to say so.
  const key = owner.z32();
  const signal = AbortSignal.timeout(RELAY_TIMEOUT_MS);
  const statuses = PKARR_RELAYS.map((relay) => relayStatus(`${relay}/${key}?policy=CacheOnly`, signal));
  if (await anyRelayHoldsRecord(statuses)) return true;
  if ((await Promise.all(statuses)).every((status) => status === 404)) return false;
  throw new PaymentListError("TRANSPORT", "Could not look up the identity's homeserver");
}

/** True as soon as one relay answers 200, so a stalled relay is not waited for. */
function anyRelayHoldsRecord(statuses: Promise<number | undefined>[]): Promise<boolean> {
  const found = statuses.map(async (status) => {
    if (await status !== 200) throw new Error("no record");
  });
  return Promise.any(found).then(() => true, () => false);
}

async function relayStatus(url: string, signal: AbortSignal): Promise<number | undefined> {
  try {
    const response = await fetch(url, { signal });
    await response.body?.cancel();
    return response.status;
  } catch {
    return undefined;
  }
}

async function createAccount(signer: Signer, homeserver: PublicKey, signupCode: string): Promise<void> {
  try {
    await signer.signup(homeserver, signupCode);
    return;
  } catch (cause) {
    const status = statusOf(cause);
    // No cause here: the SDK sends the code in the URL, and its errors can quote that URL.
    if (status !== 409) throw new PaymentListError("AUTH", `Could not sign up on the homeserver${status === undefined ? "" : `: status ${status}`}`);
  }
  // The account exists, so an earlier call failed before publishing its record.
  // publishHomeserverForce takes ownership of its argument, so it gets its own copy.
  const pkdns = signer.pkdns;
  try { await pkdns.publishHomeserverForce(PublicKey.from(homeserver.z32())); }
  finally { pkdns.free(); }
}

async function requestSignupCode(): Promise<{ signupCode: string; homeserver: PublicKey }> {
  let response: Response;
  let body: string;
  try {
    response = await fetch(SIGNUP_CODE_URL, { method: "POST", signal: AbortSignal.timeout(HOMEGATE_TIMEOUT_MS) });
    body = await response.text();
  } catch (cause) {
    throw new PaymentListError("TRANSPORT", "Could not reach Homegate", { cause });
  }
  if (response.status === 429) {
    throw new PaymentListError("RATE_LIMITED", "Homegate's signup limit for this IP address has been reached");
  }
  if (!response.ok) throw new PaymentListError("TRANSPORT", `Homegate returned status ${response.status}`);
  return parseSignupCode(body);
}

function parseSignupCode(body: string): { signupCode: string; homeserver: PublicKey } {
  // No cause here: a JSON parse error can quote the body, which may hold a signup code.
  const invalid = (): PaymentListError => new PaymentListError("INVALID_DATA", "Homegate returned an invalid response");
  let parsed: { signupCode?: unknown; homeserverPubky?: unknown } | null;
  try { parsed = JSON.parse(body); } catch { throw invalid(); }
  const signupCode = parsed?.signupCode;
  const homeserverPubky = parsed?.homeserverPubky;
  if (typeof signupCode !== "string" || signupCode.length === 0 || typeof homeserverPubky !== "string") throw invalid();
  let homeserver: PublicKey;
  try { homeserver = PublicKey.from(homeserverPubky); } catch { throw invalid(); }
  if (homeserver.z32() !== homeserverPubky) {
    homeserver.free();
    throw invalid();
  }
  return { signupCode, homeserver };
}
