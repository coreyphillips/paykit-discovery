import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";
import { readFileSync } from "node:fs";
import { Keypair, Pkdns, Pubky, PublicKey, Signer } from "@synonymdev/pubky";
import { PaymentListError } from "../dist/index.js";
import { ensureHomeserver } from "../dist/signup.js";

const fixture = JSON.parse(readFileSync(new URL("../../fixtures/publishing.json", import.meta.url), "utf8"));
const secretHex = fixture.secrets[0].secret_hex;
const owner = fixture.secrets[0].pubky;
const homeserver = "5jsjx1o6fzu6aeeo697r3i5rx15zq41kikcye8wtwdqm4nb4tryo";
const signupCode = "FAKE-SIGN-UPCD";
const homegateUrl = "https://homegate.pubky.app/ip_verification";
const relayUrls = [
  `https://pkarr.pubky.app/${owner}?policy=CacheOnly`,
  `https://pkarr.pubky.org/${owner}?policy=CacheOnly`,
];
const originals = {
  fetch: globalThis.fetch,
  timeout: AbortSignal.timeout,
  lookup: Pubky.prototype.getHomeserverOf,
  signup: Signer.prototype.signup,
  publish: Pkdns.prototype.publishHomeserverForce,
};

let requests;
let deadlines;
let signups;
let published;
let record;
let relays;
let homegateResponse;

function expectCode(code) { return (error) => error instanceof PaymentListError && error.code === code; }
function homegateAnswers(status, body) { homegateResponse = () => new Response(body, { status }); }
function homegateCalls() { return requests.filter(([url]) => url === homegateUrl); }
function failed() { throw new TypeError("fetch failed"); }
function stalled(init) {
  return new Promise((_, reject) => { init?.signal?.addEventListener("abort", () => reject(init.signal.reason)); });
}
function requestError(statusCode) {
  return Object.assign(new Error(`status ${statusCode}`), { name: "RequestError", data: { statusCode } });
}

async function ensure() {
  const keypair = Keypair.fromSecret(Uint8Array.from(secretHex.match(/../g), (byte) => parseInt(byte, 16)));
  const key = keypair.publicKey;
  const pubky = new Pubky();
  const signer = pubky.signer(keypair);
  try { await ensureHomeserver(pubky, signer, key); }
  finally { for (const owned of [signer, key, keypair, pubky]) owned.free(); }
}

beforeEach(() => {
  requests = [];
  deadlines = [];
  signups = [];
  published = [];
  record = () => undefined;
  relays = [() => new Response(null, { status: 404 }), () => new Response(null, { status: 404 })];
  homegateAnswers(200, JSON.stringify({ signupCode, homeserverPubky: homeserver }));
  globalThis.fetch = async (url, init) => {
    const target = String(url);
    requests.push([target, init?.method ?? "GET"]);
    const relay = relayUrls.indexOf(target);
    return relay === -1 ? homegateResponse(init) : relays[relay](init);
  };
  // Keep the tests fast while still seeing which deadline was asked for.
  AbortSignal.timeout = (milliseconds) => { deadlines.push(milliseconds); return originals.timeout.call(AbortSignal, 1); };
  Pubky.prototype.getHomeserverOf = async function () { return record(); };
  Signer.prototype.signup = async function (target, code) { signups.push([target.z32(), code]); };
  // Like the SDK, this takes ownership of its argument, which leaves it unusable.
  Pkdns.prototype.publishHomeserverForce = async function (target) { published.push(target.z32()); target.__destroy_into_raw(); };
});

afterEach(() => {
  globalThis.fetch = originals.fetch;
  AbortSignal.timeout = originals.timeout;
  Pubky.prototype.getHomeserverOf = originals.lookup;
  Signer.prototype.signup = originals.signup;
  Pkdns.prototype.publishHomeserverForce = originals.publish;
});

test("an identity with no record signs up with the code and homeserver Homegate returns", async () => {
  await ensure();
  assert.deepEqual(homegateCalls(), [[homegateUrl, "POST"]]);
  assert.deepEqual(signups, [[homeserver, signupCode]]);
});

test("an identity whose record resolves is left alone and uses no signup code", async () => {
  record = () => PublicKey.from(homeserver);
  await ensure();
  assert.deepEqual(requests, []);
  assert.deepEqual(signups, []);
});

test("a record only a relay still holds is never signed up over", async () => {
  relays[1] = () => new Response("packet", { status: 200 });
  await ensure();
  assert.deepEqual(homegateCalls(), []);
  assert.deepEqual(signups, []);
});

test("a record held by one relay wins over the other relay failing", async () => {
  relays[0] = () => { throw new TypeError("fetch failed"); };
  relays[1] = () => new Response("packet", { status: 200 });
  await ensure();
  assert.deepEqual(signups, []);
});

test("a record on one relay settles the lookup without waiting for a stalled relay", async () => {
  // A deadline that never fires, so only the found record can finish this lookup.
  AbortSignal.timeout = () => new AbortController().signal;
  relays[0] = stalled;
  relays[1] = () => new Response("packet", { status: 200 });
  await ensure();
  assert.deepEqual(homegateCalls(), []);
  assert.deepEqual(signups, []);
});

test("no record on one relay never signs up while another relay has not answered", async () => {
  for (const unanswered of [failed, () => new Response(null, { status: 503 }), stalled]) {
    relays[0] = unanswered;
    await assert.rejects(ensure(), expectCode("TRANSPORT"));
  }
  assert.deepEqual(homegateCalls(), []);
  assert.deepEqual(signups, []);
});

test("relays and Homegate each get a deadline", async () => {
  await ensure();
  assert.deepEqual(deadlines, [5_000, 30_000]);
});

test("a failed lookup never signs up, because it does not show there is no record", async () => {
  record = () => { throw new Error("relay unavailable"); };
  await assert.rejects(ensure(), expectCode("TRANSPORT"));
  assert.deepEqual(requests, []);
  assert.deepEqual(signups, []);
});

test("no relay answering never signs up", async () => {
  relays = [() => { throw new TypeError("fetch failed"); }, () => new Response(null, { status: 503 })];
  await assert.rejects(ensure(), expectCode("TRANSPORT"));
  assert.deepEqual(homegateCalls(), []);
  assert.deepEqual(signups, []);
});

test("Homegate's rate limit rejects with RATE_LIMITED and does not sign up", async () => {
  homegateAnswers(429, "Weekly limit exceeded");
  await assert.rejects(ensure(), expectCode("RATE_LIMITED"));
  assert.deepEqual(signups, []);
});

test("an unreachable, failing, or stalled Homegate rejects with TRANSPORT", async () => {
  homegateAnswers(500, "Homeserver unavailable");
  await assert.rejects(ensure(), expectCode("TRANSPORT"));
  for (const unanswered of [failed, stalled]) {
    homegateResponse = unanswered;
    await assert.rejects(ensure(), expectCode("TRANSPORT"));
  }
  assert.deepEqual(signups, []);
});

test("an invalid Homegate response rejects with INVALID_DATA without quoting it", async () => {
  const bodies = [
    "not json",
    "null",
    "[]",
    JSON.stringify({ signupCode }),
    JSON.stringify({ homeserverPubky: homeserver }),
    JSON.stringify({ signupCode: "", homeserverPubky: homeserver }),
    JSON.stringify({ signupCode: 1, homeserverPubky: homeserver }),
    JSON.stringify({ signupCode, homeserverPubky: "not-a-key" }),
    JSON.stringify({ signupCode, homeserverPubky: `pubky://${homeserver}` }),
  ];
  for (const body of bodies) {
    homegateAnswers(200, body);
    await assert.rejects(ensure(), (error) => {
      assert.ok(expectCode("INVALID_DATA")(error), body);
      assert.equal(error.cause, undefined);
      assert.ok(!error.message.includes(signupCode));
      return true;
    });
  }
  assert.deepEqual(signups, []);
});

test("a failed signup rejects with AUTH and keeps nothing that can quote the code", async () => {
  const url = `https://${homeserver}/auth/grant/signup?signup_token=${signupCode}`;
  const failures = [
    [new Error(`error sending request for url (${url})`), "Could not sign up on the homeserver"],
    [Object.assign(requestError(403), { message: `refused (${url})` }), "Could not sign up on the homeserver: status 403"],
  ];
  for (const [failure, message] of failures) {
    Signer.prototype.signup = async function () { throw failure; };
    await assert.rejects(ensure(), (error) => {
      assert.ok(expectCode("AUTH")(error));
      assert.equal(error.message, message);
      assert.equal(error.cause, undefined);
      return true;
    });
  }
});

test("an account that already exists gets its homeserver record published again", async () => {
  Signer.prototype.signup = async function () { throw requestError(409); };
  await ensure();
  assert.deepEqual(published, [homeserver]);
});
