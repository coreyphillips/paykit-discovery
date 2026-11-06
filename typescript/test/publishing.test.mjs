import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";
import { readFileSync } from "node:fs";
import { PublicStorage, Signer } from "@synonymdev/pubky";
import { getPaymentList, PaymentListError, setPaymentList } from "../dist/index.js";
import { deriveKey, documentPath, formatAccess, open, parseAccess, parseDocument, seal, serializeDocument, toHex } from "../dist/encrypted.js";
import { flattenEndpoints, validateEndpoints } from "../dist/endpoints.js";
import { emptyRegistry, parseRegistry, registerMissingApps, serializeRegistry } from "../dist/registry.js";

const fixture = JSON.parse(readFileSync(new URL("../../fixtures/publishing.json", import.meta.url), "utf8"));
const mnemonic = fixture.secrets[0].mnemonic;
const secretHex = fixture.secrets[0].secret_hex;
const owner = fixture.secrets[0].pubky;
const base = `pubky://${owner}`;
const registryPath = "/pub/paykit/v0/app-registry.json";
const encryptedPrefix = "/pub/paykit-discovery/v1/encrypted/";
const encoder = new TextEncoder();
const originals = { get: PublicStorage.prototype.get, list: PublicStorage.prototype.list, signin: Signer.prototype.signin };

let files;
let calls;
let signins;
let signouts;
let locks;
let hooks;

function requestError(statusCode) {
  return Object.assign(new Error(`status ${statusCode}`), { name: "RequestError", data: { statusCode } });
}
function fromHex(hex) { return Uint8Array.from(hex.match(/../g) ?? [], (byte) => parseInt(byte, 16)); }
function text(path) { return new TextDecoder().decode(files.get(path)); }
function expectCode(code) { return (error) => error instanceof PaymentListError && error.code === code; }
function network() { return calls.length + signins.length; }
function endpoint(appId, identifier, payload) { return { appId, identifier, payload }; }
function fixtureEndpoints(list) { return list.map(({ app_id, identifier, payload }) => endpoint(app_id, identifier, payload)); }
function endpointPath(appId, identifier) { return `/pub/paykit/v0/apps/${appId}/endpoints/${identifier}`; }

function fakeSession() {
  const storage = {
    async lock(path) {
      calls.push(["lock", path]);
      if (hooks.lock) await hooks.lock(path);
      if (locks.has(path)) throw requestError(423);
      locks.add(path);
      return { path, free() {} };
    },
    async unlock(lock) { calls.push(["unlock", lock.path]); locks.delete(lock.path); },
    async get(path) {
      calls.push(["session-get", path]);
      const body = files.get(path);
      if (body === undefined) throw requestError(404);
      return new Response(body);
    },
    async putTextLocked(lock, body) {
      calls.push(["put", lock.path]);
      if (hooks.put) await hooks.put(lock.path);
      files.set(lock.path, encoder.encode(body));
    },
    async putBytesLocked(lock, body) {
      calls.push(["put", lock.path]);
      if (hooks.put) await hooks.put(lock.path);
      files.set(lock.path, body.slice());
    },
    async deleteLocked(lock) {
      calls.push(["delete", lock.path]);
      if (!files.has(lock.path)) throw requestError(404);
      files.delete(lock.path);
    },
    free() {},
  };
  return { storage, async signout() { signouts++; if (hooks.signout) await hooks.signout(); }, free() {} };
}

beforeEach(() => {
  files = new Map();
  calls = [];
  signins = [];
  signouts = 0;
  locks = new Set();
  hooks = {};
  PublicStorage.prototype.get = async function (location) {
    calls.push(["get", location]);
    const body = location.startsWith(base + "/") ? files.get(location.slice(base.length)) : undefined;
    return body === undefined ? new Response(null, { status: 404 }) : new Response(body);
  };
  PublicStorage.prototype.list = async function (location, cursor, reverse, limit) {
    calls.push(["list", location]);
    const prefix = location.slice(base.length);
    return [...files.keys()].filter((path) => path.startsWith(prefix)).sort()
      .filter((path) => !cursor || owner + path > cursor).slice(0, limit).map((path) => base + path);
  };
  Signer.prototype.signin = async function (clientId) {
    const key = this.publicKey;
    signins.push({ clientId, pubky: key.z32() });
    key.free();
    if (hooks.signin) await hooks.signin();
    return fakeSession();
  };
});

afterEach(() => {
  PublicStorage.prototype.get = originals.get;
  PublicStorage.prototype.list = originals.list;
  Signer.prototype.signin = originals.signin;
});

test("a mnemonic, its hex secret, and its 32 bytes publish as the same pubky", async () => {
  const bytes = fromHex(secretHex);
  const inputs = [mnemonic, secretHex, bytes, ...fixture.equivalent_secret_inputs];
  for (const input of inputs) {
    const result = await setPaymentList(input, [endpoint("bitkit", "btc-bitcoin-p2tr", "bc1p")]);
    assert.deepEqual(result, { pubky: owner, encrypted: false });
  }
  assert.deepEqual(signins.map(({ pubky }) => pubky), inputs.map(() => owner));
  assert.ok(signins.every(({ clientId }) => clientId === "paykit-discovery"));
  assert.equal(signouts, inputs.length);
  assert.deepEqual(bytes, fromHex(secretHex), "the caller's secret bytes are not modified");
  for (const vector of fixture.secrets) {
    const result = await setPaymentList(vector.mnemonic, [endpoint("bitkit", "btc", "x")], true);
    assert.equal(result.pubky, vector.pubky);
  }
});

test("invalid secrets and input fail before any network access", async () => {
  const valid = [endpoint("bitkit", "btc", "x")];
  for (const secret of [...fixture.invalid_secrets, new Uint8Array(31), new Uint8Array(33), 42, null, undefined, [1, 2]]) {
    await assert.rejects(setPaymentList(secret, valid), expectCode("INVALID_SECRET"));
  }
  const lone = "\ud800";
  for (const details of [
    [], undefined, "x", [null], [{ appId: "bitkit", identifier: "btc" }],
    [endpoint("Bitkit", "btc", "x")], [endpoint("", "btc", "x")], [endpoint("a".repeat(65), "btc", "x")],
    [endpoint("bitkit", "private", "x")], [endpoint("bitkit", "..", "x")], [endpoint("bitkit", "a/b", "x")],
    [endpoint("bitkit", "btc", "")], [endpoint("bitkit", "btc", lone)], [endpoint("bitkit", "btc", "x".repeat(65537))],
    [endpoint("bitkit", "btc", "x"), endpoint("bitkit", "btc", "y")],
    Array.from({ length: 257 }, (_, index) => endpoint("app", `e${index}`, "x")),
    Array.from({ length: 65 }, (_, index) => endpoint(`app${index}`, "e", "x")),
    Array.from({ length: 65 }, (_, index) => endpoint("app", `e${index}`, "x".repeat(65536))),
  ]) {
    await assert.rejects(setPaymentList(mnemonic, details), expectCode("INVALID_INPUT"));
    await assert.rejects(setPaymentList(mnemonic, details, true), expectCode("INVALID_INPUT"));
  }
  await assert.rejects(setPaymentList(mnemonic, valid, "yes"), expectCode("INVALID_INPUT"));
  assert.equal(network(), 0);
});

test("public mode creates the App Registry and round-trips through getPaymentList", async () => {
  const details = [
    endpoint("savings", "btc-lightning-bolt12", "lno1savings"),
    endpoint("bitkit", "btc-bitcoin-p2tr", "bc1pbitkit"),
    endpoint("bitkit", "btc-lightning-bolt12", "lno1bitkit"),
  ];
  assert.deepEqual(await setPaymentList(mnemonic, details), { pubky: owner, encrypted: false });
  assert.equal(text(registryPath), fixture.registry.create.expected);
  assert.deepEqual(await getPaymentList(owner), [
    endpoint("bitkit", "btc-bitcoin-p2tr", "bc1pbitkit"),
    endpoint("bitkit", "btc-lightning-bolt12", "lno1bitkit"),
    endpoint("savings", "btc-lightning-bolt12", "lno1savings"),
  ]);
  assert.equal(locks.size, 0, "every lock is released");
  assert.equal(signouts, 1);
});

test("public mode keeps every registry field and replaces only the named Apps", async () => {
  const merge = fixture.registry.merge;
  files.set(registryPath, encoder.encode(merge.input));
  files.set(endpointPath("bitkit", "btc-lightning-bolt12"), encoder.encode("old-bolt12"));
  files.set(endpointPath("bitkit", "btc-bitcoin-p2tr"), encoder.encode("old-p2tr"));
  files.set(endpointPath("savings", "btc-bitcoin-p2tr"), encoder.encode("savings-p2tr"));
  await setPaymentList(mnemonic, [
    endpoint("bitkit", "btc-lightning-bolt12", "new-bolt12"),
    endpoint("new-app", "btc-bitcoin-p2tr", "new-app-p2tr"),
  ]);
  assert.equal(text(registryPath), merge.expected);
  assert.equal(text(endpointPath("bitkit", "btc-lightning-bolt12")), "new-bolt12");
  assert.equal(files.has(endpointPath("bitkit", "btc-bitcoin-p2tr")), false);
  assert.equal(text(endpointPath("savings", "btc-bitcoin-p2tr")), "savings-p2tr");
  assert.equal(text(endpointPath("new-app", "btc-bitcoin-p2tr")), "new-app-p2tr");
  assert.ok(!calls.some(([kind, path]) => kind !== "get" && kind !== "list" && path.includes("/savings/")));
});

test("the registry is written only when an App is missing", async () => {
  await setPaymentList(mnemonic, [endpoint("bitkit", "btc", "one")]);
  const registry = text(registryPath);
  calls = [];
  await setPaymentList(mnemonic, [endpoint("bitkit", "btc", "two")]);
  assert.equal(text(registryPath), registry);
  assert.ok(!calls.some(([kind, path]) => kind === "lock" && path === registryPath));
  assert.equal(text(endpointPath("bitkit", "btc")), "two");
});

test("registry writes match Paykit Library's serializer byte for byte", () => {
  const created = emptyRegistry();
  assert.equal(registerMissingApps(created, fixture.registry.create.app_ids), true);
  assert.equal(serializeRegistry(created), fixture.registry.create.expected);
  const merged = parseRegistry(fixture.registry.merge.input);
  assert.equal(registerMissingApps(merged, fixture.registry.merge.app_ids), true);
  assert.equal(serializeRegistry(merged), fixture.registry.merge.expected);
  assert.equal(registerMissingApps(merged, ["bitkit"]), false);
  const full = emptyRegistry();
  registerMissingApps(full, Array.from({ length: 60 }, (_, index) => `app${index}`));
  assert.throws(() => registerMissingApps(full, Array.from({ length: 5 }, (_, index) => `more${index}`)), expectCode("RESOURCE_LIMIT"));
});

test("a concurrent registry change rejects instead of being overwritten", async () => {
  files.set(registryPath, encoder.encode(fixture.registry.create.expected));
  const concurrent = fixture.registry.merge.input;
  hooks.lock = async (path) => { if (path === registryPath) files.set(registryPath, encoder.encode(concurrent)); };
  await assert.rejects(setPaymentList(mnemonic, [endpoint("new-app", "btc", "x")]), expectCode("TRANSPORT"));
  assert.equal(text(registryPath), concurrent);
  assert.ok(!calls.some(([kind]) => kind === "put"));
  assert.equal(locks.size, 0);
  assert.equal(signouts, 1);
});

test("a malformed registry is never overwritten", async () => {
  files.set(registryPath, encoder.encode("{\"version\":1"));
  await assert.rejects(setPaymentList(mnemonic, [endpoint("bitkit", "btc", "x")]), expectCode("INVALID_DATA"));
  assert.equal(text(registryPath), "{\"version\":1");
  assert.ok(!calls.some(([kind]) => kind === "put" || kind === "lock"));
});

test("a failed write rejects and still signs out", async () => {
  hooks.put = async (path) => { if (path.endsWith("/second")) throw new Error("disk full"); };
  await assert.rejects(setPaymentList(mnemonic, [endpoint("bitkit", "first", "1"), endpoint("bitkit", "second", "2")]), expectCode("TRANSPORT"));
  assert.equal(signouts, 1);
  assert.equal(locks.size, 0);
});

test("sign-in failures reject with AUTH and write nothing", async () => {
  hooks.signin = async () => { throw requestError(404); };
  for (const encrypted of [false, true]) {
    await assert.rejects(setPaymentList(mnemonic, [endpoint("bitkit", "btc", "x")], encrypted), expectCode("AUTH"));
  }
  assert.equal(files.size, 0);
  assert.equal(signouts, 0);
});

test("a sign-out failure does not change the result", async () => {
  hooks.signout = async () => { throw new Error("offline"); };
  assert.equal((await setPaymentList(mnemonic, [endpoint("bitkit", "btc", "x")])).pubky, owner);
});

test("contended locks are retried with backoff, then rejected", async () => {
  let contended = 2;
  hooks.lock = async () => { if (contended-- > 0) throw requestError(423); };
  await setPaymentList(mnemonic, [endpoint("bitkit", "btc", "x")]);
  assert.equal(text(endpointPath("bitkit", "btc")), "x");
  hooks.lock = async () => { throw requestError(423); };
  await assert.rejects(setPaymentList(mnemonic, [endpoint("bitkit", "btc", "y")]), expectCode("TRANSPORT"));
});

test("encrypted mode writes one document and nothing under /pub/paykit/", async () => {
  const details = fixtureEndpoints(fixture.encrypted.endpoints);
  const result = await setPaymentList(mnemonic, details, true);
  assert.equal(result.pubky, owner);
  assert.equal(result.encrypted, true);
  assert.match(result.access, /^v1\.[0-9a-f]{32}\.[0-9a-f]{64}$/);
  assert.deepEqual([...files.keys()], [encryptedPrefix + result.access.split(".")[1]]);
  assert.deepEqual(await getPaymentList(owner, result.access), fixtureEndpoints(fixture.encrypted.expected));
  assert.deepEqual(await getPaymentList(`pubky://${owner}`, ` ${result.access}\n`), fixtureEndpoints(fixture.encrypted.expected));
  assert.deepEqual(await getPaymentList(owner), [], "one-argument discovery never returns ciphertext");
  assert.equal(signouts, 1);
});

test("each recipient gets their own path and key, even for identical details", async () => {
  const lists = Array.from({ length: 5 }, (_, index) => [endpoint("shop", "btc-lightning-bolt11", `lnbc-invoice-${index % 2}`)]);
  const results = await Promise.all(lists.map((details) => setPaymentList(mnemonic, details, true)));
  const accesses = results.map(({ access }) => access);
  assert.equal(new Set(accesses).size, 5);
  assert.equal(new Set(accesses.map((access) => access.split(".")[1])).size, 5);
  assert.equal(new Set(accesses.map((access) => access.split(".")[2])).size, 5);
  assert.equal(files.size, 5);
  for (const [index, access] of accesses.entries()) assert.deepEqual(await getPaymentList(owner, access), lists[index]);
  const [first, second] = accesses.map((access) => access.split("."));
  await assert.rejects(getPaymentList(owner, `v1.${second[1]}.${first[2]}`), expectCode("INVALID_DATA"));
});

test("hierarchical keys match Pubky's published vectors", async () => {
  const secret = fromHex(fixture.hierarchical_keys.identity_secret_hex);
  for (const { path, key_hex } of fixture.hierarchical_keys.vectors) {
    assert.equal(toHex(await deriveKey(secret, path)), key_hex, path);
  }
});

test("encrypted documents match the shared vector byte for byte", async () => {
  const vector = fixture.encrypted;
  const key = await deriveKey(fromHex(vector.secret_hex), vector.path);
  assert.equal(documentPath(vector.id), vector.path);
  assert.equal(toHex(key), vector.key_hex);
  const plaintext = serializeDocument(flattenEndpoints(validateEndpoints(fixtureEndpoints(vector.endpoints), "INVALID_INPUT")));
  assert.equal(toHex(plaintext), vector.plaintext_hex);
  const sealed = await seal(key, fromHex(vector.nonce_hex), vector.owner, vector.path, plaintext);
  assert.equal(toHex(sealed), vector.sealed_hex);
  assert.equal(formatAccess(vector.id, key), vector.access);
  const access = parseAccess(vector.access);
  assert.equal(access.id, vector.id);
  assert.deepEqual(parseDocument(await open(access.key, vector.owner, vector.path, sealed)), fixtureEndpoints(vector.expected));
});

test("identifiers outside the known list publish and read back unchanged", async () => {
  const details = [endpoint("my-wallet", "Custom_v1.2", "x"), endpoint("my-wallet", "xmr-monero-subaddress", "y")];
  await setPaymentList(mnemonic, details);
  assert.deepEqual(await getPaymentList(owner), details);
});

test("reading rejects tampering, wrong keys, and moved documents", async () => {
  const vector = fixture.encrypted;
  const sealed = fromHex(vector.sealed_hex);
  files.set(vector.path, sealed);
  assert.deepEqual(await getPaymentList(owner, vector.access), fixtureEndpoints(vector.expected));
  for (const index of [0, 11, 12, sealed.length >> 1, sealed.length - 1]) {
    const tampered = sealed.slice();
    tampered[index] ^= 1;
    files.set(vector.path, tampered);
    await assert.rejects(getPaymentList(owner, vector.access), expectCode("INVALID_DATA"), `byte ${index}`);
  }
  files.set(vector.path, sealed.slice(0, 27));
  await assert.rejects(getPaymentList(owner, vector.access), expectCode("INVALID_DATA"));
  files.set(vector.path, new Uint8Array(0));
  await assert.rejects(getPaymentList(owner, vector.access), expectCode("INVALID_DATA"));
  files.set(vector.path, sealed);
  const wrongKey = vector.access.slice(0, -1) + (vector.access.endsWith("0") ? "1" : "0");
  await assert.rejects(getPaymentList(owner, wrongKey), expectCode("INVALID_DATA"));
  const movedId = "ffeeddccbbaa99887766554433221100";
  files.set(documentPath(movedId), sealed);
  await assert.rejects(getPaymentList(owner, `v1.${movedId}.${vector.key_hex}`), expectCode("INVALID_DATA"));
  files.set(documentPath(movedId), new Uint8Array(12 + (4 << 20) + 17));
  await assert.rejects(getPaymentList(owner, `v1.${movedId}.${vector.key_hex}`), expectCode("RESOURCE_LIMIT"));
});

test("a missing encrypted document rejects with NOT_FOUND, not an empty list", async () => {
  const access = `v1.${"0".repeat(32)}.${fixture.encrypted.key_hex}`;
  await assert.rejects(getPaymentList(owner, access), expectCode("NOT_FOUND"));
  for (const status of [404, 410]) {
    PublicStorage.prototype.get = async () => { throw requestError(status); };
    await assert.rejects(getPaymentList(owner, access), expectCode("NOT_FOUND"), `thrown ${status}`);
  }
  PublicStorage.prototype.get = async () => { throw requestError(500); };
  await assert.rejects(getPaymentList(owner, access), expectCode("TRANSPORT"));
});

test("invalid access strings and identities fail before network access", async () => {
  for (const access of [...fixture.invalid_access, 42, null]) {
    await assert.rejects(getPaymentList(owner, access), expectCode("INVALID_INPUT"));
  }
  await assert.rejects(getPaymentList("invalid", fixture.encrypted.access), expectCode("INVALID_PUBKY"));
  assert.equal(network(), 0);
});

test("the encrypted document parser is as strict as the Rust crate", () => {
  const valid = '{"version":1,"kind":"paykit-discovery.encrypted_payment_list","endpoints":[{"app_id":"bitkit","identifier":"btc","payload":"x"}]}';
  assert.deepEqual(parseDocument(encoder.encode(valid)), [endpoint("bitkit", "btc", "x")]);
  for (const document of [
    valid.replace('"version":1', '"version":2'),
    valid.replace('"version":1', '"version":1.0'),
    valid.replace('"version":1', '"version":"1"'),
    valid.replace('"version":1', '"version":1,"version":1'),
    valid.replace("encrypted_payment_list", "other"),
    valid.replace('"payload":"x"', '"payload":"x","extra":true'),
    valid.replace('"payload":"x"', '"payload":"x","payload":"x"'),
    valid.replace('"payload":"x"', '"payload":""'),
    valid.replace('"payload":"x"', '"payload":"\\ud800"'),
    valid.replace('"app_id":"bitkit"', '"app_id":"Bitkit"'),
    valid.replace('"identifier":"btc"', '"identifier":"private"'),
    valid.replace('"endpoints":[', '"endpoints":[{"app_id":"bitkit","identifier":"btc","payload":"y"},'),
    valid.replace(/"endpoints":\[.*\]/, '"endpoints":[]'),
    "﻿" + valid,
    "[]",
    "",
  ]) {
    assert.throws(() => parseDocument(encoder.encode(document)), expectCode("INVALID_DATA"), document);
  }
  assert.throws(() => parseDocument(Uint8Array.of(0xff)), expectCode("INVALID_DATA"));
});

test("errors never reveal secrets, mnemonics, or access keys", async () => {
  const forbidden = [secretHex, secretHex.slice(1), fixture.encrypted.key_hex, "abandon", "abound"];
  const errors = [];
  const capture = async (promise) => { try { await promise; } catch (error) { errors.push(error); } };
  await capture(setPaymentList(mnemonic.replace("about", "abound"), []));
  await capture(setPaymentList(secretHex.slice(1), []));
  await capture(setPaymentList(mnemonic, [endpoint("Bad", "btc", "x")], true));
  hooks.signin = async () => { throw requestError(500); };
  await capture(setPaymentList(mnemonic, [endpoint("bitkit", "btc", "x")], true));
  hooks.signin = undefined;
  files.set(fixture.encrypted.path, Uint8Array.of(...fromHex(fixture.encrypted.sealed_hex)).map((byte, index) => index === 20 ? byte ^ 1 : byte));
  await capture(getPaymentList(owner, fixture.encrypted.access));
  await capture(getPaymentList(owner, `v1.zz.${fixture.encrypted.key_hex}`));
  assert.equal(errors.length, 6);
  for (const error of errors) {
    const messages = [];
    for (let current = error; current; current = current.cause) messages.push(String(current), current.message ?? "", JSON.stringify(current) ?? "");
    for (const message of messages) for (const secret of forbidden) assert.ok(!message.includes(secret), message);
  }
});
