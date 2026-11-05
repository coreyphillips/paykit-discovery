import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";
import { readFileSync } from "node:fs";
import { PublicStorage } from "@synonymdev/pubky";
import { getPaymentList, PaymentListError } from "../dist/index.js";
import { parseRegistry, serializeRegistry } from "../dist/registry.js";

const fixture = JSON.parse(readFileSync(new URL("../../fixtures/discovery.json", import.meta.url), "utf8"));
const owner = fixture.owner;
const base = `pubky://${owner}`;
const registryPath = "/pub/paykit/v0/app-registry.json";
const originalGet = PublicStorage.prototype.get;
const originalList = PublicStorage.prototype.list;
let documents;
let gets;
let lists;
let listHook;
let getHook;

beforeEach(() => {
  documents = new Map(fixture.documents.map(({ path, body }) => [path, body]));
  documents.set(registryPath, JSON.stringify(fixture.registry));
  gets = [];
  lists = [];
  listHook = undefined;
  getHook = undefined;
  PublicStorage.prototype.get = async function (address) {
    gets.push(address);
    if (getHook) return getHook(address);
    const body = documents.get(address.slice(base.length));
    return body === undefined ? new Response(null, { status: 404 }) : new Response(body);
  };
  PublicStorage.prototype.list = async function (address, cursor, reverse, limit, shallow) {
    lists.push({ address, cursor, reverse, limit, shallow });
    if (listHook) return listHook(address, cursor, reverse, limit, shallow);
    const prefix = address.slice(base.length);
    return [...documents.keys()].filter((path) => path.startsWith(prefix))
      .sort().filter((path) => !cursor || owner + path > cursor)
      .slice(0, limit).map((path) => base + path);
  };
});

afterEach(() => {
  PublicStorage.prototype.get = originalGet;
  PublicStorage.prototype.list = originalList;
});

function expectCode(code) {
  return (error) => error instanceof PaymentListError && error.code === code;
}
function setRegistry(update) {
  const registry = structuredClone(fixture.registry);
  update(registry);
  documents.set(registryPath, JSON.stringify(registry));
}
function onlyBitkit() {
  setRegistry((registry) => {
    delete registry.apps.savings;
    registry.default_apps_by_endpoint = {};
  });
  for (const path of documents.keys()) if (path.includes("/savings/")) documents.delete(path);
}

test("shared fixture: preserves App attribution and honors endpoint-specific defaults", async () => {
  assert.deepEqual(await getPaymentList(owner), fixture.expected.map(({ app_id, ...endpoint }) => ({ appId: app_id, ...endpoint })));
  assert.equal(gets.length, 5);
  assert.equal(lists.length, 2);
  assert.ok(lists.every(({ reverse, limit, shallow }) => reverse === false && limit === 100 && shallow === true));
});

test("accepts bare, prefixed and URL identities with surrounding whitespace", async () => {
  for (const input of [owner, `pubky${owner}`, `pubky://${owner}`, ` \n${owner}\t`, `\u0085${owner}\u0085`]) {
    assert.equal((await getPaymentList(input)).length, 4);
  }
});

test("rejects malformed identities and resource URLs before network access", async () => {
  for (const input of ["", owner.toUpperCase(), `pubky://${owner}/`, `${owner}?x=1`, `${owner}#x`, `https://${owner}`, owner.slice(1), 42]) {
    await assert.rejects(getPaymentList(input), expectCode("INVALID_PUBKY"));
  }
  assert.equal(gets.length, 0);
  assert.equal(lists.length, 0);
});

test("does not confuse a bare key beginning with pubky with a prefix", async () => {
  getHook = async () => new Response(null, { status: 404 });
  assert.deepEqual(await getPaymentList("pubky" + "y".repeat(45) + "by"), []);
});

test("missing registry, App directory, or endpoint is ordinary absence", async () => {
  documents.delete(registryPath);
  assert.deepEqual(await getPaymentList(owner), []);
  assert.equal(lists.length, 0);
  documents.set(registryPath, JSON.stringify(fixture.registry));
  listHook = async () => { throw { name: "RequestError", data: { statusCode: 410 } }; };
  assert.deepEqual(await getPaymentList(owner), []);
  listHook = async (address) => [address + "btc-lightning-bolt12"];
  getHook = async (address) => address.endsWith(registryPath)
    ? new Response(JSON.stringify(fixture.registry)) : new Response(null, { status: 410 });
  assert.deepEqual(await getPaymentList(owner), []);
});

test("empty payloads are skipped and whitespace payloads are preserved", async () => {
  onlyBitkit();
  documents.set("/pub/paykit/v0/apps/bitkit/endpoints/btc-lightning-bolt12", "");
  documents.set("/pub/paykit/v0/apps/bitkit/endpoints/btc-bitcoin-p2tr", " \n");
  assert.deepEqual(await getPaymentList(owner), [{ appId: "bitkit", identifier: "btc-bitcoin-p2tr", payload: " \n" }]);
});

test("an App transport error rejects instead of returning partial success", async () => {
  listHook = async (address) => {
    if (address.includes("/savings/")) throw new Error("offline");
    return [address + "btc-lightning-bolt12"];
  };
  await assert.rejects(getPaymentList(owner), expectCode("TRANSPORT"));
  assert.ok(gets.some((address) => address.includes("/bitkit/endpoints/")));
});

test("server failures do not masquerade as missing data", async () => {
  getHook = async () => new Response(null, { status: 503 });
  await assert.rejects(getPaymentList(owner), expectCode("TRANSPORT"));
});

test("rejects invalid registry schemas and defaults", async () => {
  for (const update of [
    (r) => { r.version = 2; },
    (r) => { r.kind = "other"; },
    (r) => { r.key_generation = 0; },
    (r) => { r.key_generation = 1.5; },
    (r) => { r.extra = true; },
    (r) => { r.default_app_id = "unknown"; },
    (r) => { r.default_apps_by_endpoint.private = "bitkit"; },
    (r) => { r.apps.Bad = r.apps.bitkit; },
    (r) => { r.apps.bitkit.extra = true; },
    (r) => { r.apps.bitkit.capabilities.extra = true; },
    (r) => { r.apps.bitkit.capabilities.private_payments = true; },
    (r) => { r.apps.bitkit.display_name = "\u0085"; },
    (r) => { r.apps.bitkit.display_name = "\ud800"; },
    (r) => { r.apps.bitkit.display_name = "x".repeat(129); },
    (r) => { delete r.apps.bitkit.capabilities.receipts; },
  ]) {
    setRegistry(update);
    await assert.rejects(getPaymentList(owner), expectCode("INVALID_DATA"));
  }
});

test("duplicate JSON keys, including escaped aliases, are rejected", async () => {
  for (const text of [
    JSON.stringify(fixture.registry).replace('"version":1', '"version":1,"version":1'),
    JSON.stringify(fixture.registry).replace('"version":1', '"version":1,"ver\\u0073ion":1'),
    JSON.stringify(fixture.registry).replace('"receipts":false', '"receipts":false,"receipts":false'),
  ]) {
    documents.set(registryPath, text);
    await assert.rejects(getPaymentList(owner), expectCode("INVALID_DATA"));
  }
});

test("registry Noise keys accept exactly the forms Paykit Library accepts", async () => {
  assert.ok(fixture.noise_public_keys.cases.some(({ z32 }) => z32 === null));
  for (const { value, z32 } of fixture.noise_public_keys.cases) {
    setRegistry((registry) => { registry.noise_public_key = value; });
    if (z32 === null) {
      await assert.rejects(getPaymentList(owner), expectCode("INVALID_DATA"), JSON.stringify(value));
      assert.throws(() => parseRegistry(documents.get(registryPath)), expectCode("INVALID_DATA"));
    } else {
      assert.equal((await getPaymentList(owner)).length, 4, JSON.stringify(value));
      // Writes use the canonical key, as Paykit Library's serializer does.
      const registry = parseRegistry(documents.get(registryPath));
      assert.equal(registry.noiseKey, z32);
      assert.ok(serializeRegistry(registry).includes(`"noise_public_key":"${z32}"`));
    }
  }
  setRegistry((registry) => { registry.noise_public_key = 42; });
  await assert.rejects(getPaymentList(owner), expectCode("INVALID_DATA"));
});

test("u64 key generations are checked without floating-point rounding", async () => {
  documents.set(registryPath, JSON.stringify(fixture.registry).replace('"key_generation":1', '"key_generation":18446744073709551615'));
  assert.equal((await getPaymentList(owner)).length, 4);
  for (const generation of ["18446744073709551616", "1.0", "1e0", "-1"]) {
    documents.set(registryPath, JSON.stringify(fixture.registry).replace('"key_generation":1', `"key_generation":${generation}`));
    await assert.rejects(getPaymentList(owner), expectCode("INVALID_DATA"));
  }
});

test("rejects invalid UTF-8 without replacement decoding", async () => {
  documents.set(registryPath, new Uint8Array([0xff]));
  await assert.rejects(getPaymentList(owner), expectCode("INVALID_DATA"));
});

test("rejects empty or oversized registries", async () => {
  documents.set(registryPath, "");
  await assert.rejects(getPaymentList(owner), expectCode("INVALID_DATA"));
  documents.set(registryPath, " ".repeat(65537));
  await assert.rejects(getPaymentList(owner), expectCode("RESOURCE_LIMIT"));
});

test("refuses arbitrary identities, Apps, nested paths and traversal before fetching", async () => {
  for (const resource of [
    `pubky://${"y".repeat(52)}/pub/paykit/v0/apps/bitkit/endpoints/btc`,
    `${base}/pub/paykit/v0/apps/other/endpoints/btc`,
    `${base}/pub/paykit/v0/apps/bitkit/endpoints/nested/btc`,
    `${base}/pub/paykit/v0/apps/bitkit/endpoints/../btc`,
    `${base}/pub/paykit/v0/apps/bitkit/endpoints/%2e%2e`,
    `${base}/pub/paykit/v0/apps/bitkit/endpoints/private`,
    `${base}/pub/paykit/v0/apps/bitkit/endpoints/...`,
    `${base}/pub/paykit/v0/apps/bitkit/endpoints/btc?x=1`,
  ]) {
    gets = [];
    listHook = async () => [resource];
    await assert.rejects(getPaymentList(owner), expectCode("INVALID_DATA"));
    assert.deepEqual(gets, [base + registryPath]);
  }
});

test("paginates complete lists using a forward cursor", async () => {
  onlyBitkit();
  for (const path of [...documents.keys()]) if (path !== registryPath) documents.delete(path);
  for (let index = 0; index < 101; index++) {
    documents.set(`/pub/paykit/v0/apps/bitkit/endpoints/endpoint-${String(index).padStart(3, "0")}`, "opaque");
  }
  assert.equal((await getPaymentList(owner)).length, 101);
  assert.equal(lists.length, 2);
  assert.ok(lists[1].cursor.endsWith("endpoint-099"));
});

test("rejects repeated or unordered listing entries", async () => {
  listHook = async (address) => [address + "z", address + "a"];
  await assert.rejects(getPaymentList(owner), expectCode("INVALID_DATA"));
  listHook = async (address) => [address + "a", address + "a"];
  await assert.rejects(getPaymentList(owner), expectCode("INVALID_DATA"));
});

test("refuses more than 256 endpoints across Apps", async () => {
  for (const path of [...documents.keys()]) if (path !== registryPath) documents.delete(path);
  for (let index = 0; index < 129; index++) {
    for (const app of ["bitkit", "savings"]) documents.set(`/pub/paykit/v0/apps/${app}/endpoints/endpoint-${String(index).padStart(3, "0")}`, "opaque");
  }
  await assert.rejects(getPaymentList(owner), expectCode("RESOURCE_LIMIT"));
});

test("stops an oversized stream without consuming its remainder", async () => {
  let canceled = false;
  let pulls = 0;
  getHook = async () => new Response(new ReadableStream({
    pull(controller) { pulls++; controller.enqueue(new Uint8Array(65537)); },
    cancel() { canceled = true; },
  }, { highWaterMark: 0 }));
  await assert.rejects(getPaymentList(owner), expectCode("RESOURCE_LIMIT"));
  assert.equal(canceled, true);
  assert.equal(pulls, 1);
});

test("bounds total endpoint payload bytes across documents", async () => {
  onlyBitkit();
  for (const path of [...documents.keys()]) if (path !== registryPath) documents.delete(path);
  for (let index = 0; index < 65; index++) {
    documents.set(`/pub/paykit/v0/apps/bitkit/endpoints/endpoint-${String(index).padStart(3, "0")}`, "x".repeat(65536));
  }
  await assert.rejects(getPaymentList(owner), expectCode("RESOURCE_LIMIT"));
});
