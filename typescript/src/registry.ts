import { PublicKey } from "@synonymdev/pubky";
import { compare, MAX_APPS } from "./endpoints.js";
import { PaymentListError } from "./errors.js";

interface AppCapabilities {
  private_payments: boolean;
  payment_requests: boolean;
  receipts: boolean;
  outgoing_payments: boolean;
}
interface AppRecord { display_name: string; capabilities: AppCapabilities }

export interface Registry {
  apps: Set<string>;
  defaultApp?: string;
  defaults: Map<string, string>;
  /** Exact u64 lexeme, so writes never round through a float. */
  keyGeneration: string;
  /** Noise public key normalized to z-base-32, as Paykit Library writes it. */
  noiseKey: string | null;
  records: Map<string, AppRecord>;
}

/** Internal protocol parser; deliberately excluded from the package exports. */
export function parseRegistry(text: string): Registry {
  const invalid = (): never => { throw new PaymentListError("INVALID_DATA", "Invalid Paykit App Registry"); };
  let value: unknown;
  try { value = JSON.parse(text); } catch { return invalid(); }
  const numericFields = validateJsonTokens(text, invalid);
  const object = (candidate: unknown): Record<string, unknown> => {
    if (typeof candidate !== "object" || candidate === null || Array.isArray(candidate)) invalid();
    return candidate as Record<string, unknown>;
  };
  const exact = (candidate: Record<string, unknown>, required: string[], optional: string[] = []): void => {
    if (Object.keys(candidate).some((key) => !required.includes(key) && !optional.includes(key))
        || required.some((key) => !Object.hasOwn(candidate, key))) invalid();
  };
  const appId = (candidate: unknown): string => {
    if (typeof candidate !== "string" || !/^[a-z0-9-]{1,64}$/.test(candidate)) invalid();
    return candidate as string;
  };
  const wire = object(value);
  exact(wire, ["version", "kind", "key_generation", "apps", "default_apps_by_endpoint"], ["noise_public_key", "default_app_id"]);
  if (numericFields.get("version") !== "1" || wire.kind !== "paykit.app_registry") invalid();
  const generation = numericFields.get("key_generation") ?? "";
  if (!/^[1-9][0-9]*$/.test(generation) || BigInt(generation) > 18446744073709551615n) invalid();
  let noiseKey: string | null = null;
  if (wire.noise_public_key !== undefined && wire.noise_public_key !== null) {
    // Accept exactly the forms Paykit Library accepts; see parseNoisePublicKey.
    // The Noise key is registry metadata; discovery never uses it as authority.
    if (typeof wire.noise_public_key !== "string") invalid();
    noiseKey = parseNoisePublicKey(wire.noise_public_key as string) ?? invalid();
  }
  const apps = new Set<string>();
  const records = new Map<string, AppRecord>();
  const applications = object(wire.apps);
  if (Object.keys(applications).length > MAX_APPS) invalid();
  for (const [id, rawApp] of Object.entries(applications)) {
    apps.add(appId(id));
    const app = object(rawApp);
    exact(app, ["display_name", "capabilities"]);
    if (typeof app.display_name !== "string" || /^\p{White_Space}*$/u.test(app.display_name)
        || new TextEncoder().encode(app.display_name).byteLength > 128
        || /[\u0000-\u001f\u007f-\u009f]/.test(app.display_name)
        || /[\uD800-\uDFFF]/u.test(app.display_name)) invalid();
    const capabilities = object(app.capabilities);
    exact(capabilities, ["private_payments", "payment_requests", "receipts", "outgoing_payments"]);
    if (Object.values(capabilities).some((item) => typeof item !== "boolean")) invalid();
    if (wire.noise_public_key == null && (capabilities.private_payments || capabilities.payment_requests || capabilities.receipts)) invalid();
    records.set(id, {
      display_name: app.display_name as string,
      capabilities: {
        private_payments: capabilities.private_payments as boolean,
        payment_requests: capabilities.payment_requests as boolean,
        receipts: capabilities.receipts as boolean,
        outgoing_payments: capabilities.outgoing_payments as boolean,
      },
    });
  }
  const result: Registry = { apps, defaults: new Map(), keyGeneration: generation, noiseKey, records };
  const registeredApp = (candidate: unknown): string => {
    const id = appId(candidate);
    if (!apps.has(id)) invalid();
    return id;
  };
  if (wire.default_app_id != null) result.defaultApp = registeredApp(wire.default_app_id);
  const defaults = object(wire.default_apps_by_endpoint);
  if (Object.keys(defaults).length > 256) invalid();
  for (const [identifier, id] of Object.entries(defaults)) {
    if (!/^[A-Za-z0-9_.-]{1,64}$/.test(identifier) || /^\.+$/.test(identifier) || identifier === "private") invalid();
    result.defaults.set(identifier, registeredApp(id));
  }
  return result;
}

const Z32_ALPHABET = "ybndrfg8ejkmcpqxot1uwisza345h769";
const utf8 = new TextEncoder();

function after(text: string, separator: string): string {
  const index = text.indexOf(separator);
  return index === -1 ? text : text.slice(index + separator.length);
}

function before(text: string, separator: string): string {
  const index = text.indexOf(separator);
  return index === -1 ? text : text.slice(0, index);
}

/**
 * Parse a registry Noise public key exactly as Paykit Library does.
 *
 * paykit-lib reads `noise_public_key` with `PublicKey::try_from_z32`, which is
 * pkarr 8's `PublicKey::from_str`. While the text is longer than 52 bytes, it
 * drops, in order: a scheme, `//`, user info, a port, a path, a query, a
 * fragment, and leading DNS labels. The rest must be 52 z-base-32 characters;
 * the last character's 4 unused bits are ignored, and the 32 bytes must be a
 * valid Ed25519 point. The JS SDK's `PublicKey.from` accepts different aliases,
 * so this ports the Rust rules instead. `fixtures/discovery.json` pins them.
 *
 * Returns the canonical z-base-32 key, which is what Paykit Library writes back,
 * or `undefined` when Paykit Library would reject the registry.
 */
export function parseNoisePublicKey(value: string): string | undefined {
  const steps: ((text: string) => string)[] = [
    (text) => after(text, ":"),
    (text) => (text.startsWith("//") ? text.slice(2) : text),
    (text) => after(text, "@"),
    (text) => before(text, ":"),
    (text) => before(text, "/"),
    (text) => before(text, "?"),
    (text) => before(text, "#"),
    (text) => {
      const trimmed = text.endsWith(".") ? text.replace(/^\.+|\.+$/g, "") : text;
      return trimmed.slice(trimmed.lastIndexOf(".") + 1);
    },
  ];
  let text = value;
  for (const step of steps) {
    if (utf8.encode(text).byteLength <= 52) break;
    text = step(text);
  }
  if (!/^[ybndrfg8ejkmcpqxot1uwisza345h769]{52}$/.test(text)) return undefined;

  const bytes = new Uint8Array(32);
  let buffer = 0;
  let bits = 0;
  let length = 0;
  for (const character of text) {
    buffer = (buffer << 5) | Z32_ALPHABET.indexOf(character);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      if (length < 32) bytes[length++] = (buffer >> bits) & 0xff;
    }
    buffer &= (1 << bits) - 1;
  }
  let canonical = "";
  buffer = 0;
  bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      canonical += Z32_ALPHABET[(buffer >> bits) & 31];
    }
    buffer &= (1 << bits) - 1;
  }
  canonical += Z32_ALPHABET[(buffer << (5 - bits)) & 31];

  // The SDK checks that the bytes are a valid Ed25519 point.
  try {
    const key = PublicKey.from(canonical);
    try { return key.z32() === canonical ? canonical : undefined; } finally { key.free(); }
  } catch {
    return undefined;
  }
}

/** A registry for an identity that has none yet. */
export function emptyRegistry(): Registry {
  return { apps: new Set(), defaults: new Map(), keyGeneration: "1", noiseKey: null, records: new Map() };
}

/**
 * Register each missing App with its ID as display name and no capabilities.
 * Existing Apps, the Noise key, and every default are kept. Returns whether
 * the registry changed.
 */
export function registerMissingApps(registry: Registry, appIds: string[]): boolean {
  const missing = appIds.filter((id) => !registry.records.has(id));
  if (registry.records.size + missing.length > MAX_APPS) {
    throw new PaymentListError("RESOURCE_LIMIT", "The Paykit App Registry would exceed 64 Apps");
  }
  for (const id of missing) {
    registry.apps.add(id);
    registry.records.set(id, {
      display_name: id,
      capabilities: { private_payments: false, payment_requests: false, receipts: false, outgoing_payments: false },
    });
  }
  return missing.length > 0;
}

/** Serialize exactly as Paykit Library's `serialize_paykit_app_registry` does. */
export function serializeRegistry(registry: Registry): string {
  const string = (value: string): string => JSON.stringify(value);
  const apps = [...registry.records.keys()].sort(compare).map((id) => {
    const { display_name, capabilities: c } = registry.records.get(id)!;
    return `${string(id)}:{"display_name":${string(display_name)},"capabilities":{"private_payments":${c.private_payments},`
      + `"payment_requests":${c.payment_requests},"receipts":${c.receipts},"outgoing_payments":${c.outgoing_payments}}}`;
  });
  const defaults = [...registry.defaults.keys()].sort(compare)
    .map((identifier) => `${string(identifier)}:${string(registry.defaults.get(identifier)!)}`);
  return `{"version":1,"kind":"paykit.app_registry","key_generation":${registry.keyGeneration},`
    + `"noise_public_key":${registry.noiseKey === null ? "null" : string(registry.noiseKey)},`
    + `"apps":{${apps.join(",")}},`
    + `"default_app_id":${registry.defaultApp === undefined ? "null" : string(registry.defaultApp)},`
    + `"default_apps_by_endpoint":{${defaults.join(",")}}}`;
}

// JSON.parse silently accepts duplicate keys and rounds large u64 values.
// Scan already-valid JSON tokens to reject ambiguity and retain the raw lexeme
// of each top-level value that is a single token (numbers, strings, literals).
export function validateJsonTokens(text: string, invalid: () => never): Map<string, string> {
  const tokens = text.match(/"(?:\\.|[^"\\])*"|[{}\[\]:,]|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null/g) ?? [];
  const numericFields = new Map<string, string>();
  let position = 0;
  function visit(depth: number): void {
    if (depth > 64) invalid();
    const token = tokens[position++];
    if (token === "{") {
      const keys = new Set<string>();
      if (tokens[position] === "}") { position++; return; }
      while (true) {
        const key = JSON.parse(tokens[position++]!) as string;
        if (keys.has(key)) invalid();
        keys.add(key);
        position++; // Colon; JSON.parse has already checked grammar.
        if (depth === 0) numericFields.set(key, tokens[position]!);
        visit(depth + 1);
        if (tokens[position++] === "}") return;
      }
    }
    if (token === "[") {
      if (tokens[position] === "]") { position++; return; }
      while (true) { visit(depth + 1); if (tokens[position++] === "]") return; }
    }
  }
  visit(0);
  return numericFields;
}
