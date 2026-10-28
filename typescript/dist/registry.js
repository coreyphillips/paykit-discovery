import { PublicKey } from "@synonymdev/pubky";
import { PaymentListError } from "./errors.js";
/** Internal protocol parser; deliberately excluded from the package exports. */
export function parseRegistry(text) {
    const invalid = () => { throw new PaymentListError("INVALID_DATA", "Invalid Paykit App Registry"); };
    let value;
    try {
        value = JSON.parse(text);
    }
    catch {
        return invalid();
    }
    const numericFields = validateJsonTokens(text, invalid);
    const object = (candidate) => {
        if (typeof candidate !== "object" || candidate === null || Array.isArray(candidate))
            invalid();
        return candidate;
    };
    const exact = (candidate, required, optional = []) => {
        if (Object.keys(candidate).some((key) => !required.includes(key) && !optional.includes(key))
            || required.some((key) => !Object.hasOwn(candidate, key)))
            invalid();
    };
    const appId = (candidate) => {
        if (typeof candidate !== "string" || !/^[a-z0-9-]{1,64}$/.test(candidate))
            invalid();
        return candidate;
    };
    const wire = object(value);
    exact(wire, ["version", "kind", "key_generation", "apps", "default_apps_by_endpoint"], ["noise_public_key", "default_app_id"]);
    if (numericFields.get("version") !== "1" || wire.kind !== "paykit.app_registry")
        invalid();
    const generation = numericFields.get("key_generation") ?? "";
    if (!/^[1-9][0-9]*$/.test(generation) || BigInt(generation) > 18446744073709551615n)
        invalid();
    if (wire.noise_public_key !== undefined && wire.noise_public_key !== null) {
        // Match Paykit Library's Pubky parser, including accepted identity aliases.
        // The Noise key is registry metadata; discovery never uses it as authority.
        if (typeof wire.noise_public_key !== "string")
            invalid();
        try {
            const key = PublicKey.from(wire.noise_public_key);
            key.free();
        }
        catch {
            invalid();
        }
    }
    const apps = new Set();
    const applications = object(wire.apps);
    if (Object.keys(applications).length > 64)
        invalid();
    for (const [id, rawApp] of Object.entries(applications)) {
        apps.add(appId(id));
        const app = object(rawApp);
        exact(app, ["display_name", "capabilities"]);
        if (typeof app.display_name !== "string" || /^\p{White_Space}*$/u.test(app.display_name)
            || new TextEncoder().encode(app.display_name).byteLength > 128
            || /[\u0000-\u001f\u007f-\u009f]/.test(app.display_name)
            || /[\uD800-\uDFFF]/u.test(app.display_name))
            invalid();
        const capabilities = object(app.capabilities);
        exact(capabilities, ["private_payments", "payment_requests", "receipts", "outgoing_payments"]);
        if (Object.values(capabilities).some((item) => typeof item !== "boolean"))
            invalid();
        if (wire.noise_public_key == null && (capabilities.private_payments || capabilities.payment_requests || capabilities.receipts))
            invalid();
    }
    const result = { apps, defaults: new Map() };
    const registeredApp = (candidate) => {
        const id = appId(candidate);
        if (!apps.has(id))
            invalid();
        return id;
    };
    if (wire.default_app_id != null)
        result.defaultApp = registeredApp(wire.default_app_id);
    const defaults = object(wire.default_apps_by_endpoint);
    if (Object.keys(defaults).length > 256)
        invalid();
    for (const [identifier, id] of Object.entries(defaults)) {
        if (!/^[A-Za-z0-9_.-]{1,64}$/.test(identifier) || /^\.+$/.test(identifier) || identifier === "private")
            invalid();
        result.defaults.set(identifier, registeredApp(id));
    }
    return result;
}
// JSON.parse silently accepts duplicate keys and rounds large u64 values.
// Scan already-valid JSON tokens to reject ambiguity and retain integer lexemes.
function validateJsonTokens(text, invalid) {
    const tokens = text.match(/"(?:\\.|[^"\\])*"|[{}\[\]:,]|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?|true|false|null/g) ?? [];
    const numericFields = new Map();
    let position = 0;
    function visit(depth) {
        if (depth > 64)
            invalid();
        const token = tokens[position++];
        if (token === "{") {
            const keys = new Set();
            if (tokens[position] === "}") {
                position++;
                return;
            }
            while (true) {
                const key = JSON.parse(tokens[position++]);
                if (keys.has(key))
                    invalid();
                keys.add(key);
                position++; // Colon; JSON.parse has already checked grammar.
                if (depth === 0 && (key === "version" || key === "key_generation"))
                    numericFields.set(key, tokens[position]);
                visit(depth + 1);
                if (tokens[position++] === "}")
                    return;
            }
        }
        if (token === "[") {
            if (tokens[position] === "]") {
                position++;
                return;
            }
            while (true) {
                visit(depth + 1);
                if (tokens[position++] === "]")
                    return;
            }
        }
    }
    visit(0);
    return numericFields;
}
//# sourceMappingURL=registry.js.map