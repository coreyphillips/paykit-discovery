interface AppCapabilities {
    private_payments: boolean;
    payment_requests: boolean;
    receipts: boolean;
    outgoing_payments: boolean;
}
interface AppRecord {
    display_name: string;
    capabilities: AppCapabilities;
}
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
export declare function parseRegistry(text: string): Registry;
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
export declare function parseNoisePublicKey(value: string): string | undefined;
/** A registry for an identity that has none yet. */
export declare function emptyRegistry(): Registry;
/**
 * Register each missing App with its ID as display name and no capabilities.
 * Existing Apps, the Noise key, and every default are kept. Returns whether
 * the registry changed.
 */
export declare function registerMissingApps(registry: Registry, appIds: string[]): boolean;
/** Serialize exactly as Paykit Library's `serialize_paykit_app_registry` does. */
export declare function serializeRegistry(registry: Registry): string;
export declare function validateJsonTokens(text: string, invalid: () => never): Map<string, string>;
export {};
