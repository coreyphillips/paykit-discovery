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
