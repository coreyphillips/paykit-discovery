interface Registry {
    apps: Set<string>;
    defaultApp?: string;
    defaults: Map<string, string>;
}
/** Internal protocol parser; deliberately excluded from the package exports. */
export declare function parseRegistry(text: string): Registry;
export {};
