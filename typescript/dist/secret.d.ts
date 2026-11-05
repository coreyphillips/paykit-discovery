/**
 * Resolve a secret to a fresh 32-byte identity secret; the caller zeroes it.
 *
 * A mnemonic resolves the way Pubky Ring (`pubky-core-ffi`) does: the first
 * 32 bytes of its BIP39 seed, with no passphrase. Whitespace runs collapse to
 * one space and ASCII letters are lowercased first, as in the Rust crate.
 * The caller's buffer is copied, never modified.
 */
export declare function parseSecret(input: unknown): Uint8Array<ArrayBuffer>;
