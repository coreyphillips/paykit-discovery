import { mnemonicToSeedSync, validateMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";
import { PaymentListError } from "./errors.js";

/**
 * Resolve a secret to a fresh 32-byte identity secret; the caller zeroes it.
 *
 * A mnemonic resolves the way Pubky Ring (`pubky-core-ffi`) does: the first
 * 32 bytes of its BIP39 seed, with no passphrase. Whitespace runs collapse to
 * one space and ASCII letters are lowercased first, as in the Rust crate.
 * The caller's buffer is copied, never modified.
 */
export function parseSecret(input: unknown): Uint8Array<ArrayBuffer> {
  const invalid = (): PaymentListError => new PaymentListError(
    "INVALID_SECRET",
    "Expected a BIP39 English mnemonic, a 64-character hex identity secret, or 32 secret bytes",
  );
  if (input instanceof Uint8Array) {
    if (input.byteLength !== 32) throw invalid();
    return Uint8Array.from(input);
  }
  if (typeof input !== "string") throw invalid();
  const normalized = input.split(/\p{White_Space}+/u).filter(Boolean).join(" ")
    .replace(/[A-Z]/g, (letter) => letter.toLowerCase());
  if (/^[0-9a-f]{64}$/.test(normalized)) {
    const secret = new Uint8Array(32);
    for (let index = 0; index < 32; index++) secret[index] = parseInt(normalized.slice(index * 2, index * 2 + 2), 16);
    return secret;
  }
  if (!validateMnemonic(normalized, wordlist)) throw invalid();
  const seed = mnemonicToSeedSync(normalized, "");
  try { return Uint8Array.from(seed.subarray(0, 32)); } finally { seed.fill(0); }
}
