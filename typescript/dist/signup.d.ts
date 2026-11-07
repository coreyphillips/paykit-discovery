import { PublicKey, type Pubky, type Signer } from "@synonymdev/pubky";
/**
 * Sign up the identity if, and only if, no homeserver record for it can be found.
 *
 * Signup force-publishes the homeserver record, so running it for an identity
 * that has one would point that identity away from its data. The decision comes
 * from the record, never from a failed sign-in, which does not show that no
 * account exists. An identity with a record continues to sign-in unchanged.
 */
export declare function ensureHomeserver(pubky: Pubky, signer: Signer, owner: PublicKey): Promise<void>;
