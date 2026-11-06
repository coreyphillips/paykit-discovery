/**
 * Stable failure categories.
 *
 * `INVALID_SECRET`, `INVALID_INPUT`, and `AUTH` were added with `setPaymentList`,
 * and `NOT_FOUND` with encrypted lists. Exhaustive `switch` statements over this
 * union need cases for them.
 */
export type PaymentListErrorCode =
  | "INVALID_PUBKY"
  | "INVALID_SECRET"
  | "INVALID_INPUT"
  | "INVALID_DATA"
  | "NOT_FOUND"
  | "RESOURCE_LIMIT"
  | "AUTH"
  | "TRANSPORT";

/**
 * A lookup or publish failed; an incomplete Payment List is never returned as success.
 * Messages and causes never include a secret, mnemonic, or access key.
 */
export class PaymentListError extends Error {
  readonly name = "PaymentListError";
  constructor(readonly code: PaymentListErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
  }
}
