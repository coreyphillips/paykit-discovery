/** Stable failure categories for discovery. */
export type PaymentListErrorCode = "INVALID_PUBKY" | "INVALID_DATA" | "RESOURCE_LIMIT" | "TRANSPORT";

/** A lookup failed; an incomplete Payment List is never returned as success. */
export class PaymentListError extends Error {
  readonly name = "PaymentListError";
  constructor(readonly code: PaymentListErrorCode, message: string, options?: ErrorOptions) {
    super(message, options);
  }
}
