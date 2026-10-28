/** Stable failure categories for discovery. */
export type PaymentListErrorCode = "INVALID_PUBKY" | "INVALID_DATA" | "RESOURCE_LIMIT" | "TRANSPORT";
/** A lookup failed; an incomplete Payment List is never returned as success. */
export declare class PaymentListError extends Error {
    readonly code: PaymentListErrorCode;
    readonly name = "PaymentListError";
    constructor(code: PaymentListErrorCode, message: string, options?: ErrorOptions);
}
