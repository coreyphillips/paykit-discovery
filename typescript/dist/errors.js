/** A lookup failed; an incomplete Payment List is never returned as success. */
export class PaymentListError extends Error {
    code;
    name = "PaymentListError";
    constructor(code, message, options) {
        super(message, options);
        this.code = code;
    }
}
//# sourceMappingURL=errors.js.map