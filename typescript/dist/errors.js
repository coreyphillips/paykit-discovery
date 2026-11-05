/**
 * A lookup or publish failed; an incomplete Payment List is never returned as success.
 * Messages and causes never include a secret, mnemonic, or access key.
 */
export class PaymentListError extends Error {
    code;
    name = "PaymentListError";
    constructor(code, message, options) {
        super(message, options);
        this.code = code;
    }
}
//# sourceMappingURL=errors.js.map