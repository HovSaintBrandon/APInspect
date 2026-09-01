class InfrastructureError extends Error {
    // `status` is the upstream HTTP status code that caused this, when known
    // (e.g. OpenRouter's 401/402/403) — lets callers like engine.js branch on
    // "is this billing/auth exhaustion" without regex-parsing the message.
    constructor(message, { status } = {}) {
        super(message);
        this.name = 'InfrastructureError';
        this.status = status ?? null;
    }
}

module.exports = { InfrastructureError };
