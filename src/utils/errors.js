class InfrastructureError extends Error {
    constructor(message) {
        super(message);
        this.name = 'InfrastructureError';
    }
}

module.exports = { InfrastructureError };
