class Context {
    constructor(config) {
        this.baseUrl = config.base_url;
        this.auth = config.auth || null;
        this.endpoints = config.endpoints || [];
        this.environment = config.environment || 'production';
        this.headers = config.headers || {};

        // Derived state
        this.results = [];

        // Evidence store: populated by newmanRunner before AI checks run.
        // Keyed as "METHOD /path" (e.g. "GET /api/users").
        // Initialized here so it exists before runAudit is called.
        this.evidenceStore = new Map();

        // Variable store for dynamic resolution (e.g., {{booking_id}} -> "123")
        this.store = {};
    }

    /**
     * Retrieve captured request/response evidence for an endpoint.
     * @param {object} endpoint - { path, methods }
     * @returns {object|undefined} Evidence object or undefined if not captured.
     */
    getEvidenceFor(endpoint) {
        const method = (endpoint.methods && endpoint.methods[0]) || 'GET';
        const key = `${method.toUpperCase()} ${endpoint.path}`;
        return this.evidenceStore.get(key);
    }

    getAuthHeaders() {
        if (!this.auth) return {};

        if (this.auth.type === 'bearer') {
            return { 'Authorization': `Bearer ${this.auth.token}` };
        }

        if (this.auth.type === 'basic') {
            const token = Buffer.from(`${this.auth.username}:${this.auth.password}`).toString('base64');
            return { 'Authorization': `Basic ${token}` };
        }

        if (this.auth.type === 'header') {
            return { [this.auth.key]: this.auth.value };
        }

        return {};
    }

    addResult(result) {
        this.results.push(result);
    }

    getResults() {
        return this.results;
    }

    setVariable(key, value) {
        this.store[key] = value;
    }

    getVariable(key) {
        return this.store[key];
    }

    resolveString(input) {
        if (!input || typeof input !== 'string') return input;
        return input.replace(/\{\{([^}]+)\}\}/g, (match, varName) => {
            const value = this.store[varName];
            if (value === undefined) {
                // If the variable isn't in our store, return the original {{match}}
                return match; 
            }
            return value;
        });
    }
}

module.exports = Context;
