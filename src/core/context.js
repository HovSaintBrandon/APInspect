class Context {
    constructor(config) {
        this.baseUrl = config.base_url;
        this.auth = config.auth || null;
        this.endpoints = config.endpoints || [];
        this.environment = config.environment || 'production';
        this.headers = config.headers || {};

        // Derived state
        this.results = [];
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
}

module.exports = Context;
