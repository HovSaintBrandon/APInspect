const { decode } = require('./jwt/jwtCodec');
const { refreshAccessToken, REFRESH_SKEW_SECONDS } = require('./jwt/tokenRefresher');
const logger = require('../utils/logger');

class Context {
    // Bounds how many harvested sample records (see addSampleRecord) a single run
    // accumulates — plenty to give the probe synthesizer multiple distinct entities
    // to draw a cross-object pair from, without the prompt payload growing with
    // collection size.
    static MAX_SAMPLE_RECORDS = 30;

    constructor(config) {
        this.baseUrl = config.base_url;
        this.auth = config.auth || null;
        this.endpoints = config.endpoints || [];
        this.environment = config.environment || 'production';
        this.headers = config.headers || {};

        // Derived state
        this.results = [];

        // Run-level degradation notices (e.g. "AI probe synthesis unavailable: ...")
        // — surfaced in the console summary and the JSON report, distinct from
        // per-check results because they describe the run itself, not one endpoint.
        this.warnings = [];

        // Evidence store: populated by newmanRunner before AI checks run.
        // Keyed as "METHOD /path" (e.g. "GET /api/users").
        // Initialized here so it exists before runAudit is called.
        this.evidenceStore = new Map();

        // Variable store for dynamic resolution (e.g., {{booking_id}} -> "123")
        this.store = {};

        // In-flight token refresh (see ensureFreshToken) — deduped across concurrent requests.
        this._refreshPromise = null;

        // Sample records harvested during discovery (see discovery.js) — real,
        // distinct entities pulled from list-endpoint responses, each reduced to
        // just its identifier-shaped fields. Exists so the AI probe layer can test
        // cross-object identifier confusion (BOLA-01) with genuine foreign IDs
        // instead of inventing values that wouldn't actually resolve to anything.
        this.sampleRecords = [];
        // Dedupes addSampleRecord — discovery re-pings already-resolved list
        // endpoints on every pass (see discovery.js), which would otherwise queue
        // the same one or two records repeatedly instead of leaving room for
        // genuinely different entities from other endpoints.
        this._seenSampleRecordKeys = new Set();
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

    /**
     * If the current bearer token is a JWT that's expired (or about to expire)
     * and a refresh token was supplied, exchange it for a new access token and
     * swap it into this.auth in place — so a long scan's later requests pick up
     * a live token via getAuthHeaders() instead of failing auth partway through.
     * No-op for non-bearer auth, a non-JWT token, or one still comfortably valid.
     * Concurrent callers (e.g. the rate-limit check's parallel requests) share a
     * single in-flight refresh instead of each spending the (often single-use)
     * refresh token.
     */
    async ensureFreshToken() {
        if (this.auth?.type !== 'bearer' || !this.auth.refreshToken) return;

        let exp;
        try {
            exp = decode(this.auth.token).payload.exp;
        } catch (e) {
            return; // not a JWT (or malformed) — nothing we can introspect, leave it alone
        }
        if (!exp || exp - Date.now() / 1000 > REFRESH_SKEW_SECONDS) return;

        if (!this._refreshPromise) {
            this._refreshPromise = refreshAccessToken({
                currentToken: this.auth.token,
                refreshToken: this.auth.refreshToken,
                tokenUrl: this.auth.tokenUrl,
                clientId: this.auth.clientId,
                clientSecret: this.auth.clientSecret,
            }).then((result) => {
                this.auth.token = result.accessToken;
                this.auth.refreshToken = result.refreshToken;
                logger.info('🔄 Bearer token expired mid-scan — refreshed via refresh token.');
                logger.info(`   New access token: ${result.accessToken}`);
            }).finally(() => {
                this._refreshPromise = null;
            });
        }
        return this._refreshPromise;
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

    addWarning(warning) {
        this.warnings.push(warning);
    }

    getWarnings() {
        return this.warnings;
    }

    setVariable(key, value) {
        this.store[key] = value;
    }

    getVariable(key) {
        return this.store[key];
    }

    /**
     * Record one harvested sample entity (see discovery.js) — its identifier-shaped
     * fields only, e.g. { health_id: "...", contact_id: "..." }. Capped so a very
     * large or very chatty collection can't grow this unbounded across a long scan;
     * once full, later records are dropped rather than displacing earlier ones, so
     * results stay stable across a run instead of depending on discovery order.
     */
    addSampleRecord(source, record) {
        if (this.sampleRecords.length >= Context.MAX_SAMPLE_RECORDS) return;
        if (!record || typeof record !== 'object' || Object.keys(record).length === 0) return;

        const key = `${source}::${JSON.stringify(record)}`;
        if (this._seenSampleRecordKeys.has(key)) return;
        this._seenSampleRecordKeys.add(key);

        this.sampleRecords.push({ source, record });
    }

    /** Harvested sample records — see addSampleRecord. */
    getSampleRecords() {
        return this.sampleRecords;
    }

    resolveString(input) {
        if (!input || typeof input !== 'string') return input;
        return input.replace(/\{\{([^}]+)\}\}/g, (match, varName) => {
            // {{base_url}} / {{baseUrl}} are not harvested variables — they're the
            // spec's own way of spelling "the host, which axios's baseURL already
            // supplies separately." Resolving them to the actual base URL string
            // would double it up inside a path (baseURL + "/https://host/api/...");
            // the correct resolution is to drop them, same as the Postman-specific
            // {{baseUrl}} stripping this generalizes.
            if (varName === 'base_url' || varName === 'baseUrl') {
                return '';
            }
            const value = this.store[varName];
            if (value === undefined) {
                // If the variable isn't in our store, return the original {{match}}
                return match;
            }
            return value;
        });
    }

    /**
     * The one shared routine for turning a spec's raw endpoint path into
     * something safe to request — every check (hardcoded or AI-probe) and the
     * discovery/harvesting phase must go through this, not resolveString directly,
     * so they can never disagree about what a given endpoint's real URL is.
     * Also collapses accidental "//" left behind by stripping {{base_url}} out of
     * a path that already had its own leading slash (e.g. "/{{base_url}}/api/x").
     */
    resolvePath(rawPath) {
        const resolved = this.resolveString(rawPath);
        if (typeof resolved !== 'string') return resolved;
        return resolved.replace(/\/{2,}/g, '/');
    }

    /** True if the path still has an unresolved {{var}} after resolvePath(). */
    hasUnresolvedVariables(rawPath) {
        const resolved = this.resolvePath(rawPath);
        return typeof resolved === 'string' && /\{\{[^}]+\}\}/.test(resolved);
    }
}

module.exports = Context;
