const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const logger = require('../../utils/logger');
const packageJson = require('../../../package.json');
const aiConfig = require('../../config/aiConfig');

class AICache {
    constructor(cacheFilePath) {
        this.cacheFilePath = cacheFilePath ? path.resolve(cacheFilePath) : null;
        this.isActive = !!this.cacheFilePath;
        this.cache = {
            metadata: {
                model: aiConfig.AI_MODEL,
                checklist_version: "1.0", // Hardcoded for now, could load from checklist.json
                apinspect_version: packageJson.version
            },
            endpoints: {}
        };
        this.isDirty = false;
        
        if (this.isActive) {
            this._loadCache();
        }
    }

    _loadCache() {
        if (!fs.existsSync(this.cacheFilePath)) {
            logger.info(`Cache file not found at ${this.cacheFilePath}, a new one will be created.`);
            return;
        }

        try {
            const raw = JSON.parse(fs.readFileSync(this.cacheFilePath, 'utf-8'));
            
            // Validate metadata
            if (!raw.metadata || 
                raw.metadata.model !== this.cache.metadata.model ||
                raw.metadata.checklist_version !== this.cache.metadata.checklist_version ||
                raw.metadata.apinspect_version !== this.cache.metadata.apinspect_version) {
                logger.warn('Cache metadata mismatch (version/model changed). Invalidating entire cache.');
                return; // Leave memory cache empty so it overwrites
            }

            this.cache = raw;
            logger.info(`Loaded AI cache from ${this.cacheFilePath} (${Object.keys(this.cache.endpoints).length} endpoints)`);
        } catch (err) {
            logger.error(`Failed to parse cache file: ${err.message}. Starting fresh.`);
        }
    }

    save() {
        if (!this.isActive || !this.isDirty) return;
        try {
            fs.writeFileSync(this.cacheFilePath, JSON.stringify(this.cache, null, 2), 'utf-8');
            logger.info(`Saved AI cache to ${this.cacheFilePath}`);
            this.isDirty = false;
        } catch (err) {
            logger.error(`Failed to save AI cache: ${err.message}`);
        }
    }

    _generateEndpointHash(endpoint) {
        // Create a deterministic representation of the endpoint's structure
        // This ensures if the path, method, or parameters change, the hash changes.
        const hashable = {
            path: endpoint.path,
            methods: endpoint.methods ? endpoint.methods.slice().sort() : []
        };
        
        const str = JSON.stringify(hashable);
        return crypto.createHash('sha256').update(str).digest('hex').substring(0, 16);
    }

    _getEndpointKey(endpoint) {
        const hash = this._generateEndpointHash(endpoint);
        const method = (endpoint.methods && endpoint.methods.length > 0) ? endpoint.methods[0] : 'GET';
        return `${method} ${endpoint.path}:${hash}`;
    }

    getApplicability(endpoint) {
        if (!this.isActive) return null;
        const key = this._getEndpointKey(endpoint);
        const entry = this.cache.endpoints[key];
        return entry ? entry.applicability : null; // returns array of ids or null
    }

    setApplicability(endpoint, applicableCheckIds) {
        if (!this.isActive) return;
        const key = this._getEndpointKey(endpoint);
        if (!this.cache.endpoints[key]) this.cache.endpoints[key] = { probes: {} };
        this.cache.endpoints[key].applicability = applicableCheckIds;
        this.isDirty = true;
    }

    getProbe(endpoint, checklistId) {
        if (!this.isActive) return null;
        const key = this._getEndpointKey(endpoint);
        const entry = this.cache.endpoints[key];
        return (entry && entry.probes) ? entry.probes[checklistId] : null;
    }

    setProbe(endpoint, checklistId, probeSpec) {
        if (!this.isActive) return;
        const key = this._getEndpointKey(endpoint);
        if (!this.cache.endpoints[key]) this.cache.endpoints[key] = { probes: {} };
        this.cache.endpoints[key].probes[checklistId] = probeSpec;
        this.isDirty = true;
    }
}

module.exports = AICache;
