const logger = require('../utils/logger');

// Helper: does this request have meaningful authentication?
function hasAuthentication(request) {
    if (!request) return false;

    const auth = request.auth;
    if (auth && auth.type && auth.type !== 'noauth') {
        return { type: auth.type, present: true };
    }

    // Look in headers (most common way in Postman collections)
    const headers = request.header || [];
    const authHeader = headers.find(h =>
        h.key?.toLowerCase() === 'authorization' ||
        h.key?.toLowerCase() === 'x-api-key' ||
        h.key?.toLowerCase() === 'api-key' ||
        h.key?.toLowerCase() === 'x-access-token'
    );

    if (authHeader) {
        return { type: 'header', key: authHeader.key, valueHint: authHeader.value };
    }

    // Sometimes in query
    const query = request.url?.query || [];
    const apiKeyQuery = query.find(q =>
        ['apikey', 'api_key', 'token', 'access_token', 'key'].includes(q.key?.toLowerCase())
    );

    if (apiKeyQuery) {
        return { type: 'query', key: apiKeyQuery.key };
    }

    return false;
}

// Helper: is this likely a sensitive operation?
const sensitiveKeywords = [
    'user', 'account', 'profile', 'password', 'email', 'admin', 'delete', 'update', 'patch',
    'change', 'reset', 'role', 'permission', 'setting', 'config', 'payment', 'order', 'invoice'
];

function isPotentiallySensitive(item) {
    const name = (item.name || '').toLowerCase();
    const req = item.request || {};
    const urlPath = (req.url?.path || []).join('/').toLowerCase();

    return sensitiveKeywords.some(kw => name.includes(kw) || urlPath.includes(kw));
}

// Main logic
const analyze = (collectionData) => {
    logger.title('Running Static Analysis on Postman Collection...');

    // We'll collect findings here
    const findings = {
        missingAuth: [],
        weakAuth: [],
        apiKeyInQuery: [],
        noAuthorizationHeaderCommon: [],
    };

    let totalRequests = 0;

    // Recursive walker
    const analyzeItem = (item) => {
        if (item.item) {
            // folder
            item.item.forEach(analyzeItem);
            return;
        }

        if (!item.request) return;
        totalRequests++;

        const req = item.request;
        const method = (req.method || 'GET').toUpperCase();
        const name = item.name || 'unnamed';
        const pathStr = Array.isArray(req.url?.path) ? req.url.path.join('/') : (req.url || '');

        const authInfo = hasAuthentication(req);

        // 1. Missing / weak authentication on potentially sensitive endpoints
        if (isPotentiallySensitive(item) && !authInfo) {
            findings.missingAuth.push({
                name,
                method,
                path: pathStr,
                issue: 'No authentication detected on sensitive-looking endpoint'
            });
        }

        // 2. API keys visible in query string (very bad practice)
        if (authInfo?.type === 'query') {
            findings.apiKeyInQuery.push({
                name,
                method,
                path: pathStr,
                key: authInfo.key,
                issue: 'API key/token sent via query string → logged, cached, shared'
            });
        }

        // 3. Authorization header missing on most endpoints (heuristic)
        if (method !== 'OPTIONS' && !authInfo) {
            findings.noAuthorizationHeaderCommon.push({
                name,
                method,
                path: pathStr
            });
        }

        // 4. Very weak / suspicious patterns
        // hardcoded token visible (not using variable {{...}})
        if (authInfo?.valueHint && !authInfo.valueHint.includes('{{')) {
            if (authInfo.valueHint.length > 6) {
                findings.weakAuth.push({
                    name,
                    method,
                    path: pathStr,
                    issue: 'Hardcoded credential detected in collection',
                    valueSnippet: authInfo.valueHint.substring(0, 5) + '...'
                });
            }
        }
    };

    const items = collectionData.item || collectionData;
    if (Array.isArray(items)) {
        items.forEach(analyzeItem);
    } else if (items) {
        analyzeItem(items);
    }

    // Report Results
    let issuesFound = 0;

    if (findings.missingAuth.length > 0) {
        logger.warn(`⚠️  Potentially unprotected sensitive endpoints (${findings.missingAuth.length}):`);
        findings.missingAuth.forEach(f => logger.info(`  • ${f.method} ${f.path} → ${f.name}`));
        issuesFound += findings.missingAuth.length;
    }

    if (findings.apiKeyInQuery.length > 0) {
        logger.error(`❌ API keys/tokens sent via query string (${findings.apiKeyInQuery.length}):`);
        findings.apiKeyInQuery.forEach(f => logger.info(`  • ${f.method} ${f.path} (${f.key})`));
        issuesFound += findings.apiKeyInQuery.length;
    }

    if (findings.weakAuth.length > 0) {
        logger.error(`❌ Hardcoded secrets found (${findings.weakAuth.length}):`);
        findings.weakAuth.forEach(f => logger.info(`  • ${f.method} ${f.path} → ${f.issue}`));
        issuesFound += findings.weakAuth.length;
    }

    // Summary
    if (issuesFound === 0) {
        logger.success(`Static analysis complete. No obvious issues found across ${totalRequests} requests.`);
    } else {
        logger.title(`Static Analysis Complete. Found ${issuesFound} potential issues.`);
    }

    return findings;
};

module.exports = { analyze };
