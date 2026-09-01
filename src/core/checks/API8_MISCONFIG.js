// API8:2023 Security Misconfiguration — combines the existing deterministic
// CORS and security-header checks into one OWASP-labeled result for the
// declarative path (runner.js expects exactly one result per check ID).
const cors = require('../../checks/misconfigurations/cors');
const securityHeaders = require('../../checks/misconfigurations/securityHeaders');
const { combineResults } = require('./resultCombiner');

module.exports = async (context, client, endpoint) => {
    const [corsResult, headersResult] = await Promise.all([
        cors(context, client, endpoint),
        securityHeaders(context, client, endpoint),
    ]);
    return combineResults([corsResult, headersResult]);
};
