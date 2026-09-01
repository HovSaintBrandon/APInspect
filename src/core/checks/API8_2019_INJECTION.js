// Injection (SQLi/XSS payload fuzzing + path traversal) — combines the existing
// deterministic injection checks. Labeled against the 2019 OWASP API Security
// Top 10 (API8:2019 Injection) deliberately: the 2023 edition dropped a
// dedicated numbered Injection category, so there's no correct 2023 ID to use
// here without misrepresenting one. Testing for it is still worthwhile.
const sqliXss = require('../../checks/injection/sqliXss');
const pathTraversal = require('../../checks/injection/pathTraversal');
const { combineResults } = require('./resultCombiner');

module.exports = async (context, client, endpoint) => {
    const [sqliResult, traversalResult] = await Promise.all([
        sqliXss(context, client, endpoint),
        pathTraversal(context, client, endpoint),
    ]);
    return combineResults([sqliResult, traversalResult]);
};
