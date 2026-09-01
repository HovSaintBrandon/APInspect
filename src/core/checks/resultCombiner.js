/**
 * src/core/checks/resultCombiner.js
 *
 * A few OWASP API Top 10 categories map onto more than one existing hardcoded
 * check module (e.g. API7_MISCONFIG covers both CORS and security headers).
 * runner.js expects exactly one result per check ID, so those wrappers run
 * every sub-check and combine here — worst status wins, every sub-check's
 * message and details survive in the combined result rather than being
 * dropped, so the evidence trail stays complete.
 */
const STATUS_PRIORITY = ['FAIL', 'FAILED', 'WARN', 'MANUAL', 'TO BE CONFIRMED', 'ROUTE_NOT_FOUND', 'AUTH_BLOCKED', 'N/A', 'PASS'];

const rankOf = (status) => {
    const rank = STATUS_PRIORITY.indexOf(status);
    return rank === -1 ? STATUS_PRIORITY.length : rank;
};

const combineResults = (results) => {
    const valid = results.filter(Boolean);
    if (valid.length === 0) return { status: 'MANUAL', message: 'No sub-check results to combine.' };
    if (valid.length === 1) return valid[0];

    const worst = valid.reduce((worstSoFar, r) => (rankOf(r.status) < rankOf(worstSoFar.status) ? r : worstSoFar));

    return {
        status: worst.status,
        message: valid.map(r => r.message).filter(Boolean).join(' | '),
        details: { combined: valid.map(r => ({ status: r.status, message: r.message, details: r.details })) },
    };
};

module.exports = { combineResults, STATUS_PRIORITY };
