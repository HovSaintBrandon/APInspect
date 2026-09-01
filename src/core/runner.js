/**
 * src/core/runner.js
 *
 * Executes an explicit list of check IDs against one endpoint. Does not choose
 * checks, does not call an LLM, does not decide applicability — every decision
 * about what runs came from apinspect.config.yaml before this module was ever
 * invoked. This is what makes the declarative CLI path reproducible: same
 * config, same target, same findings, every time.
 */
const CHECKS = require('./checks');
const { getCheckMeta } = require('./checks/cvss');

const VALID_CHECK_IDS = new Set(Object.keys(CHECKS));

function isKnownCheck(checkId) {
    return VALID_CHECK_IDS.has(checkId);
}

/**
 * @param {string} checkId
 * @param {{path: string, methods: string[], body?: object}} endpoint
 * @param {import('./context')} context - shared Context instance
 * @param {object} client - axios instance from src/utils/httpClient.js
 * @returns {Promise<object>} normalized finding: { check_id, endpoint, method,
 *   status, message, details, cvss_vector, severity, evidence }
 */
async function runCheck(checkId, endpoint, context, client) {
    const checkFn = CHECKS[checkId];
    if (!checkFn) {
        throw new Error(`Unknown check ID: "${checkId}". Known checks: ${[...VALID_CHECK_IDS].join(', ')}`);
    }

    const method = (endpoint.methods && endpoint.methods[0]) || 'GET';
    const meta = getCheckMeta(checkId);

    // Bracket the exchange log so evidence captures every request THIS check
    // made (some, like rate-limiting/injection checks, fire several), not just
    // the last one logged process-wide.
    const exchangeLogStart = context._exchangeLog ? context._exchangeLog.length : 0;

    let result;
    try {
        result = await checkFn(context, client, endpoint);
    } catch (err) {
        result = { status: 'MANUAL', message: `Check threw an unexpected error: ${err.message}` };
    }

    const evidence = context._exchangeLog ? context._exchangeLog.slice(exchangeLogStart) : [];

    return {
        check_id: checkId,
        endpoint: endpoint.path,
        method,
        status: result.status,
        message: result.message,
        details: result.details || null,
        cvss_vector: meta.cvss_vector,
        severity: meta.severity,
        evidence,
    };
}

module.exports = { runCheck, isKnownCheck, VALID_CHECK_IDS };
