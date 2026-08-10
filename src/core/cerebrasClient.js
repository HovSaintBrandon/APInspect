const axios = require('axios');
const logger = require('../utils/logger');
const { AI_MODEL } = require('../config/aiConfig');
const { InfrastructureError } = require('../utils/errors');

const CEREBRAS_URL = 'https://api.cerebras.ai/v1/chat/completions';

// Errors that are transient — worth retrying
const RETRYABLE_STATUS_CODES = new Set([429, 503, 502, 504]);
const RETRYABLE_CODES = new Set(['ETIMEDOUT', 'ECONNRESET', 'ECONNREFUSED', 'ENOTFOUND']);

// Errors that will never fix themselves — fail immediately
const FATAL_STATUS_CODES = new Set([400, 401, 403]);

const MAX_RETRIES = 3;
const BASE_DELAY_MS = 1000;

// A server-provided Retry-After can be huge (a daily/hourly quota reset can be
// thousands of seconds out) — sleeping for the full duration would hang a CI job
// for up to an hour instead of failing the step. Cap what we'll actually wait for;
// anything longer is treated as quota exhaustion and fails fast instead.
const MAX_BACKOFF_MS = 120_000; // 2 minutes

// Every actual request sent to Cerebras, including retries — this is the number
// that maps to real quota/billing usage, not "logical" calls. Module-level because
// callCerebras is the single choke point every AI-touched code path funnels through.
let _requestCount = 0;

function getCallCount() {
    return _requestCount;
}

function resetCallCount() {
    _requestCount = 0;
}

function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}

function isRetryable(err) {
    if (err.response) {
        if (FATAL_STATUS_CODES.has(err.response.status)) return false;
        return RETRYABLE_STATUS_CODES.has(err.response.status);
    }
    // Network-level errors (no response)
    return RETRYABLE_CODES.has(err.code);
}

function getRetryDelay(err, attempt) {
    // Honour Retry-After if the server provides it
    if (err.response?.headers?.['retry-after']) {
        const retryAfter = parseInt(err.response.headers['retry-after'], 10);
        if (!isNaN(retryAfter)) return retryAfter * 1000;
    }
    // Exponential backoff with jitter: 1s, 2s, 4s + up to 500ms jitter
    return (BASE_DELAY_MS * Math.pow(2, attempt)) + Math.floor(Math.random() * 500);
}

/**
 * Make a Cerebras API call with exponential backoff for transient errors.
 * 
 * - Retryable errors (429, 503, timeouts): retry up to MAX_RETRIES times,
 *   then throw InfrastructureError.
 * - Non-retryable errors (401, 400, malformed response): throw immediately.
 *
 * @param {object} opts - { systemPrompt, userContent, temperature }
 * @returns {Promise<object>} - The parsed JSON response from the model
 * @throws {InfrastructureError} - If retries exhausted or fatal API error
 * @throws {Error} - If the model returns a malformed response
 */
async function callCerebras({ systemPrompt, userContent, temperature = 0, model = AI_MODEL }) {
    if (!process.env.CEREBRAS_API_KEY) {
        throw new InfrastructureError('CEREBRAS_API_KEY is not set in environment.');
    }

    let lastError;
    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
        try {
            _requestCount++;
            const res = await axios.post(CEREBRAS_URL, {
                model,
                messages: [
                    { role: 'system', content: systemPrompt },
                    { role: 'user', content: typeof userContent === 'string' ? userContent : JSON.stringify(userContent) },
                ],
                response_format: { type: 'json_object' },
                temperature,
            }, {
                headers: { Authorization: `Bearer ${process.env.CEREBRAS_API_KEY}` },
                timeout: 25000,
            });

            const raw = res.data.choices[0].message.content;
            return JSON.parse(raw);

        } catch (err) {
            lastError = err;
            const status = err.response?.status;

            // Non-retryable: fail immediately
            if (err.response && FATAL_STATUS_CODES.has(status)) {
                throw new InfrastructureError(
                    `Cerebras API returned ${status} (non-retryable): ` +
                    (err.response.data?.message || err.message)
                );
            }

            // JSON parse error on a 200 — malformed model output, not infrastructure
            if (!err.response && !err.code && err instanceof SyntaxError) {
                throw err;
            }

            if (attempt < MAX_RETRIES && isRetryable(err)) {
                const delay = getRetryDelay(err, attempt);

                if (delay > MAX_BACKOFF_MS) {
                    // The server is telling us to come back in minutes/hours, not
                    // seconds — that's a quota reset, not a transient blip. Waiting
                    // it out would hang the run; fail fast so the caller (engine.js)
                    // can abort or the CI job can report a clear cause instead of a
                    // multi-hour timeout.
                    throw new InfrastructureError(
                        `Cerebras API asked us to wait ${Math.round(delay / 1000)}s before retrying ` +
                        `(status ${status || err.code}) — likely a rate/quota limit, not a transient error. ` +
                        `Aborting rather than blocking the run for that long.`
                    );
                }

                logger.warn(
                    `[CerebrasClient] ${status || err.code || err.message} — ` +
                    `retrying (${attempt + 1}/${MAX_RETRIES}) in ${Math.round(delay / 1000)}s...`
                );
                await sleep(delay);
            } else if (attempt >= MAX_RETRIES) {
                throw new InfrastructureError(
                    `Cerebras API unreachable after ${MAX_RETRIES} retries: ${err.message}`
                );
            } else {
                // Not retryable
                throw new InfrastructureError(`Cerebras API call failed: ${err.message}`);
            }
        }
    }

    throw new InfrastructureError(`Cerebras API unreachable after ${MAX_RETRIES} retries: ${lastError?.message}`);
}

/**
 * Legacy compatibility shim for scoreCheck callers (sensitiveDataAI.js etc.)
 * Returns a safe MANUAL result instead of throwing so hardcoded check modules
 * aren't broken by the new strict client.
 */
async function scoreCheck({ model = AI_MODEL, systemPrompt, evidence }) {
    try {
        const parsed = await callCerebras({ model, systemPrompt, userContent: evidence });
        if (!parsed.verdict || !parsed.evidence_cited) {
            return { status: 'MANUAL', message: 'AI response malformed — flagged for manual review' };
        }
        return parsed;
    } catch (err) {
        if (err.name === 'InfrastructureError') throw err; // propagate to abort the scan
        logger.error(`Cerebras API call failed: ${err.message}`);
        return { status: 'MANUAL', message: `AI request failed: ${err.message}` };
    }
}

module.exports = { callCerebras, scoreCheck, getCallCount, resetCallCount };
