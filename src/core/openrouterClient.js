const axios = require('axios');
const logger = require('../utils/logger');
const { AI_PROVIDER_POLICY } = require('../config/aiConfig');
const { InfrastructureError } = require('../utils/errors');
const modelTierRouter = require('./modelTierRouter');

const OPENROUTER_URL = 'https://openrouter.ai/api/v1/chat/completions';

// Errors that are transient — worth retrying
const RETRYABLE_STATUS_CODES = new Set([429, 503, 502, 504]);
const RETRYABLE_CODES = new Set(['ETIMEDOUT', 'ECONNRESET', 'ECONNREFUSED', 'ENOTFOUND']);

// Errors that will never fix themselves — fail immediately
const FATAL_STATUS_CODES = new Set([400, 401, 403]);

// A different key means a different rate/quota bucket — worth a one-time swap
// rather than backing off or aborting the whole scan.
const KEY_SWITCH_STATUS_CODES = new Set([401, 402, 403, 429]);

// Module-level because callOpenRouter is the single choke point every AI-touched
// code path funnels through — once the primary key is exhausted it stays
// exhausted for the rest of the process, so we don't re-attempt it per call.
let _usingAltKey = false;

// Models we've already warned served a response in place of what was requested —
// logged once per distinct fallback model per process, not once per call, so a
// long scan that lands on the same fallback repeatedly doesn't spam the log.
const _warnedFallbackModels = new Set();

// OpenRouter nests its actual error text under data.error.message, not data.message —
// fall through a few shapes so a fatal-status log/throw always carries the real reason
// instead of axios's generic "Request failed with status code NNN". When the error was
// relayed from an upstream provider (see isRetryable below), name the provider too —
// "Provider returned error" alone doesn't say which one or why.
function extractApiErrorMessage(err) {
    const apiError = err.response?.data?.error;
    if (apiError?.metadata?.provider_name) {
        const upstreamSuffix = apiError.metadata.raw ? `, upstream: ${apiError.metadata.raw}` : '';
        return `${apiError.message} (provider: ${apiError.metadata.provider_name}${upstreamSuffix})`;
    }
    return apiError?.message || err.response?.data?.message || err.message;
}

// True when a FATAL_STATUS_CODES response was actually relayed from a specific upstream
// provider (OpenRouter's `provider` object nests provider_name + previous_errors) rather
// than being a real problem with our own API key/request. Observed live: OpenRouter's own
// automatic provider failover (allow_fallbacks) can still exhaust every provider it tried
// within one request and surface the last one's error as a 401/403 — but that provider
// pool often isn't equally exhausted a few seconds later. Treat it as worth OUR retry
// loop's backoff rather than instantly fatal, the same way a bad API key (no
// provider_name — the request never reached a provider at all) still isn't.
function isProviderRelayedError(err) {
    return !!err.response?.data?.error?.metadata?.provider_name;
}

function getApiKey() {
    if (_usingAltKey && process.env.OPENROUTER_API_KEY_ALT) {
        return process.env.OPENROUTER_API_KEY_ALT;
    }
    return process.env.OPENROUTER_API_KEY;
}

const MAX_RETRIES = 3;
const BASE_DELAY_MS = 1000;

// A server-provided Retry-After can be huge (a daily/hourly quota reset can be
// thousands of seconds out) — sleeping for the full duration would hang a CI job
// for up to an hour instead of failing the step. Cap what we'll actually wait for;
// anything longer is treated as quota exhaustion and fails fast instead.
const MAX_BACKOFF_MS = 120_000; // 2 minutes

// Every actual request sent to OpenRouter, including retries — this is the number
// that maps to real quota/billing usage, not "logical" calls. Module-level because
// callOpenRouter is the single choke point every AI-touched code path funnels through.
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
    if (err instanceof SyntaxError) return true;
    if (err.response) {
        if (FATAL_STATUS_CODES.has(err.response.status)) return isProviderRelayedError(err);
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
 * Parse a model response as JSON, tolerating a stray markdown code fence —
 * reasoning-model preview tiers occasionally wrap the JSON in one despite
 * response_format: json_object. Logs the raw (truncated) content before
 * giving up so a genuinely malformed response is debuggable after the fact.
 *
 * @param {string} raw
 * @returns {object}
 * @throws {SyntaxError} if the content isn't valid JSON even after unwrapping
 */
function parseModelJson(raw) {
    try {
        return JSON.parse(raw);
    } catch (parseErr) {
        const trimmed = raw.trim();
        let fenced = trimmed;
        if (fenced.startsWith('```')) {
            fenced = fenced.replace(/^```[a-zA-Z]*\n/, '');
        }
        if (fenced.endsWith('```')) {
            fenced = fenced.slice(0, -3).trimEnd();
        }
        if (fenced !== trimmed) {
            try {
                return JSON.parse(fenced);
            } catch (_) { /* fall through to logging below */ }
        }

        // Try removing trailing garbage after the last '}' or ']'
        let noGarbage = fenced;
        const lastBrace = noGarbage.lastIndexOf('}');
        const lastBracket = noGarbage.lastIndexOf(']');
        const lastValid = Math.max(lastBrace, lastBracket);
        if (lastValid !== -1 && lastValid < noGarbage.length - 1) {
            try {
                return JSON.parse(noGarbage.slice(0, lastValid + 1));
            } catch (_) { /* fall through */ }
        }

        logger.error(
            `[OpenRouterClient] Model returned invalid JSON (${parseErr.message}). ` +
            `Raw content (truncated): ${raw.slice(0, 2000)}`
        );
        throw parseErr;
    }
}

/**
 * Make an OpenRouter API call with exponential backoff for transient errors.
 *
 * - Retryable errors (429, 503, timeouts, and a 401/400/403 relayed from a
 *   specific upstream provider rather than our own key/request — see
 *   isProviderRelayedError): retry up to MAX_RETRIES times, then throw
 *   InfrastructureError.
 * - Non-retryable errors (a genuine 401/400/403 on our own key/request,
 *   malformed response after retries): throw immediately / after retries.
 *
 * @param {object} opts - { systemPrompt, userContent, temperature }
 * @returns {Promise<object>} - The parsed JSON response from the model
 * @throws {InfrastructureError} - If retries exhausted or fatal API error
 * @throws {Error} - If the model returns a malformed response
 */
async function callOpenRouter({ systemPrompt, userContent, temperature = 0 }) {
    if (!process.env.OPENROUTER_API_KEY && !process.env.OPENROUTER_API_KEY_ALT) {
        throw new InfrastructureError('OPENROUTER_API_KEY is not set in environment.');
    }

    // Captured once for the whole logical call — a retry within this call (a 503,
    // a rate limit) keeps using the same tier. Rotation is a call-to-call decision
    // driven by reportSuccess/reportFailure below, not a mid-retry one; the tier
    // router and this function's own retry loop handle two different problems
    // ("is this one call getting through" vs. "should the NEXT call even try this
    // tier"), so they don't reach into each other.
    const { model, models } = modelTierRouter.getActiveModelFields();

    let lastError;
    for (let attempt = 0; attempt <= MAX_RETRIES; attempt++) {
        try {
            _requestCount++;
            const requestStartedAt = Date.now();
            const res = await axios.post(OPENROUTER_URL, {
                model,
                models,
                provider: AI_PROVIDER_POLICY,
                messages: [
                    { role: 'system', content: systemPrompt },
                    { role: 'user', content: typeof userContent === 'string' ? userContent : JSON.stringify(userContent) },
                ],
                response_format: { type: 'json_object' },
                temperature,
                max_tokens: 8192,
            }, {
                headers: { Authorization: `Bearer ${getApiKey()}` },
                timeout: 25000,
            });

            // OpenRouter reports which model/provider actually answered — can differ
            // from `model` once either fallback layer kicks in. A different model means
            // different tone, JSON adherence, and tool-calling reliability, so surface it
            // instead of letting it pass silently as if the requested model had answered.
            const servedBy = res.data.model;
            if (servedBy && servedBy !== model && !_warnedFallbackModels.has(servedBy)) {
                _warnedFallbackModels.add(servedBy);
                logger.warn(`[OpenRouterClient] Response served by fallback model "${servedBy}", not requested "${model}" — verdict quality/JSON adherence may differ.`);
            }

            // A 2xx response body isn't guaranteed to have the expected shape. Observed
            // live: OpenRouter can return HTTP 200 with an error envelope instead of a
            // real completion — "Insufficient balance" (402), "Provider returned error"
            // (401) — rather than a real non-2xx status. When that envelope is present,
            // synthesize a response-shaped error so it flows through the SAME
            // status-code logic below (alt-key switch on 402/401/403/429, immediate
            // fail on a genuine fatal status, retry on a provider-relayed one) as a
            // "real" non-2xx would — a billing/auth problem shouldn't silently get
            // bucketed as generic malformed JSON and burn 3 retries before failing
            // with a message that hides the actual cause.
            const raw = res.data?.choices?.[0]?.message?.content;
            if (raw === undefined || raw === null) {
                const embeddedError = res.data?.error;
                if (embeddedError) {
                    const envelopeErr = new Error(embeddedError.message || 'OpenRouter returned an error envelope in a 200 response');
                    envelopeErr.response = { status: embeddedError.code || 500, data: res.data, headers: res.headers };
                    throw envelopeErr;
                }
                // No error envelope either — a genuinely unexpected empty/malformed body.
                // Fall through to the existing malformed-JSON retry/degrade handling.
                throw new SyntaxError(`OpenRouter response missing choices[0].message.content (raw body: ${JSON.stringify(res.data).slice(0, 500)})`);
            }
            const parsed = parseModelJson(raw); // throws SyntaxError on malformed JSON, handled below — not a tier success
            modelTierRouter.reportSuccess(Date.now() - requestStartedAt);
            return parsed;

        } catch (err) {
            lastError = err;
            const status = err.response?.status;

            // A rate/quota/auth error on OUR primary key doesn't mean the alt key is
            // in the same boat — swap once and retry immediately, no backoff needed
            // since it's a different bucket entirely. Excludes provider-relayed
            // errors (see isProviderRelayedError) — those aren't about our key at
            // all, so switching keys can't fix them and would just burn the swap.
            if (err.response && KEY_SWITCH_STATUS_CODES.has(status) && !isProviderRelayedError(err) && !_usingAltKey && process.env.OPENROUTER_API_KEY_ALT) {
                _usingAltKey = true;
                logger.warn(`[OpenRouterClient] ${status} on primary key — switching to OPENROUTER_API_KEY_ALT and retrying...`);
                continue;
            }

            // Non-retryable: fail immediately — unless it's a provider-relayed error
            // (isProviderRelayedError), which falls through to the normal backoff/
            // retry path below instead. Also reported to the tier router — a model
            // that's been retired/renamed shows up as a genuinely fatal "model not
            // found"-style error here, and this is the only path that would ever
            // catch it (a rotation-worthy failure, not just an account/key issue).
            if (err.response && FATAL_STATUS_CODES.has(status) && !isProviderRelayedError(err)) {
                modelTierRouter.reportFailure();
                throw new InfrastructureError(
                    `OpenRouter API returned ${status} (non-retryable): ${extractApiErrorMessage(err)}`,
                    { status }
                );
            }

            // JSON parse error on a 200 — malformed model output, treat as transient
            // (falls through to isRetryable logic below)

            if (attempt < MAX_RETRIES && isRetryable(err)) {
                const delay = getRetryDelay(err, attempt);

                if (delay > MAX_BACKOFF_MS) {
                    // The server is telling us to come back in minutes/hours, not
                    // seconds — that's a quota reset, not a transient blip. Waiting
                    // it out would hang the run; fail fast so the caller (engine.js)
                    // can abort or the CI job can report a clear cause instead of a
                    // multi-hour timeout. Reported to the tier router too — a model
                    // specifically getting rate-limited is exactly the kind of
                    // per-model signal rotation exists to react to.
                    modelTierRouter.reportFailure();
                    throw new InfrastructureError(
                        `OpenRouter API asked us to wait ${Math.round(delay / 1000)}s before retrying ` +
                        `(status ${status || err.code}) — likely a rate/quota limit, not a transient error. ` +
                        `Aborting rather than blocking the run for that long.`,
                        { status }
                    );
                }

                logger.warn(
                    `[OpenRouterClient] ${status || err.code || err.message} — ` +
                    `retrying (${attempt + 1}/${MAX_RETRIES}) in ${Math.round(delay / 1000)}s...`
                );
                await sleep(delay);
            } else if (attempt >= MAX_RETRIES) {
                modelTierRouter.reportFailure();
                const isMalformedJson = err instanceof SyntaxError;
                let cause = err.message;
                if (isMalformedJson) cause = 'malformed JSON';
                else if (err.response) cause = extractApiErrorMessage(err);
                const infraErr = new InfrastructureError(
                    `OpenRouter API failed after ${MAX_RETRIES} retries: ${cause}`,
                    { status }
                );
                // Lets callers (e.g. a batched classifier) tell "the model keeps writing
                // bad JSON" apart from a real outage (network/auth/quota) — the former is
                // an evaluation gap for that one batch, not a reason to abort the whole scan.
                if (isMalformedJson) infraErr.reason = 'malformed_json';
                throw infraErr;
            } else {
                // Not retryable — e.g. a 404 (RETRYABLE_STATUS_CODES doesn't include it, so
                // isRetryable() said no) that isn't one of the FATAL_STATUS_CODES either.
                modelTierRouter.reportFailure();
                throw new InfrastructureError(`OpenRouter API call failed (status ${status || err.code}): ${extractApiErrorMessage(err)}`, { status });
            }
        }
    }

    throw new InfrastructureError(`OpenRouter API unreachable after ${MAX_RETRIES} retries: ${lastError?.message}`, { status: lastError?.response?.status });
}

/**
 * Legacy compatibility shim for scoreCheck callers (sensitiveDataAI.js etc.)
 * Returns a safe MANUAL result instead of throwing so hardcoded check modules
 * aren't broken by the new strict client.
 */
async function scoreCheck({ systemPrompt, evidence }) {
    try {
        const parsed = await callOpenRouter({ systemPrompt, userContent: evidence });
        if (!parsed.verdict || !parsed.evidence_cited) {
            return { status: 'MANUAL', message: 'AI response malformed — flagged for manual review' };
        }
        return parsed;
    } catch (err) {
        if (err.name === 'InfrastructureError') throw err; // propagate to abort the scan
        logger.error(`OpenRouter API call failed: ${err.message}`);
        return { status: 'MANUAL', message: `AI request failed: ${err.message}` };
    }
}

module.exports = { callOpenRouter, scoreCheck, getCallCount, resetCallCount };
