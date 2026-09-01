/**
 * src/core/modelTierRouter.js
 *
 * Decides which tier of OpenRouter models openrouterClient.js should send on the
 * NEXT call, based on how calls using the currently-active tier have behaved so
 * far. See docs/MODEL-TIER-ROUTER-PLAN.md for the full design rationale.
 *
 * OpenRouter resolves its `models` fallback field entirely server-side within one
 * HTTP request — we only ever observe a request's final outcome (success, with
 * which model actually answered, or one aggregate failure once every model in
 * the array is exhausted). There is no per-model breakdown mid-request, so model
 * selection has to be a per-call decision made here before the request goes out,
 * not something steerable during it.
 *
 * State is module-level and process-lifetime only (mirrors the existing
 * _usingAltKey pattern in openrouterClient.js) — each `apinspect scan` invocation
 * is a fresh process, and the free-model landscape shifts fast enough that
 * carrying health data across runs isn't worth the complexity of persisting it.
 */

const logger = require('../utils/logger');
const { AI_MODEL_TIERS, AI_MODEL_ROUTER_CONFIG } = require('../config/aiConfig');

const { failureThreshold, slowLatencyMs, slowWindowSize, cooldownMs } = AI_MODEL_ROUTER_CONFIG;

let _activeTierIndex = 0;

const _tierState = AI_MODEL_TIERS.map(() => ({
    consecutiveFailures: 0,
    recentLatencies: [],
    unhealthyUntil: 0,
}));

function _rollingAverage(latencies) {
    return latencies.reduce((sum, ms) => sum + ms, 0) / latencies.length;
}

// Picks the next tier in round-robin order — this is the "loop": after the last
// tier it wraps back to tier 0. If every tier is currently on cooldown, forces
// the least-recently-failed one anyway (see docs/MODEL-TIER-ROUTER-PLAN.md's
// "all tiers on cooldown" section) rather than refusing to make a call — a
// model/provider quality problem shouldn't hard-abort the scan the way a real
// account-level outage (auth/quota, handled separately in openrouterClient.js)
// still does.
function _pickNextHealthyTierIndex(fromIndex) {
    const now = Date.now();
    for (let step = 1; step <= AI_MODEL_TIERS.length; step++) {
        const candidate = (fromIndex + step) % AI_MODEL_TIERS.length;
        if (_tierState[candidate].unhealthyUntil <= now) return candidate;
    }
    // Every tier is on cooldown — force the one whose cooldown ends soonest.
    let soonest = (fromIndex + 1) % AI_MODEL_TIERS.length;
    for (let i = 0; i < AI_MODEL_TIERS.length; i++) {
        if (_tierState[i].unhealthyUntil < _tierState[soonest].unhealthyUntil) soonest = i;
    }
    logger.warn('[ModelTierRouter] Every tier is on cooldown — forcing the soonest-to-recover tier anyway rather than aborting.');
    return soonest;
}

function _rotate(reason) {
    const from = _activeTierIndex;
    _tierState[from].unhealthyUntil = Date.now() + cooldownMs;
    _tierState[from].consecutiveFailures = 0;
    _tierState[from].recentLatencies = [];

    _activeTierIndex = _pickNextHealthyTierIndex(from);

    logger.warn(
        `[ModelTierRouter] Tier ${from} ${reason} — rotating to tier ${_activeTierIndex}: ` +
        `[${AI_MODEL_TIERS[_activeTierIndex].join(', ')}]`
    );
}

/**
 * @returns {{model: string, models: string[]}} the request fields for the
 *   currently-active tier — `model` is that tier's first entry (OpenRouter
 *   expects `model` to match models[0]), `models` is the full tier.
 */
function getActiveModelFields() {
    const tier = AI_MODEL_TIERS[_activeTierIndex];
    return { model: tier[0], models: tier };
}

/**
 * Record a fully successful call (already past openrouterClient's own
 * MAX_RETRIES loop) against the active tier — resets its failure streak and
 * feeds the rolling latency window used for the "slow" rotation check.
 *
 * @param {number} latencyMs
 */
function reportSuccess(latencyMs) {
    const state = _tierState[_activeTierIndex];
    state.consecutiveFailures = 0;
    // A real success proves this tier is healthy right now — clear any stale
    // cooldown flag left over from a forced-through pick (see
    // _pickNextHealthyTierIndex) rather than leaving it misreported as
    // "on cooldown" in getStatus() until the original timer would've expired.
    state.unhealthyUntil = 0;

    state.recentLatencies.push(latencyMs);
    if (state.recentLatencies.length > slowWindowSize) state.recentLatencies.shift();

    if (state.recentLatencies.length >= slowWindowSize && _rollingAverage(state.recentLatencies) > slowLatencyMs) {
        _rotate(`is slow (rolling avg ${Math.round(_rollingAverage(state.recentLatencies))}ms over last ${slowWindowSize} calls > ${slowLatencyMs}ms)`);
    }
}

/**
 * Record a call that exhausted openrouterClient's own retry loop and threw —
 * rotates away from the active tier once failureThreshold is hit.
 */
function reportFailure() {
    const state = _tierState[_activeTierIndex];
    state.consecutiveFailures++;

    if (state.consecutiveFailures >= failureThreshold) {
        _rotate(`unhealthy (${state.consecutiveFailures} consecutive call failures)`);
    }
}

/** @returns {object} snapshot of router state, for debugging/tests. */
function getStatus() {
    return {
        activeTierIndex: _activeTierIndex,
        activeTier: AI_MODEL_TIERS[_activeTierIndex],
        tiers: AI_MODEL_TIERS.map((tier, i) => ({
            tier,
            ..._tierState[i],
            onCooldown: _tierState[i].unhealthyUntil > Date.now(),
        })),
    };
}

module.exports = { getActiveModelFields, reportSuccess, reportFailure, getStatus };
