/**
 * APInspect AI Configuration
 * Tune these thresholds to adjust AI verdict sensitivity per-run.
 *
 * Model pinning:
 *   Always pin the model ID here — never hard-code it in individual modules.
 *   Before upgrading, check: https://openrouter.ai/models
 *   Preview/stealth models (stealth/ox-alpha) can be discontinued or renamed
 *   at any time; do NOT use them in a CI/CD pipeline without an explicit
 *   fallback strategy.
 */

// Pinned OpenRouter model — stealth preview tier as of Aug 2026 (see warning
// above: stealth models can be pulled or renamed without notice).
const AI_MODEL = 'stealth/ox-alpha';

// Model pool, split into tiers of up to 3 — OpenRouter hard-caps its `models`
// fallback field at 3 entries total (confirmed live: a 4th entry 400s the whole
// request), so 6 candidates become 2 tiers rather than one flat list. Tier 0 is
// used by default; modelTierRouter.js rotates to tier 1 once tier 0 looks
// unhealthy (see AI_MODEL_ROUTER_CONFIG below), and loops back to tier 0 if
// tier 1 also goes bad.
//
// Every entry below was verified live against the real API under this exact
// AI_PROVIDER_POLICY (require_parameters + response_format: json_object +
// data_collection: 'deny') this session — most of the free catalog was NOT
// viable and is worth remembering before adding more:
//   - thinkingmachines/inkling(-small):free -> 403, "only available on agentic
//     harnesses" — not reachable via the plain chat completions API at all.
//   - nvidia/nemotron-3-ultra-550b-a55b:free, nvidia/nemotron-3-nano-omni-*,
//     nvidia/nemotron-3.5-lightning:free, cohere/north-mini-code:free,
//     poolside/laguna-*:free -> 404 "No endpoints found that can handle the
//     requested parameters" — no provider for these supports response_format
//     + require_parameters together. Persistent, not transient.
//   - nvidia/nemotron-3-super-120b-a12b:free, liquid/lfm-2.5-2.6b:free -> 404
//     "No endpoints found matching your data policy (Free model training)" —
//     these specifically require opting INTO training-data collection as the
//     price of free access, which data_collection: 'deny' rules out. Loosening
//     data_collection would open these up, at the cost documented above it.
//   - openrouter/free -> 200 but an empty/null message content — OpenRouter's
//     own opaque auto-router; unusable with this client's strict-JSON parsing.
// google/gemma-4-26b-a4b-it:free and z-ai/glm-5.2:free also passed (both only
// rate-limited, not structurally broken) but weren't needed to fill both tiers
// — swap them in ahead of anything above if a current tier member goes bad.
//
// This is a snapshot from one test session, not a permanent ranking — model
// availability/pricing/policy on OpenRouter's free tier changes often. Watch
// the "[OpenRouterClient] response served by <model>, not <requested>" and
// "rotating to tier N" log lines and reorder/swap based on what you actually
// see land in FALCON verdicts.
// Leave AI_MODEL_TIERS as a single one-model tier (e.g. [[AI_MODEL]]) to
// disable fallback/rotation entirely and fail closed on AI_MODEL alone — do
// this for a run whose result you need to be reproducible against one known
// model.
const AI_MODEL_TIERS = [
    [AI_MODEL, 'dots-studio/dots-3-note-preview:free', 'minimax/minimax-m2.7:free'],
    ['minimax/minimax-m3:free', 'google/gemma-4-31b-it:free', 'z-ai/glm-5.2:free'],
];

// Fail fast at load time rather than with a confusing 400 mid-scan if a tier
// is ever hand-edited past OpenRouter's cap.
for (const [i, tier] of AI_MODEL_TIERS.entries()) {
    if (!Array.isArray(tier) || tier.length === 0 || tier.length > 3) {
        throw new Error(`aiConfig.js: AI_MODEL_TIERS[${i}] must have 1-3 entries (OpenRouter's fallback cap) — got ${tier?.length ?? 'invalid'}.`);
    }
}

// Tunables for modelTierRouter.js's rotation decisions.
const AI_MODEL_ROUTER_CONFIG = {
    // Full call failures (all of callOpenRouter's own MAX_RETRIES exhausted) in a
    // row against the active tier before rotating away from it. Deliberately low
    // relative to that per-call retry count — by the time this fires, that's
    // already 2 whole exhausted-retry call failures against the same 3 models,
    // not a single blip the retry loop should have already absorbed.
    failureThreshold: 2,
    // A tier is "slow" once its rolling average latency over the last
    // slowWindowSize successful calls exceeds this many ms. 15s leaves headroom
    // under callOpenRouter's 25s axios timeout — slow-but-not-yet-timing-out
    // gets caught here instead of only via outright failures.
    slowLatencyMs: 15_000,
    slowWindowSize: 4,
    // Once rotated away from, a tier is skipped in the round-robin loop for this
    // long before it's eligible again — long enough for a transient outage to
    // have a real chance to clear, short enough that a long-running scan can
    // recover mid-run.
    cooldownMs: 5 * 60 * 1000,
};

// Sent as OpenRouter's `provider` request field on every call.
// - allow_fallbacks: within ONE model, let OpenRouter retry a different HOST
//   on a 5xx/rate-limit before giving up on that model — this is the automatic
//   layer, on by default upstream; kept explicit here for clarity.
// - require_parameters: only route to a provider that actually honors every
//   parameter this client sends (response_format: json_object, temperature).
//   Without this, a fallback provider can silently ignore response_format and
//   hand back prose instead of JSON — reintroducing the exact malformed-output
//   failure mode the retry/degrade logic in openrouterClient.js exists for.
// - data_collection: this tool sends live target-API responses — auth tokens,
//   PII, internal stack traces — to whichever model/provider ends up serving a
//   call. 'deny' opts every provider that gets used out of retaining requests
//   for training, with no observed availability cost (every model across both
//   AI_MODEL_TIERS routes fine with this set).
// - zdr (stricter: require a zero-data-retention *host*, not just a policy
//   that says "don't train on this") is deliberately left OFF by default —
//   turning it on 404s outright ("No endpoints found matching your data
//   policy") for every model currently in this config, because none of their
//   providers are ZDR-enrolled today. Confirm your target model(s) actually
//   have a ZDR-eligible host before flipping this on (openrouter.ai/settings/privacy
//   lists account-level enrollment; provider-level support varies per model).
const AI_PROVIDER_POLICY = {
    allow_fallbacks: true,
    require_parameters: true,
    data_collection: 'deny',
    // zdr: true,
};

// Global baseline confidence threshold.
// AI verdicts with confidence below this are force-downgraded to MANUAL /
// TO BE CONFIRMED.
const AI_CONFIDENCE_THRESHOLD = 0.6;

// Asymmetric FAIL threshold.
// A FAIL verdict below this confidence is also downgraded —
// false positives on FAIL erode trust faster than missed issues.
// Must be >= AI_CONFIDENCE_THRESHOLD.
const AI_FAIL_CONFIDENCE_THRESHOLD = 0.75;

module.exports = {
    AI_MODEL,
    AI_MODEL_TIERS,
    AI_MODEL_ROUTER_CONFIG,
    AI_PROVIDER_POLICY,
    AI_CONFIDENCE_THRESHOLD,
    AI_FAIL_CONFIDENCE_THRESHOLD,
};
