/**
 * APInspect AI Configuration
 * Tune these thresholds to adjust AI verdict sensitivity per-run.
 *
 * Model pinning:
 *   Always pin the model ID here — never hard-code it in individual modules.
 *   Before upgrading, check: https://inference-docs.cerebras.ai/models/overview
 *   Preview models (zai-glm-4.7, gemma-4-31b) can be discontinued at any time;
 *   do NOT use them in a CI/CD pipeline without an explicit fallback strategy.
 */

// Pinned Cerebras model — Production tier as of July 2026.
// ~3,000 tok/s; sufficient for structured JSON generation in all three AI stages.
const AI_MODEL = 'gpt-oss-120b';

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
    AI_CONFIDENCE_THRESHOLD,
    AI_FAIL_CONFIDENCE_THRESHOLD,
};
