# Tiered Model Fallback Router — Design Plan

> **Status: implemented.** `src/config/aiConfig.js` (`AI_MODEL_TIERS`, `AI_MODEL_ROUTER_CONFIG`),
> `src/core/modelTierRouter.js`, and `src/core/openrouterClient.js` now match this design, with one
> refinement found during live verification: `isRetryable()`/`isProviderRelayedError()` in
> `openrouterClient.js` distinguish a *provider-relayed* fatal status (an upstream provider's own
> error surfaced through OpenRouter, carrying `error.metadata.provider_name`) from a genuine
> account-level fatal error (bad key, deleted model) — only the latter reports an immediate tier
> failure; the former gets the normal backoff/retry first, since it's often gone on the next attempt.
> This doc is kept as the design rationale; treat the code as the source of truth for exact behavior.

## The problem

We picked 6 free/preview OpenRouter models worth trying (1 primary + 5 candidates), but OpenRouter
hard-caps the `models` fallback array at **3 entries total** (confirmed live: a 4th entry 400s the
whole request — see the incident this plan follows). `aiConfig.js` currently ships only the primary
plus 2 fallbacks as a result — the other 3 candidates we picked are sitting unused.

The ask: don't throw away the other 3. Split the 6 into two tiers of 3, run tier 1 by default, and
when tier 1 stops being trustworthy (every model in it is failing, erroring as deleted/unknown, or
consistently slow), switch to tier 2 for subsequent calls. When tier 2 also goes bad, loop back to
tier 1 — on the chance whatever was wrong with it was transient.

This is a **design plan**, not a diff — a few parameters below are genuine judgment calls (rotation
threshold, "slow" definition, what to do if every tier is currently unhealthy) that are called out
explicitly for you to confirm or adjust before anyone writes code.

## What OpenRouter actually gives us to work with

Confirmed by live testing against the real API this session:

- `models: [a, b, c]` is evaluated **entirely server-side, inside one HTTP request**. We get back
  either a success (with `response.data.model` telling us which of the 3 actually answered) or,
  once OpenRouter has exhausted all 3, a single aggregate failure. **We never see "a failed, b
  failed, c succeeded" — only the final outcome.**
- There is no API-level signal for "this model was deleted" distinct from any other failure — a
  retired model ID just fails every request routed to it, same shape as a transient outage. We
  don't need to special-case detecting deletion; a tier that's dead because a model in it was
  pulled looks identical, over a few calls, to a tier that's dead for any other reason. One
  generic "this tier keeps failing" signal covers all of it.
- Consequence for the design: **model selection is a per-call decision made by our code before the
  request goes out**, not something steerable mid-request. "Rotating tiers" means: based on how the
  *last* call(s) using the active tier behaved, decide which tier to send with the *next* call.

## Current architecture (as of this session)

- `src/config/aiConfig.js` — `AI_MODEL` (primary), `AI_MODEL_FALLBACKS` (flat list, ≤2 entries to
  respect the 3-item cap), `AI_PROVIDER_POLICY` (the `provider` object sent on every call).
- `src/core/openrouterClient.js` — the single choke point every AI call funnels through
  (`callOpenRouter`). Already has three pieces of module-level, process-lifetime state worth
  reusing as precedent for how the router should behave:
  - `_usingAltKey` — flips once, permanently, when the primary API key hits a rate/quota/auth
    error. Same shape of problem as tier rotation: "this resource looks bad, stop trying it for
    the rest of the process."
  - `_warnedFallbackModels` — a `Set` used purely to de-duplicate a log line so a long scan
    doesn't spam it every call.
  - `buildModelsField(model)` — the function this plan replaces. Currently static: always returns
    `AI_MODEL_FALLBACKS` truncated to the 3-item cap, with a one-time warning if truncation
    happened.
  - The existing per-call retry loop (`MAX_RETRIES = 3`, exponential backoff) already absorbs
    single-request blips (429/503/timeouts/malformed JSON) *within* one tier before giving up and
    throwing. Tier rotation sits **above** this loop, not inside it — it reacts to a whole call
    (all 3 retries) failing, not to an individual retry.
- Callers (`applicabilityEngine.js`, `probeSynthesizer.js`, `verdictClassifier.js`, and three spots
  in `cli/index.js`) never override `model` — every call uses the default, so the router only needs
  to handle the one shared model chain, not per-caller variance.

## Proposed design: `ModelTierRouter`

A new small module, `src/core/modelTierRouter.js`, sitting next to `openrouterClient.js` (it's
tightly coupled to that file's request-building, not a checklist-orchestration concern like the
`src/core/ai/*` modules).

### Config shape (`aiConfig.js` changes)

Replace the flat `AI_MODEL_FALLBACKS` with an explicit array of tiers — explicit beats "flat list
auto-chunked into 3s" because there are only ever 2 tiers here, and explicit means no magic-number
chunking math to get wrong later:

```js
// Each inner array is sent as OpenRouter's `models` field verbatim — max 3 entries per tier,
// enforced at load time (throw early, don't silently truncate a mis-edited config).
const AI_MODEL_TIERS = [
    ['stealth/ox-alpha', 'nvidia/nemotron-3-ultra-550b-a55b:free', 'thinkingmachines/inkling:free'],
    ['minimax/minimax-m3:free', 'nvidia/nemotron-3-nano-omni-30b-a3b-reasoning:free', 'google/gemma-4-31b-it:free'],
];

const AI_MODEL_ROUTER_CONFIG = {
    // Full call failures (all MAX_RETRIES exhausted) in a row against the active tier before
    // rotating away from it. 2 is deliberately low relative to MAX_RETRIES=3 per call — by the
    // time this fires, that's already 2 x (up to 4 requests) = up to 8 dead requests against the
    // same 3 models, not a single blip.
    failureThreshold: 2,
    // A tier is "slow" if its rolling average latency over the last N successful calls exceeds
    // this many ms. 15s leaves headroom under the existing 25s axios timeout — slow-but-not-yet-
    // timing-out gets caught here instead of only via outright failures.
    slowLatencyMs: 15_000,
    slowWindowSize: 4,
    // Once rotated away from, a tier is skipped for this long before it's eligible again in the
    // round-robin loop — long enough that a transient outage has a real chance to clear, short
    // enough that a scan lasting longer than this can recover mid-run.
    cooldownMs: 5 * 60 * 1000,
};
```

`AI_MODEL` stays as-is, used only as the human-readable "primary" label in logs/docs — the actual
per-call `model`/`models` fields come from whichever tier is active.

### State machine

Module-level state in `modelTierRouter.js` (process-lifetime, matching `_usingAltKey` — no need to
persist across CLI invocations; each `apinspect scan` is a fresh process, and the free-model
landscape shifts fast enough that yesterday's health data isn't worth carrying forward anyway):

```js
let _activeTierIndex = 0;
const _tierState = AI_MODEL_TIERS.map(() => ({
    consecutiveFailures: 0,
    recentLatencies: [],       // last N successful call latencies, for the slow check
    unhealthyUntil: 0,         // epoch ms; 0 = not on cooldown
}));
```

Public surface:
- `getActiveModelFields()` → `{ model: tier[0], models: tier }` for the active tier — dropped
  straight into the request body in place of today's `buildModelsField()` call.
- `reportSuccess(latencyMs)` → resets that tier's `consecutiveFailures`, pushes `latencyMs` into
  its rolling window (capped at `slowWindowSize`), and checks the slow-rotation condition.
- `reportFailure()` → increments `consecutiveFailures`; if it hits `failureThreshold`, rotates.
- `_rotate(reason)` → puts the current tier on cooldown (`unhealthyUntil = now + cooldownMs`),
  resets its counters, advances `_activeTierIndex = (_activeTierIndex + 1) % AI_MODEL_TIERS.length`
  (this is the "loop" — after the last tier it wraps back to tier 0), and logs the switch:
  `[OpenRouterClient] Tier 0 unhealthy (2 consecutive failures) — rotating to tier 1: [minimax/..., nvidia/..., google/...]`.
- `getStatus()` → for debugging/tests: current tier index, per-tier state snapshot.

### Where it plugs into `callOpenRouter`

Two edits to `openrouterClient.js`:
1. Replace `...buildModelsField(model)` with `...modelTierRouter.getActiveModelFields()` (this also
   subsumes today's `model` field — the router decides both `model` and `models` together, so the
   `model = AI_MODEL` default parameter on `callOpenRouter` goes away, or becomes purely a fallback
   for the one legacy caller pattern (`scoreCheck`) that explicitly passes `model` — see open
   question below).
2. Wrap the `axios.post` call with a latency measurement (`Date.now()` before/after — or
   `process.hrtime.bigint()` for precision) and call `reportSuccess`/`reportFailure` on the
   **outer** result — i.e., after the existing per-call retry loop has either succeeded or
   exhausted `MAX_RETRIES` and is about to throw. Do **not** call `reportFailure` on every
   individual retry inside the loop — that would rotate away from a tier on the same kind of
   single blip the retry loop already exists to absorb.

This keeps the two failure-handling layers cleanly separated: the existing retry loop handles
*this one call*, the router handles *which models the next call should even try*.

### "All tiers currently on cooldown" — the one real open question

If every tier is unhealthy-until when the router needs to pick one (e.g. tier 1 just died and tier
2 is still cooling down from an earlier rotation), two options:

- **Fail closed** — throw `InfrastructureError`, matching today's "abort the whole scan on a real
  outage" philosophy. Simple, consistent, but harsh: it stops the scan even though retrying anyway
  costs nothing but time.
- **Force the least-recently-failed tier anyway** (recommended) — ignore cooldown as a last resort
  rather than a hard gate, log that it's a forced retry, and let the normal retry/failure counters
  keep running. Matches the tool's existing bias (see the malformed-JSON fix earlier this session)
  toward degrading gracefully over hard-aborting when the failure is about model/provider quality
  rather than a genuine account-level outage (auth/quota — those still abort immediately via the
  existing `FATAL_STATUS_CODES` path, untouched by any of this).

Recommend the second option but flagging it explicitly since it's a real behavior choice, not a
mechanical one.

## Testing plan

Mirrors how the malformed-JSON degrade path and the fallback-model warning were verified earlier
this session — mocked `axios`, no real API calls needed for the unit-level behavior:

1. Tier 0 healthy → every call uses tier 0's `model`/`models`.
2. Force `failureThreshold` consecutive thrown errors → confirm rotation to tier 1, confirm the log
   line, confirm tier 0's counters reset and it's on cooldown.
3. Tier 1 also fails past threshold → confirm loop-back to tier 0 (respecting whichever
   all-cooldown policy is chosen above).
4. Feed `reportSuccess` latencies above `slowLatencyMs` for `slowWindowSize` calls with zero hard
   failures → confirm rotation still fires (slowness alone is a trigger, not just errors).
5. A single success after some failures → confirm `consecutiveFailures` resets to 0 (recovery
   doesn't require a full cooldown cycle if the tier is still active and simply had a blip).
6. One live smoke test at the end: temporarily point tier 0 at an obviously-invalid model ID,
   confirm real rotation to tier 1 happens against the live API and a real response comes back.

## Implementation checklist

1. `aiConfig.js` — replace `AI_MODEL_FALLBACKS` with `AI_MODEL_TIERS` (validate ≤3 entries per
   tier at module load, throw a clear error immediately if violated — fail at startup, not with a
   confusing 400 mid-scan) and add `AI_MODEL_ROUTER_CONFIG`.
2. New `src/core/modelTierRouter.js` — state + the four functions above, unit-testable in
   isolation from `openrouterClient.js`.
3. `openrouterClient.js` — swap in `getActiveModelFields()`, add latency timing +
   `reportSuccess`/`reportFailure` calls around the existing retry loop's outer success/throw
   points. `getCallCount()`/`resetCallCount()` stay as-is.
4. Decide and resolve the `model` param question for `scoreCheck`'s legacy callers (grep shows
   nothing currently overrides it — confirm still true at implementation time, then either drop
   the override capability or keep it as an explicit opt-out from router-driven selection for that
   one caller).
5. Update the README's "Model fallback" section (added earlier this session) to describe tiers +
   rotation instead of a flat fallback list, including the new `AI_MODEL_ROUTER_CONFIG` knobs.
6. Tests per the plan above, then one live smoke test before calling it done.
