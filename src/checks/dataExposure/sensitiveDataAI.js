const { scoreCheck } = require('../../core/cerebrasClient');
const SYSTEM_PROMPT = require('./prompts/sensitiveDataExposure');

/**
 * AI-assisted check: Sensitive Data Exposure
 *
 * Reads captured request/response evidence from context.evidenceStore
 * and asks Cerebras to score this checklist item.
 *
 * Falls back to MANUAL if:
 *  - No evidence was captured for this endpoint
 *  - The response body is empty
 *  - The AI call fails or returns a malformed response
 *  - AI confidence is below threshold (handled centrally in engine.js)
 *
 * Export shape is identical to rule-based checks so it drops in to
 * the engine's checksRegistry without any orchestration changes.
 */
module.exports = async (context, client, endpoint) => {
    const evidence = context.getEvidenceFor(endpoint);

    if (!evidence || !evidence.responseBody) {
        return {
            status: 'MANUAL',
            message: 'No captured response available for this endpoint — run `apinspect audit` first to populate evidence, then re-scan.',
        };
    }

    const result = await scoreCheck({
        systemPrompt: SYSTEM_PROMPT,
        evidence: {
            url: evidence.url,
            method: evidence.method,
            statusCode: evidence.statusCode,
            responseHeaders: evidence.responseHeaders,
            // Cap payload to avoid blowing Cerebras context window
            responseBody: evidence.responseBody.slice(0, 8000),
        },
    });

    // If scoreCheck itself returned a fallback (API error, malformed response),
    // it already has { status: 'MANUAL', message } — pass it through.
    if (result.status === 'MANUAL') {
        return result;
    }

    return {
        status: result.verdict,
        message: result.message,
        details: { statusCode: evidence.statusCode },
        ai_confidence: result.confidence,
        ai_reasoning: result.message,
        evidence_cited: result.evidence_cited,
    };
};
