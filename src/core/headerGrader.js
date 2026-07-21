const rules = require('../config/securityHeaderRules.json');

// One evaluator per `partialCredit[].test` name referenced in securityHeaderRules.json.
// Each receives the raw header value (string) and the full lower-cased headers map,
// and returns true if the weakness it names is present.
const QUALITY_TESTS = {
    maxAgeBelow6Months: (value) => {
        const match = /max-age=(\d+)/i.exec(value || '');
        if (!match) return true;
        return parseInt(match[1], 10) < 15552000; // 180 days
    },
    missingIncludeSubDomains: (value) => !/includesubdomains/i.test(value || ''),
    unsafeInline: (value) => /'unsafe-inline'/i.test(value || ''),
    unsafeEval: (value) => /'unsafe-eval'/i.test(value || ''),
    wildcardSource: (value) => /(^|\s)\*(\s|;|$)/.test(value || ''),
    missingDefaultSrc: (value) => !/default-src/i.test(value || ''),
    weakValue_xfo: (value) => !/^(deny|sameorigin)$/i.test((value || '').trim()),
    weakValue_xcto: (value) => (value || '').trim().toLowerCase() !== 'nosniff',
    unsafeUrl: (value) => (value || '').trim().toLowerCase() === 'unsafe-url',
    enabledBlockMode: () => false,
};

// A couple of rules reuse the generic "weakValue" test name in the JSON but need
// header-specific logic — map them here rather than special-casing the header name inline.
const TEST_ALIASES = {
    'x-frame-options': { weakValue: 'weakValue_xfo' },
    'x-content-type-options': { weakValue: 'weakValue_xcto' },
};

const resolveTest = (headerKey, testName) => {
    const alias = TEST_ALIASES[headerKey] && TEST_ALIASES[headerKey][testName];
    return QUALITY_TESTS[alias || testName];
};

const GRADE_THRESHOLDS = [
    { min: 90, grade: 'A+' },
    { min: 80, grade: 'A' },
    { min: 65, grade: 'B' },
    { min: 50, grade: 'C' },
    { min: 35, grade: 'D' },
    { min: 20, grade: 'E' },
    { min: -Infinity, grade: 'F' },
];

const scoreToGrade = (score) => GRADE_THRESHOLDS.find(t => score >= t.min).grade;

const normalizeHeaders = (headers = {}) => {
    const out = {};
    for (const [key, value] of Object.entries(headers)) {
        out[key.toLowerCase()] = Array.isArray(value) ? value.join(', ') : value;
    }
    return out;
};

/**
 * Grade a response's security headers, securityheaders.com-style.
 * @param {object} headers - Response headers (any casing).
 * @param {object} opts
 * @param {boolean} opts.isHttps - Whether the graded URL is HTTPS (gates HSTS applicability).
 * @returns {{ grade: string, score: number, maxScore: number, findings: Array }}
 */
const grade = (headers, { isHttps = true } = {}) => {
    const h = normalizeHeaders(headers);
    const findings = [];

    let maxPoints = 0;
    let earnedPoints = 0;
    let leakPenalty = 0;

    for (const rule of rules) {
        const value = h[rule.header];
        const present = value !== undefined && value !== null && value !== '';

        // Leaking / fingerprinting headers: penalize if present, never contribute to maxPoints.
        if (rule.leaking) {
            if (present) {
                leakPenalty += rule.weight;
                findings.push({
                    header: rule.label,
                    status: 'LEAK',
                    value,
                    message: `${rule.label} discloses server implementation details.`,
                    recommendation: rule.recommendation,
                });
            }
            continue;
        }

        // Informational-only headers (e.g. deprecated X-XSS-Protection) never affect the score.
        if (rule.informational) {
            if (present) {
                findings.push({
                    header: rule.label,
                    status: 'INFO',
                    value,
                    message: `${rule.label} is present but deprecated.`,
                    recommendation: rule.recommendation,
                });
            }
            continue;
        }

        // HSTS only applies to HTTPS targets — don't penalize plain-HTTP endpoints for it.
        if (rule.httpsOnly && !isHttps) {
            findings.push({
                header: rule.label,
                status: 'N/A',
                value: null,
                message: `${rule.label} skipped — target is not served over HTTPS.`,
                recommendation: rule.recommendation,
            });
            continue;
        }

        maxPoints += rule.weight;

        if (!present) {
            findings.push({
                header: rule.label,
                status: 'MISSING',
                value: null,
                message: `${rule.label} is missing.`,
                recommendation: rule.recommendation,
            });
            continue;
        }

        // Present — check value quality via this rule's partialCredit tests.
        let points = rule.weight;
        const weaknesses = [];
        for (const check of (rule.partialCredit || [])) {
            const test = resolveTest(rule.header, check.test);
            if (test && test(value, h)) {
                points -= rule.weight * check.penaltyFraction;
                weaknesses.push(check.note);
            }
        }
        points = Math.max(0, points);
        earnedPoints += points;

        if (weaknesses.length > 0) {
            findings.push({
                header: rule.label,
                status: 'WEAK',
                value,
                message: `${rule.label} is present but weak: ${weaknesses.join('; ')}.`,
                recommendation: rule.recommendation,
            });
        } else {
            findings.push({
                header: rule.label,
                status: 'GOOD',
                value,
                message: `${rule.label} is present and correctly configured.`,
                recommendation: null,
            });
        }
    }

    const scaledScore = maxPoints > 0 ? (earnedPoints / maxPoints) * 100 : 100;
    const score = Math.max(0, Math.round(scaledScore - leakPenalty));

    return {
        grade: scoreToGrade(score),
        score,
        maxScore: 100,
        findings,
    };
};

module.exports = { grade };
