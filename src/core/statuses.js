/**
 * src/core/statuses.js
 *
 * Single source of truth for APInspect's result-status vocabulary. Every module
 * that needs to test "is this a fail" or "is this a coverage gap, not a verdict"
 * imports from here instead of hand-maintaining its own copy of the list — that
 * duplication is exactly how FAIL/FAILED drifted into two strings meaning the
 * same thing, and how coverage-gap statuses used to get silently folded into
 * PASS/N/A by reporters that didn't know they existed.
 */

// 'FAILED' is kept only so results/caches generated before this file existed
// (or an AI response that slips back to the old contract) still compare correctly.
// Every code path that emits a new result should emit 'FAIL'.
const FAIL_STATUSES = ['FAIL', 'FAILED'];

const PASS_STATUS = 'PASS';
const NOT_APPLICABLE_STATUS = 'N/A';

// "A human needs to look at this specific piece of evidence" — ambiguous or
// low-confidence, but a real evaluation was attempted.
const NEEDS_REVIEW_STATUSES = ['MANUAL', 'TO BE CONFIRMED'];

// The checklist item WAS applicable and a real request WAS sent, but the
// result can't be trusted as a security verdict because the request never
// reached the code under test. Distinct from NEEDS_REVIEW (a human should
// judge this evidence) and from N/A (this test does not apply here at all) —
// collapsing either of those into this bucket is what let "107 passed" and
// "135 N/A" both overstate the scan's real coverage.
const COVERAGE_GAP_STATUSES = ['AUTH_BLOCKED', 'ROUTE_NOT_FOUND', 'ENDPOINT_UNHEALTHY', 'UNRESOLVED_PATH'];

const isFail = (status) => FAIL_STATUSES.includes(status);
const isCoverageGap = (status) => COVERAGE_GAP_STATUSES.includes(status);
const isNeedsReview = (status) => NEEDS_REVIEW_STATUSES.includes(status);

module.exports = {
    FAIL_STATUSES,
    PASS_STATUS,
    NOT_APPLICABLE_STATUS,
    NEEDS_REVIEW_STATUSES,
    COVERAGE_GAP_STATUSES,
    isFail,
    isCoverageGap,
    isNeedsReview,
};
