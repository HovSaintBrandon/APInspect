const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');
const { isFail, COVERAGE_GAP_STATUSES } = require('../core/statuses');

const generate = (results, outputPath) => {
    try {
        const reportPath = outputPath || path.join(process.cwd(), 'reports', 'report.json');

        const passed = results.filter(r => r.status === 'PASS').length;
        const failed = results.filter(r => isFail(r.status)).length;
        const na     = results.filter(r => r.status === 'N/A').length;
        // "Applicable" = every result the applicability engine didn't rule out entirely.
        // Coverage % is how much of that was actually evaluated (PASS/FAIL) rather than
        // stalled on a coverage gap (auth block, 404, unhealthy endpoint, unresolved path)
        // or left for manual review — so a headline pass/fail count can no longer imply
        // more assurance than the scan actually delivered.
        const applicable = results.length - na;
        const evaluated = passed + failed;

        const summary = {
            total: results.length,
            passed,
            failed,
            tbc: results.filter(r => r.status === 'TO BE CONFIRMED').length,
            manual: results.filter(r => r.status === 'MANUAL').length,
            na,
            auth_blocked: results.filter(r => r.status === 'AUTH_BLOCKED').length,
            route_not_found: results.filter(r => r.status === 'ROUTE_NOT_FOUND').length,
            endpoint_unhealthy: results.filter(r => r.status === 'ENDPOINT_UNHEALTHY').length,
            unresolved_path: results.filter(r => r.status === 'UNRESOLVED_PATH').length,
            coverage_gaps: results.filter(r => COVERAGE_GAP_STATUSES.includes(r.status)).length,
            coverage: {
                applicable,
                evaluated,
                coverage_pct: applicable > 0 ? Math.round((evaluated / applicable) * 1000) / 10 : null,
            },
        };

        const jsonContent = JSON.stringify(results.map((r, index) => ({
            id: index + 1,
            check: r.check,
            endpoint: r.endpoint,
            method: r.method,
            status: r.status,
            severity: r.severity || 'Info',
            confirmation_status: r.confirmation_status || 'confirmed',
            message: r.message,
            details: r.details,
            // AI fields: only included when present (undefined fields are
            // stripped by JSON.stringify, keeping non-AI results clean)
            ...(r.ai_confidence !== undefined && {
                ai_confidence: r.ai_confidence,
                ai_reasoning: r.ai_reasoning,
                evidence_cited: r.evidence_cited,
            }),
            // Evidence trail: emitted for every result that has one (hardcoded
            // checks now carry one too — see engine.js _buildHardcodedEvidenceTrail).
            // True N/A results (never sent a request) legitimately have none.
            ...(r.evidence_trail && { evidence_trail: r.evidence_trail }),
        })), null, 2);

        // Ensure dir exists
        const dir = path.dirname(reportPath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }

        fs.writeFileSync(reportPath, jsonContent);
        logger.success(`JSON Report saved to ${reportPath}`);
    } catch (err) {
        logger.error(`Failed to generate JSON report: ${err.message}`);
    }
};

module.exports = { generate };
