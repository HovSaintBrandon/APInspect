const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');

const generate = (results, outputPath) => {
    try {
        const reportPath = outputPath || path.join(process.cwd(), 'reports', 'report.json');
        const jsonContent = JSON.stringify({
            timestamp: new Date().toISOString(),
            summary: {
                total: results.length,
                passed: results.filter(r => r.status === 'PASS').length,
                failed: results.filter(r => r.status === 'FAIL' || r.status === 'FAILED').length,
                tbc: results.filter(r => r.status === 'TO BE CONFIRMED').length,
                manual: results.filter(r => r.status === 'MANUAL').length,
                na: results.filter(r => r.status === 'N/A').length,
            },
            results: results.map(r => ({
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
                // Evidence trail: only emitted for actionable findings (FAIL, WARN, TBC)
                // so PASS/N/A results stay compact
                ...((r.evidence_trail && ['FAIL', 'FAILED', 'WARN', 'TO BE CONFIRMED', 'MANUAL'].includes(r.status)) && {
                    evidence_trail: r.evidence_trail,
                }),
            }))
        }, null, 2);

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
