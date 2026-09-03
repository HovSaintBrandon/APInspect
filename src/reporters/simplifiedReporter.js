/**
 * src/reporters/simplifiedReporter.js
 *
 * Companion to checklistReporter (the FALCON review spreadsheet): pivots the
 * same checklist results into a flat, client-facing audit matrix — one row
 * per checklist item, every tested endpoint's verdict folded into a single
 * `results` map keyed by endpoint path, e.g. { "/policy/assign": "PASS" }.
 * `comment` is left blank for a reviewer to fill in by hand; the full
 * per-endpoint message/reasoning/evidence already lives in the JSON report.
 *
 * Usage:
 *   const simplifiedReporter = require('./simplifiedReporter');
 *   simplifiedReporter.generate(results, './reports/simplified-report.json', {
 *       project: 'Parental Control Solution',
 *       classification: 'C2 - Safaricom Internal',
 *   });
 */

const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');
const checklist = require('../config/checklist.json');
const { isFail } = require('../core/statuses');

// Same internal-status → FALCON-vocabulary mapping as checklistReporter — kept
// in sync deliberately rather than shared, since the two reporters are allowed
// to diverge independently (this one has no coverage-gap detail to preserve).
const toFalconVerdict = (status) => {
    const map = {
        'PASS':             'PASS',
        'FAIL':             'FAILED',
        'FAILED':           'FAILED',
        'N/A':              'N/A',
        'MANUAL':           'TO BE CONFIRMED',
        'TO BE CONFIRMED':  'TO BE CONFIRMED',
    };
    if (map[status]) return map[status];
    if (isFail(status)) return 'FAILED';
    return 'TO BE CONFIRMED';
};

// DD.MM.YY, matching the engagement report convention.
const formatDate = (date) => {
    const d = date || new Date();
    const dd = String(d.getDate()).padStart(2, '0');
    const mm = String(d.getMonth() + 1).padStart(2, '0');
    const yy = String(d.getFullYear()).slice(-2);
    return `${dd}.${mm}.${yy}`;
};

const VERDICT_PRIORITY = {
    'FAILED': 4, 'FAIL': 4,
    'TO BE CONFIRMED': 3, 'MANUAL': 3,
    'AUTH_BLOCKED': 3, 'ROUTE_NOT_FOUND': 3, 'ENDPOINT_UNHEALTHY': 3, 'UNRESOLVED_PATH': 3,
    'PASS': 2, 'N/A': 1,
};

const generate = (results, outputPath, meta = {}) => {
    try {
        const reportPath = outputPath || path.join(process.cwd(), 'reports', 'simplified-report.json');
        const project = meta.project || '';
        const classification = meta.classification || '';
        const date = formatDate(meta.date);

        // itemId -> Map(endpoint -> worst result seen for that (item, endpoint) pair)
        const itemEndpointResults = new Map();

        for (const result of results) {
            const match = result.check && result.check.match(/^checklist\/(.+)$/);
            if (!match) continue;
            const itemId = match[1];

            if (!itemEndpointResults.has(itemId)) itemEndpointResults.set(itemId, new Map());
            const endpointMap = itemEndpointResults.get(itemId);

            const existing = endpointMap.get(result.endpoint);
            if (!existing || (VERDICT_PRIORITY[result.status] || 0) > (VERDICT_PRIORITY[existing.status] || 0)) {
                endpointMap.set(result.endpoint, result);
            }
        }

        const rows = checklist.map((item, index) => {
            const endpointMap = itemEndpointResults.get(item.id);
            const endpointVerdicts = {};
            if (endpointMap) {
                for (const [endpoint, result] of endpointMap) {
                    endpointVerdicts[endpoint] = toFalconVerdict(result.status);
                }
            }

            return {
                project,
                date,
                classification,
                id: index + 1,
                domain: 'API',
                subject: item.category,
                test: item.test_name,
                results: endpointVerdicts,
                comment: '',
            };
        });

        const jsonContent = JSON.stringify(rows, null, 2);

        const dir = path.dirname(reportPath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

        fs.writeFileSync(reportPath, jsonContent);
        logger.success(`Simplified Report saved to ${reportPath}`);
    } catch (err) {
        logger.error(`Failed to generate simplified report: ${err.message}`);
    }
};

module.exports = { generate };
