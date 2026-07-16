/**
 * src/reporters/checklistReporter.js
 *
 * Pivots the flat results array back into the FALCON checklist spreadsheet
 * shape: Subject | Test Name | Verdict | Comments, grouped by category.
 *
 * Output is a CSV that is a drop-in replacement for the manual FALCON review
 * spreadsheet — the same columns, the same grouping, same verdict vocabulary
 * (PASS, FAILED, N/A, TO BE CONFIRMED).
 *
 * Usage:
 *   const checklistReporter = require('./checklistReporter');
 *   checklistReporter.generate(results, './reports/falcon-review.csv');
 */

const fs   = require('fs');
const path = require('path');
const logger = require('../utils/logger');
const checklist = require('../config/checklist.json');

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
const escapeCsv = (str) => {
    if (str === null || str === undefined) return '';
    const s = String(str);
    if (s.includes(',') || s.includes('"') || s.includes('\n')) {
        return `"${s.replace(/"/g, '""')}"`;
    }
    return s;
};

const rowToCsv = (...fields) => fields.map(escapeCsv).join(',');

// Translate between internal status codes and FALCON vocabulary
const toFalconVerdict = (status) => {
    const map = {
        'PASS':             'PASS',
        'FAIL':             'FAILED',
        'FAILED':           'FAILED',
        'N/A':              'N/A',
        'MANUAL':           'TO BE CONFIRMED',
        'TO BE CONFIRMED':  'TO BE CONFIRMED',
    };
    return map[status] || 'TO BE CONFIRMED';
};

// Build a human-readable comment from the result fields
const buildComment = (result) => {
    const parts = [];

    if (result.message) parts.push(result.message);

    if (result.ai_confidence !== undefined) {
        parts.push(`AI confidence: ${(result.ai_confidence * 100).toFixed(0)}%`);
    }

    if (result.ai_reasoning && result.ai_reasoning !== result.message) {
        parts.push(`Reasoning: ${result.ai_reasoning}`);
    }

    if (result.evidence_cited && result.evidence_cited.length > 0) {
        parts.push(`Evidence: ${result.evidence_cited.join(', ')}`);
    }

    return parts.join(' | ');
};

// ---------------------------------------------------------------------------
// Main generate function
// ---------------------------------------------------------------------------
const generate = (results, outputPath) => {
    try {
        const reportPath = outputPath || path.join(process.cwd(), 'reports', 'falcon-review.csv');

        // Index results by checklist item ID (extracted from check name like "checklist/AUTH-01")
        // Support both checklist-mode IDs ("checklist/AUTH-01") and legacy names
        const resultsByItemId = new Map();

        for (const result of results) {
            // Extract item ID from "checklist/AUTH-01" → "AUTH-01"
            const match = result.check && result.check.match(/^checklist\/(.+)$/);
            if (match) {
                const id  = match[1];
                const key = `${id}::${result.endpoint}`;

                // If we have multiple endpoints, keep the worst verdict
                if (!resultsByItemId.has(key)) {
                    resultsByItemId.set(key, result);
                } else {
                    const existing = resultsByItemId.get(key);
                    const priority = { 'FAILED': 4, 'FAIL': 4, 'TO BE CONFIRMED': 3, 'MANUAL': 3, 'PASS': 2, 'N/A': 1 };
                    if ((priority[result.status] || 0) > (priority[existing.status] || 0)) {
                        resultsByItemId.set(key, result);
                    }
                }
            }
        }

        // Get unique endpoints tested
        const endpointsTested = [...new Set(results.map(r => r.endpoint))];

        // Build CSV rows — one block per checklist item, one row per endpoint
        const headers = ['Subject', 'Test Name', 'Endpoint', 'Method', 'Verdict', 'Comments'];
        const rows = [headers.join(',')];

        // Group checklist items by category
        const categories = [...new Set(checklist.map(i => i.category))];

        for (const category of categories) {
            const items = checklist.filter(i => i.category === category);

            for (const item of items) {
                // Find all results for this item across all endpoints
                const itemResults = [];
                for (const endpoint of endpointsTested) {
                    const key = `${item.id}::${endpoint}`;
                    if (resultsByItemId.has(key)) {
                        itemResults.push(resultsByItemId.get(key));
                    }
                }

                if (itemResults.length === 0) {
                    // Item was never tested (e.g., checklist has extra items not covered by this scan)
                    rows.push(rowToCsv(
                        category,
                        `[${item.id}] ${item.test_name}`,
                        '—',
                        '—',
                        'N/A',
                        'Not tested in this scan run.'
                    ));
                } else {
                    for (const result of itemResults) {
                        rows.push(rowToCsv(
                            category,
                            `[${item.id}] ${item.test_name}`,
                            result.endpoint,
                            result.method || '—',
                            toFalconVerdict(result.status),
                            buildComment(result)
                        ));
                    }
                }
            }
        }

        // Add a summary block at the top
        const totalItems  = rows.length - 1; // Subtract header
        const passCount   = results.filter(r => r.status === 'PASS').length;
        const failCount   = results.filter(r => r.status === 'FAIL' || r.status === 'FAILED').length;
        const tbcCount    = results.filter(r => r.status === 'MANUAL' || r.status === 'TO BE CONFIRMED').length;
        const naCount     = results.filter(r => r.status === 'N/A').length;

        const summaryRows = [
            `# APInspect FALCON Review Report`,
            `# Generated: ${new Date().toISOString()}`,
            `# Total results: ${results.length} | PASS: ${passCount} | FAILED: ${failCount} | TO BE CONFIRMED: ${tbcCount} | N/A: ${naCount}`,
            '',
            ...rows,
        ];

        const csvContent = summaryRows.join('\n');

        const dir = path.dirname(reportPath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

        fs.writeFileSync(reportPath, csvContent);
        logger.success(`FALCON Checklist Report saved to ${reportPath}`);
        logger.info(`  PASS: ${passCount} | FAILED: ${failCount} | TO BE CONFIRMED: ${tbcCount} | N/A: ${naCount}`);

    } catch (err) {
        logger.error(`Failed to generate FALCON checklist report: ${err.message}`);
    }
};

module.exports = { generate };
