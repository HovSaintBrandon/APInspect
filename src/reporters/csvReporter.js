const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');

const escapeCsv = (str) => {
    if (str === null || str === undefined) return '';
    const stringified = String(str);
    // Escape quotes and wrap in quotes if contains comma, quote or newline
    if (stringified.includes(',') || stringified.includes('"') || stringified.includes('\n')) {
        return `"${stringified.replace(/"/g, '""')}"`;
    }
    return stringified;
};

const generate = (results, outputPath) => {
    try {
        const reportPath = outputPath || path.join(process.cwd(), 'reports', 'report.csv');

        // Define columns
        const headers = ['Check', 'Endpoint', 'Method', 'Status', 'Message', 'Details'];

        // Create rows
        const rows = results.map(r => {
            return [
                r.check,
                r.endpoint,
                r.method,
                r.status,
                r.message,
                JSON.stringify(r.details) // Flatten details for CSV
            ].map(escapeCsv).join(',');
        });

        // Combine
        const csvContent = [headers.join(','), ...rows].join('\n');

        // Ensure dir exists
        const dir = path.dirname(reportPath);
        if (!fs.existsSync(dir)) {
            fs.mkdirSync(dir, { recursive: true });
        }

        fs.writeFileSync(reportPath, csvContent);
        logger.success(`CSV Report saved to ${reportPath}`);

    } catch (err) {
        logger.error(`Failed to generate CSV report: ${err.message}`);
    }
};

module.exports = { generate };
