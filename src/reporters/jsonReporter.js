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
                failed: results.filter(r => r.status === 'FAIL').length,
                manual: results.filter(r => r.status === 'MANUAL').length,
            },
            results: results
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
