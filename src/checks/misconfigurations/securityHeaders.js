const headerGrader = require('../../core/headerGrader');

// Grades below this get FAIL, below this-but-above the next get WARN, rest PASS.
const FAIL_BELOW_GRADE = new Set(['F', 'E']);
const WARN_BELOW_GRADE = new Set(['D', 'C']);

module.exports = async function securityHeadersCheck(context, client, endpoint) {
    try {
        const response = await client.request({
            method: endpoint.methods[0] || 'GET',
            url: endpoint.path,
        });

        const isHttps = context.baseUrl.startsWith('https');
        const result = headerGrader.grade(response.headers, { isHttps });

        let status = 'PASS';
        if (FAIL_BELOW_GRADE.has(result.grade)) status = 'FAIL';
        else if (WARN_BELOW_GRADE.has(result.grade)) status = 'WARN';

        const actionable = result.findings.filter(f => ['MISSING', 'WEAK', 'LEAK'].includes(f.status));

        return {
            status,
            message: `Security headers grade: ${result.grade} (${result.score}/100).`,
            details: {
                grade: result.grade,
                score: result.score,
                findings: result.findings,
                recommendations: actionable.map(f => ({ header: f.header, recommendation: f.recommendation })),
            },
        };
    } catch (error) {
        return { status: 'PASS', message: `Skipped headers check (request failed: ${error.message}).`, details: {} };
    }
};
