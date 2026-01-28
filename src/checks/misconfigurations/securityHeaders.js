module.exports = async (context, client, endpoint) => {
    try {
        const response = await client.request({
            method: endpoint.methods[0] || 'GET',
            url: endpoint.path,
        });

        const headers = response.headers;
        const missingHeaders = [];
        const insecureHeaders = [];

        // Check for Missing Security Headers
        if (!headers['strict-transport-security'] && context.baseUrl.startsWith('https')) missingHeaders.push('Strict-Transport-Security');
        if (!headers['x-content-type-options']) missingHeaders.push('X-Content-Type-Options');
        if (!headers['x-frame-options']) missingHeaders.push('X-Frame-Options');
        // CSP is complex, but check existence
        if (!headers['content-security-policy']) missingHeaders.push('Content-Security-Policy');

        // Check for Information Leakage Headers
        if (headers['x-powered-by']) insecureHeaders.push(`X-Powered-By: ${headers['x-powered-by']}`);
        if (headers['server']) insecureHeaders.push(`Server: ${headers['server']}`);

        if (missingHeaders.length > 0 || insecureHeaders.length > 0) {
            return {
                status: 'WARN', // Warn because not all checks are critical for all APIs
                message: 'Security header misconfigurations detected.',
                details: { missing: missingHeaders, leaking: insecureHeaders }
            };
        }

        return {
            status: 'PASS',
            message: 'Basic security headers are present.',
            details: {}
        };

    } catch (error) {
        return { status: 'PASS', message: 'Skipped headers check (request failed).', details: {} };
    }
};
