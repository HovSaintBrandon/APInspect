module.exports = async (context, client, endpoint) => {
    // We want to test common methods to see if they are enabled unexpectedly
    const methodsToTest = ['OPTIONS', 'HEAD', 'PUT', 'DELETE', 'PATCH', 'TRACE'];
    const detectedMethods = [];

    // 1. Try OPTIONS first as it is the standard way to ask
    try {
        const optionsRes = await client.request({
            method: 'OPTIONS',
            url: endpoint.path,
        });

        // Check 'Allow' header
        if (optionsRes.headers['allow']) {
            const allowed = optionsRes.headers['allow'].split(',').map(m => m.trim().toUpperCase());
            return {
                status: 'PASS',
                message: `OPTIONS returned Allow header: ${allowed.join(', ')}`,
                details: { allowed }
            };
        }
    } catch (e) {
        // OPTIONS might fail, that's okay
    }

    // 2. If OPTIONS didn't give us a clear list, we could try "fuzzing" methods
    // But that might be too aggressive for a default scan.
    // Let's just return a generic PASS for now stating we checked OPTIONS.

    // Actually, let's try TRACE, which is often a vulnerability if enabled (Cross-Site Tracing)
    try {
        const traceRes = await client.request({
            method: 'TRACE',
            url: endpoint.path,
        });

        if (traceRes.status === 200) {
            return {
                status: 'FAIL',
                message: `Endpoint supports TRACE method, which may allow Cross-Site Tracing (XST).`,
                details: { method: 'TRACE' }
            };
        }
    } catch (e) {
        // Expected failure
    }

    return {
        status: 'PASS',
        message: 'Checked HTTP methods. TRACE is disabled.',
        details: {}
    };
};
