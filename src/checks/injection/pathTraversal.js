module.exports = async (context, client, endpoint) => {
    // Path traversal usually targets file retrieval endpoints.
    // We will fuzz URL parameters and the path itself with dot-dot-slash patterns.

    // Only safe to test on GET usually
    if (endpoint.methods[0] !== 'GET') {
        return { status: 'PASS', message: 'Skipping path traversal for non-GET method.', details: {} };
    }

    const payloads = [
        '../../../../etc/passwd',
        '..%2F..%2F..%2F..%2Fetc%2Fpasswd',
        '../../windows/win.ini',
        '..%2F..%2Fwindows%2Fwin.ini'
    ];

    const triggers = ['root:x:0:0', '[extensions]', 'fonts']; // Indicators of success

    for (const payload of payloads) {
        try {
            // Append payload to triggers
            const separator = endpoint.path.includes('?') ? '&' : '?';
            const fuzzedUrl = `${endpoint.path}${separator}file=${payload}`; // naive assumption of 'file' param

            // Also try replacing last segment? Too destructive?
            // Let's stick to appending for now or replacing endpoint parameters if we parsed them.

            // Blind fuzzing:
            const response = await client.request({
                method: 'GET',
                url: fuzzedUrl,
            });

            const body = JSON.stringify(response.data);
            for (const trigger of triggers) {
                if (body.includes(trigger)) {
                    return {
                        status: 'FAIL',
                        message: `Path Traversal vulnerability detected with payload: ${payload}`,
                        details: { match: trigger }
                    };
                }
            }

        } catch (error) {
            // Errors are expected
        }
    }

    return {
        status: 'PASS',
        message: 'No path traversal leakage detected.',
        details: {}
    };
};
