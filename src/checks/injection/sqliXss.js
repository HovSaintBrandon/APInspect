module.exports = async (context, client, endpoint) => {
    // Only test GET parameters for now to avoid side effects
    if (endpoint.methods[0] !== 'GET') {
        return { status: 'PASS', message: 'Skipping injection fuzzing for non-GET method (Safety).', details: {} };
    }

    // Identify query parameters? 
    // If endpoint has no params, we can append some.
    // If endpoint definition (from Postman) has params, we use them.

    // Simplified fuzzing: Append bad chars to URL and check for 500 or specific errors
    const payloads = [
        "'",
        "\"",
        "<script>alert(1)</script>",
        " OR 1=1"
    ];

    for (const payload of payloads) {
        try {
            // Append payload to path. 
            // If path has query ?, append &fuzz=payload. If not, ?fuzz=payload
            // Or try to inject into existing params if we knew them.
            // Let's just blindly append a fuzz parameter for generic testing
            const separator = endpoint.path.includes('?') ? '&' : '?';
            const fuzzedUrl = `${endpoint.path}${separator}fuzz_test=${encodeURIComponent(payload)}`;

            await client.request({
                method: 'GET',
                url: fuzzedUrl,
            });

            // If 200 OK, it didn't crash. 
            // We'd need to check response body for reflection (XSS) or SQL errors.

            // This needs response analysis. 
            // For MVP: if it returns 500, we flag it.

        } catch (error) {
            if (error.response && error.response.status >= 500) {
                return {
                    status: 'FAIL',
                    message: `Injection payload '${payload}' triggered Server Error (${error.response.status}). Potential vulnerability.`,
                    details: { payload, status: error.response.status }
                };
            }
        }
    }

    return {
        status: 'PASS',
        message: 'Basic injection fuzzing did not trigger server errors.',
        details: {}
    };
};
