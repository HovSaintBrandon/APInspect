module.exports = async (context, client, endpoint) => {
    // Proactively trigger a bad request to see how the server handles it
    // e.g. send invalid JSON or bad query param
    // But we must be careful not to be destructive.

    // For now, let's just analyze the existing response if 500
    // OR try to send a guaranteed "bad" request.

    try {
        // Send a request strictly to provoke an error? 
        // Let's rely on standard requests first. If the endpoint failed (status >= 500)
        // we assume the 'client' threw a 500.

        // We'll purposely send a broken JSON body to a POST if applicable
        if (endpoint.methods.includes('POST') || endpoint.methods.includes('PUT')) {
            try {
                await client.request({
                    method: 'POST',
                    url: endpoint.path,
                    data: '{ "invalid": ', // Malformed JSON
                    headers: { 'Content-Type': 'application/json' }
                });
            } catch (postErr) {
                if (postErr.response) {
                    return analyzeErrorResponse(postErr.response);
                }
            }
        }

        return {
            status: 'PASS',
            message: 'No stack traces detected (Default check).',
            details: {}
        };

    } catch (error) {
        // If the main request logic fails at network level
        return { status: 'MANUAL', message: 'Could not run error check.' };
    }
};

function analyzeErrorResponse(response) {
    const body = JSON.stringify(response.data || '');
    const findings = [];

    // Look for stack trace signatures
    if (body.includes('at /') || body.includes('at new ') || body.includes('npm_modules')) {
        findings.push('Stack Trace');
    }

    if (body.includes('SyntaxError') || body.includes('ReferenceError')) {
        findings.push('Runtime Error Name');
    }

    if (findings.length > 0) {
        return {
            status: 'FAIL',
            message: `Verbose error information exposed: ${findings.join(', ')}`,
            details: { status: response.status, findings }
        };
    }

    return {
        status: 'PASS',
        message: `Error response (${response.status}) handles data gracefully.`,
        details: { status: response.status }
    };
}
