// Checks if the endpoint demands authentication
module.exports = async (context, client, endpoint) => {
    if (!context.auth) {
        return {
            status: 'MANUAL',
            message: 'No auth configuration provided. Skipping auth checks.'
        };
    }

    try {
        const method = endpoint.methods[0] || 'GET';

        // 1. Send request WITHOUT auth headers
        // Create a new client instance/request config that specifically excludes auth
        // We can't reuse value from context.getAuthHeaders() easily if we used the shared client 
        // BUT our shared client *already* has auth headers.
        // So we need to override headers to remove auth.

        const reqConfig = {
            method: method,
            url: endpoint.path,
            headers: {}, // Reset headers
        };

        // Explicitly remove standard auth headers if they exist in global config
        // (This is a simplified approach; specific header keys depend on auth type)
        if (context.auth.type === 'bearer' || context.auth.type === 'basic') {
            reqConfig.headers['Authorization'] = '';
            // Note: Axios might still send empty header. Ideally we strictly omit it.
            delete reqConfig.headers['Authorization'];
        }
        // For specific headers
        if (context.auth.type === 'header') {
            reqConfig.headers[context.auth.key] = '';
        }

        // Perform request
        await client.request(reqConfig);

        // If we reach here, the request succeeded (2xx) WITHOUT auth.
        // That means it looks like a FAIL (Publicly accessible).
        // BUT some endpoints are meant to be public. 
        // For now we flag it as FAIL/WARN.

        return {
            status: 'FAIL',
            message: `Endpoint ${method} ${endpoint.path} accessed successfully without authentication.`,
            details: { access: 'unauthenticated' }
        };

    } catch (error) {
        if (error.response) {
            const status = error.response.status;
            if (status === 401 || status === 403) {
                return {
                    status: 'PASS',
                    message: `Endpoint ${endpoint.methods[0]} ${endpoint.path} correctly blocked unauthenticated access (Status: ${status}).`,
                    details: { status }
                };
            } else {
                // It failed for another reason (404, 400, 500), so we can't be sure about auth
                return {
                    status: 'MANUAL',
                    message: `Endpoint returned ${status} without auth. Needs manual verification.`,
                    details: { status }
                };
            }
        }

        return {
            status: 'MANUAL',
            message: `Network error during auth check: ${error.message}`,
            details: { error: error.message }
        };
    }
};
