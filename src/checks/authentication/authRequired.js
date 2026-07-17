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
            headers: {},
        };

        // The shared client instance carries auth headers as axios defaults, which a
        // per-request {} does not override. Axios only drops a default header when the
        // request explicitly sets that key to null, so clear it that way instead.
        if (context.auth.type === 'bearer' || context.auth.type === 'basic') {
            reqConfig.headers['Authorization'] = null;
        }
        if (context.auth.type === 'header') {
            reqConfig.headers[context.auth.key] = null;
        }

        // validateStatus is configured to never throw (see httpClient.js), so the
        // no-auth response resolves normally here regardless of status code.
        const response = await client.request(reqConfig);
        const status = response.status;

        if (status === 401 || status === 403) {
            return {
                status: 'PASS',
                message: `Endpoint ${method} ${endpoint.path} correctly blocked unauthenticated access (Status: ${status}).`,
                details: { status }
            };
        }

        if (status >= 200 && status < 300) {
            return {
                status: 'FAIL',
                message: `Endpoint ${method} ${endpoint.path} accessed successfully without authentication.`,
                details: { access: 'unauthenticated', status }
            };
        }

        return {
            status: 'MANUAL',
            message: `Endpoint returned ${status} without auth. Needs manual verification.`,
            details: { status }
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
