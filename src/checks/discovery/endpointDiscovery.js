// A 404 means no route matched — that's the one status code that must NOT be
// reported as "reachable". Everything else (2xx, other 4xx, 5xx) means a real
// route handler received the request, which is what "reachable" actually claims.
const describeReachability = (method, path, status) => {
    if (status === 404) {
        return {
            status: 'ROUTE_NOT_FOUND',
            message: `No route matched for ${method} ${path} (404) — the endpoint is not reachable at this path. If this is unexpected, check for an unresolved path template (e.g. {{base_url}}, {{id}}) before trusting any other check result for this endpoint.`,
            details: { status }
        };
    }
    return {
        status: 'PASS',
        message: `Endpoint ${method} ${path} is reachable (Status: ${status}).`,
        details: { status }
    };
};

module.exports = async (context, client, endpoint) => {
    try {
        // Attempt to access the endpoint with default method (GET usually)
        // We expect *some* response (2xx, 4xx, 5xx) to confirm it exists/is reachable.
        const method = endpoint.methods[0] || 'GET';
        const response = await client.request({
            method: method,
            url: endpoint.path,
        });

        return describeReachability(method, endpoint.path, response.status);

    } catch (error) {
        if (error.response) {
            // It's reachable but returned an error status, which is fine for discovery
            return describeReachability(endpoint.methods[0], endpoint.path, error.response.status);
        }

        // Network error, truly unreachable
        return {
            status: 'FAIL',
            message: `Endpoint ${endpoint.methods[0]} ${endpoint.path} is not reachable: ${error.message}`,
            details: { error: error.message }
        };
    }
};
