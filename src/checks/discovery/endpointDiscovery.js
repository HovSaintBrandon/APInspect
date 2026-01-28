module.exports = async (context, client, endpoint) => {
    try {
        // Attempt to access the endpoint with default method (GET usually)
        // We expect *some* response (2xx, 4xx, 5xx) to confirm it exists/is reachable.
        const method = endpoint.methods[0] || 'GET';
        const response = await client.request({
            method: method,
            url: endpoint.path,
        });

        return {
            status: 'PASS',
            message: `Endpoint ${method} ${endpoint.path} is reachable (Status: ${response.status}).`,
            details: { status: response.status }
        };

    } catch (error) {
        if (error.response) {
            // It's reachable but returned an error status, which is fine for discovery
            return {
                status: 'PASS',
                message: `Endpoint ${endpoint.methods[0]} ${endpoint.path} is reachable (Status: ${error.response.status}).`,
                details: { status: error.response.status }
            };
        }

        // Network error, truly unreachable
        return {
            status: 'FAIL',
            message: `Endpoint ${endpoint.methods[0]} ${endpoint.path} is not reachable: ${error.message}`,
            details: { error: error.message }
        };
    }
};
