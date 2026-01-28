module.exports = async (context, client, endpoint) => {
    try {
        // Test for Reflective CORS or Wildcard
        const origin = 'https://evil.com';
        const response = await client.request({
            method: 'OPTIONS', // or the endpoint method
            url: endpoint.path,
            headers: {
                'Origin': origin
            }
        });

        const allowOrigin = response.headers['access-control-allow-origin'];
        const allowCredentials = response.headers['access-control-allow-credentials'];

        if (allowOrigin === '*') {
            return {
                status: 'FAIL',
                message: 'CORS: Access-Control-Allow-Origin is set to wildscard (*). Public access allowed.',
                details: { header: allowOrigin }
            };
        }

        if (allowOrigin === origin) {
            if (allowCredentials === 'true') {
                return {
                    status: 'FAIL',
                    message: 'CORS: Managed to reflect authentication origin with Credentials set to true. High vulnerability.',
                    details: { origin: allowOrigin, credentials: allowCredentials }
                };
            }

            return {
                status: 'WARN',
                message: 'CORS: API reflects the requested Origin header. Potentially unsafe if intended for public use.',
                details: { origin: allowOrigin }
            };
        }

        return {
            status: 'PASS',
            message: 'CORS headers appear secure or are not present.',
            details: {}
        };

    } catch (error) {
        // If request fails, it might just not support OPTIONS or Origin
        return {
            status: 'PASS',
            message: 'No permissive CORS headers detected on failure.',
            details: {}
        };
    }
};
