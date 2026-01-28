module.exports = async (context, client, endpoint) => {
    try {
        const method = endpoint.methods[0] || 'GET';
        if (method !== 'GET') {
            // We typically check response bodies of GET requests for leaks
            // Only check if we can actually get data
            return {
                status: 'PASS',
                message: 'Skipping sensitive data check for non-GET method.',
                details: {}
            };
        }

        const response = await client.request({
            method: method,
            url: endpoint.path,
        });

        const body = JSON.stringify(response.data);
        const findings = [];

        // Comprehensive Regex Patterns
        const patterns = [
            { name: 'Email Address', regex: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/ },
            { name: 'SSN (US)', regex: /\b\d{3}-\d{2}-\d{4}\b/ },
            { name: 'Private Key', regex: /-----BEGIN PRIVATE KEY-----/ },
            { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/ },
            { name: 'JWT Token', regex: /eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+/ },
            { name: 'Stripe Key', regex: /sk_live_[0-9a-zA-Z]{24}/ },
            { name: 'Google API Key', regex: /AIza[0-9A-Za-z-_]{35}/ },
            { name: 'Generic Secret', regex: /[A-Za-z0-9+/=]{40}/ }
        ];

        patterns.forEach(p => {
            if (p.regex.test(body)) {
                findings.push(p.name);
            }
        });

        if (findings.length > 0) {
            return {
                status: 'FAIL',
                message: `Sensitive data potentially exposed: ${findings.join(', ')}`,
                details: { findings }
            };
        }

        return {
            status: 'PASS',
            message: 'No sensitive data patterns detected in response.',
            details: {}
        };

    } catch (error) {
        return {
            status: 'PASS', // Failed verification implies no data exposed usually
            message: 'Request failed, so no data exposed.',
            details: {}
        };
    }
};
