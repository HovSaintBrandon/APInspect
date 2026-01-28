const logger = require('../../utils/logger');

module.exports = async (context, client, endpoint) => {
    // Only test rate limiting on specific endpoints or if safe?
    // Testing EVERY endpoint might cause a DoS or get IP banned.
    // For a scanner, we usually send a burst of ~10-20 requests.

    // Skip GETs usually unless we want to test DoS, but POSTs are critical for Brute Force (Auth)
    const method = endpoint.methods[0] || 'GET';
    const requestCount = 10;
    const promises = [];

    // Simple strategy: Send N requests in parallel
    for (let i = 0; i < requestCount; i++) {
        promises.push(client.request({
            method: method,
            url: endpoint.path,
        }).catch(e => e.response || { status: 500 })); // Catch errors to allow analyzing status
    }

    try {
        const responses = await Promise.all(promises);

        // Analyze logic
        // If we see 429 (Too Many Requests) -> PASS (Rate limit is enforced)
        // If all 200/401 -> POTENTIAL FAIL (No rate limit detected for small burst)

        const tooManyRequests = responses.filter(r => r.status === 429);
        if (tooManyRequests.length > 0) {
            return {
                status: 'PASS',
                message: `Rate limiting detected. Received ${tooManyRequests.length} 429 responses out of ${requestCount}.`,
                details: { burstSize: requestCount, blocked: tooManyRequests.length }
            };
        }

        // If we didn't hit 429, it doesn't mean it's definitly vulnerable (limit might be 100)
        // But for "Brute Force" on login (if this is login), 10 should ideally trigger something or slow down.

        return {
            status: 'WARN',
            message: `No rate limiting triggered after ${requestCount} parallel requests. Verify limits manually.`,
            details: { burstSize: requestCount, statuses: responses.map(r => r.status) }
        };

    } catch (error) {
        return {
            status: 'MANUAL',
            message: 'Rate limit check failed due to network error.',
            details: {}
        };
    }
};
