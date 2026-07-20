const { generateFuzzedBodies } = require('../../utils/bodyFuzzer');

const payloads = [
    '../../../../etc/passwd',
    '..%2F..%2F..%2F..%2Fetc%2Fpasswd',
    '../../windows/win.ini',
    '..%2F..%2Fwindows%2Fwin.ini'
];

const triggers = ['root:x:0:0', '[extensions]', 'fonts']; // Indicators of success

const findTrigger = (responseData) => {
    const body = JSON.stringify(responseData);
    return triggers.find(trigger => body.includes(trigger));
};

const fuzzViaQueryParams = async (client, endpoint) => {
    for (const payload of payloads) {
        try {
            // Append payload to triggers
            const separator = endpoint.path.includes('?') ? '&' : '?';
            const fuzzedUrl = `${endpoint.path}${separator}file=${payload}`; // naive assumption of 'file' param

            const response = await client.request({ method: 'GET', url: fuzzedUrl });

            const trigger = findTrigger(response.data);
            if (trigger) {
                return {
                    status: 'FAIL',
                    message: `Path Traversal vulnerability detected with payload: ${payload}`,
                    details: { match: trigger }
                };
            }
        } catch (error) {
            // Errors are expected
        }
    }
    return null;
};

// Mutate the endpoint's known-good JSON body one field at a time with traversal
// payloads — catches file-path parameters that only exist in the request body
// (e.g. a POST { "filename": "report.pdf" } download endpoint).
const fuzzViaBody = async (client, endpoint) => {
    const method = endpoint.methods[0];

    for (const payload of payloads) {
        const mutations = generateFuzzedBodies(endpoint.body, payload);

        for (const { body, field } of mutations) {
            try {
                const response = await client.request({ method, url: endpoint.path, data: body });

                const trigger = findTrigger(response.data);
                if (trigger) {
                    return {
                        status: 'FAIL',
                        message: `Path Traversal vulnerability detected in body field '${field}' with payload: ${payload}`,
                        details: { match: trigger, field, payload }
                    };
                }
            } catch (error) {
                // Errors are expected
            }
        }
    }
    return null;
};

module.exports = async function pathTraversalCheck(context, client, endpoint) {
    const method = endpoint.methods[0];

    if (method === 'GET') {
        const result = await fuzzViaQueryParams(client, endpoint);
        if (result) return result;

        return {
            status: 'PASS',
            message: 'No path traversal leakage detected.',
            details: {}
        };
    }

    if (['POST', 'PUT', 'PATCH'].includes(method) && endpoint.body) {
        const result = await fuzzViaBody(client, endpoint);
        if (result) return result;

        return {
            status: 'PASS',
            message: 'No path traversal leakage detected in request body fields.',
            details: {}
        };
    }

    return {
        status: 'PASS',
        message: 'Skipping path traversal fuzzing — non-GET method with no known request payload to fuzz.',
        details: {}
    };
};
