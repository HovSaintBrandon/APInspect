const { generateFuzzedBodies } = require('../../utils/bodyFuzzer');

const payloads = [
    "'",
    "\"",
    "<script>alert(1)</script>",
    " OR 1=1"
];

// Common SQL engine error signatures reflected back in a response body.
const SQL_ERROR_SIGNATURES = [
    /sql syntax.*mysql/i,
    /warning.*mysqli/i,
    /unclosed quotation mark/i,
    /quoted string not properly terminated/i,
    /pg_query\(\)/i,
    /sqlite3?\.(operationalerror|error)/i,
    /ORA-\d{5}/,
    /System\.Data\.SqlClient/,
];

const fuzzViaQueryParams = async (client, endpoint) => {
    for (const payload of payloads) {
        try {
            const separator = endpoint.path.includes('?') ? '&' : '?';
            const fuzzedUrl = `${endpoint.path}${separator}fuzz_test=${encodeURIComponent(payload)}`;

            await client.request({ method: 'GET', url: fuzzedUrl });
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
    return null;
};

// Mutate the endpoint's known-good JSON body one field at a time and check for
// reflected SQL errors or 500s — the body-carrying counterpart to query-param fuzzing.
const fuzzViaBody = async (client, endpoint) => {
    const method = endpoint.methods[0];

    for (const payload of payloads) {
        const mutations = generateFuzzedBodies(endpoint.body, payload);

        for (const { body, field } of mutations) {
            try {
                const response = await client.request({
                    method,
                    url: endpoint.path,
                    data: body,
                });

                const responseText = typeof response.data === 'string'
                    ? response.data
                    : JSON.stringify(response.data);

                const matchedSignature = SQL_ERROR_SIGNATURES.find(sig => sig.test(responseText));
                if (matchedSignature) {
                    return {
                        status: 'FAIL',
                        message: `Injection payload '${payload}' in body field '${field}' triggered a SQL error signature in the response. Potential vulnerability.`,
                        details: { payload, field, matchedSignature: matchedSignature.toString() }
                    };
                }
            } catch (error) {
                if (error.response && error.response.status >= 500) {
                    return {
                        status: 'FAIL',
                        message: `Injection payload '${payload}' in body field '${field}' triggered Server Error (${error.response.status}). Potential vulnerability.`,
                        details: { payload, field, status: error.response.status }
                    };
                }
            }
        }
    }
    return null;
};

module.exports = async function sqliXssCheck(context, client, endpoint) {
    const method = endpoint.methods[0];

    if (method === 'GET') {
        const result = await fuzzViaQueryParams(client, endpoint);
        if (result) return result;

        return {
            status: 'PASS',
            message: 'Basic injection fuzzing did not trigger server errors.',
            details: {}
        };
    }

    if (['POST', 'PUT', 'PATCH'].includes(method) && endpoint.body) {
        const result = await fuzzViaBody(client, endpoint);
        if (result) return result;

        return {
            status: 'PASS',
            message: 'Basic body-field injection fuzzing did not trigger server errors or SQL error signatures.',
            details: {}
        };
    }

    return {
        status: 'PASS',
        message: 'Skipping injection fuzzing — non-GET method with no known request payload to fuzz.',
        details: {}
    };
};
