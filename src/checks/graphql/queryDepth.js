// Abuses the recursive __Type.fields.type.ofType.fields... chain (present on every GraphQL
// schema via introspection) to build a deeply nested query without needing app-specific schema
// knowledge. Servers without query-depth limiting will happily execute this — a DoS vector.
const DEPTH = 12;

const buildDeepQuery = (depth) => {
    let inner = '__typename';
    for (let i = 0; i < depth; i++) {
        inner = `fields { type { ofType { ${inner} } } }`;
    }
    return `query DeepQueryDepthProbe { __schema { types { ${inner} } } }`;
};

module.exports = async (context, client, endpoint) => {
    if (context.getVariable('__graphqlQueryDepthChecked')) {
        return null;
    }
    context.setVariable('__graphqlQueryDepthChecked', true);

    try {
        const response = await client.request({
            method: 'POST',
            url: endpoint.path,
            headers: { 'Content-Type': 'application/json' },
            data: { query: buildDeepQuery(DEPTH) },
        });

        const hasErrors = Array.isArray(response.data && response.data.errors) && response.data.errors.length > 0;
        const rejectedForDepth = hasErrors && response.data.errors.some(e =>
            /depth|complexity|too deep|nested/i.test(e.message || '')
        );

        if (rejectedForDepth) {
            return {
                status: 'PASS',
                message: `Server rejected a ${DEPTH}-level-deep query — depth/complexity limiting appears enforced.`,
                details: { status: response.status },
            };
        }

        if (response.status >= 200 && response.status < 300 && !hasErrors) {
            return {
                status: 'FAIL',
                message: `Server executed a ${DEPTH}-level-deep query with no rejection — no query depth/complexity limit detected (potential DoS vector).`,
                details: { status: response.status },
            };
        }

        return {
            status: 'MANUAL',
            message: `Deep query returned an ambiguous result (status ${response.status}) — verify depth limiting manually.`,
            details: { status: response.status, errors: response.data && response.data.errors },
        };
    } catch (error) {
        return { status: 'MANUAL', message: `Could not run query depth check: ${error.message}` };
    }
};
