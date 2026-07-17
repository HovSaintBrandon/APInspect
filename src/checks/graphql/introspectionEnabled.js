const { getIntrospectionQuery } = require('graphql');

// Verifies the GraphQL introspection query is disabled (or restricted) — leaving it
// enabled in production hands an attacker the full schema, including hidden mutations.
module.exports = async (context, client, endpoint) => {
    // Introspection is a schema-wide property, not per-operation — only probe it once per scan.
    if (context.getVariable('__graphqlIntrospectionChecked')) {
        return null;
    }
    context.setVariable('__graphqlIntrospectionChecked', true);

    try {
        const response = await client.request({
            method: 'POST',
            url: endpoint.path,
            headers: { 'Content-Type': 'application/json' },
            data: { query: getIntrospectionQuery() },
        });

        const schemaReturned = !!(response.data && response.data.data && response.data.data.__schema);

        if (schemaReturned) {
            return {
                status: 'FAIL',
                message: 'GraphQL introspection is enabled — full schema (types, fields, mutations) is publicly discoverable.',
                details: { status: response.status },
            };
        }

        return {
            status: 'PASS',
            message: 'GraphQL introspection is disabled or restricted.',
            details: { status: response.status },
        };
    } catch (error) {
        return { status: 'MANUAL', message: `Could not run introspection check: ${error.message}` };
    }
};
