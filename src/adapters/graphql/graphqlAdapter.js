const fs = require('fs');
const path = require('path');
const axios = require('axios');
const { buildSchema, getIntrospectionQuery, buildClientSchema, isObjectType } = require('graphql');
const logger = require('../../utils/logger');

const isGraphqlFile = (filePath) => {
    const ext = path.extname(filePath).toLowerCase();
    return ext === '.graphql' || ext === '.gql';
};

// Convert every field on Query/Mutation into a synthetic Endpoint. GraphQL has a single
// transport endpoint, so `path` is constant — the operation identity lives in `originalName`/`schema`.
const buildEndpointsFromSchema = (schema, graphqlPath) => {
    const endpoints = [];

    const rootTypes = [
        { type: schema.getQueryType(), operationType: 'query' },
        { type: schema.getMutationType(), operationType: 'mutation' },
    ];

    for (const { type, operationType } of rootTypes) {
        if (!type || !isObjectType(type)) continue;

        const fields = type.getFields();
        for (const [fieldName, field] of Object.entries(fields)) {
            endpoints.push({
                path: graphqlPath,
                methods: ['POST'],
                protocol: 'graphql',
                originalName: `${operationType === 'query' ? 'Query' : 'Mutation'}.${fieldName}`,
                schema: {
                    operationType,
                    fieldName,
                    args: field.args.map(a => ({ name: a.name, type: a.type.toString() })),
                    returnType: field.type.toString(),
                },
            });
        }
    }

    return endpoints;
};

// Fetch and build a GraphQLSchema from a live server via introspection.
const introspect = async (url) => {
    const response = await axios.post(url, {
        query: getIntrospectionQuery(),
    }, { headers: { 'Content-Type': 'application/json' } });

    if (!response.data || !response.data.data) {
        throw new Error(
            `Introspection query to ${url} did not return a schema. ` +
            `Introspection may be disabled — supply an SDL file instead.`
        );
    }

    return buildClientSchema(response.data.data);
};

/**
 * Discover GraphQL operations either from a local SDL file (.graphql/.gql) or
 * via live introspection against a URL.
 * @param {string} target - Path to an SDL file, or a GraphQL endpoint URL.
 * @param {string|null} cliBaseUrl - Optional base URL override (used with SDL files).
 * @returns {Promise<{base_url: string, endpoints: Array, protocol: string}>}
 */
const discover = async (target, cliBaseUrl = null) => {
    let schema;
    let base_url;
    let graphqlPath = '/graphql';

    if (isGraphqlFile(target)) {
        const sdl = fs.readFileSync(path.resolve(target), 'utf-8');
        schema = buildSchema(sdl);

        if (!cliBaseUrl) {
            throw new Error(
                'Base URL is required when discovering from a local SDL file. Pass -b/--base-url.'
            );
        }
        base_url = cliBaseUrl.replace(/\/$/, '');
    } else {
        // Treat target as a live GraphQL endpoint URL
        const url = new URL(target);
        graphqlPath = url.pathname || '/graphql';
        base_url = `${url.protocol}//${url.host}`;

        logger.info(`Introspecting GraphQL schema at ${target}...`);
        schema = await introspect(target);
    }

    const endpoints = buildEndpointsFromSchema(schema, graphqlPath);
    logger.info(`Extracted ${endpoints.length} GraphQL operations (queries + mutations).`);

    return { base_url, endpoints, protocol: 'graphql' };
};

module.exports = { discover, isGraphqlFile };
