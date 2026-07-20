const path = require('path');
const SwaggerParser = require('@apidevtools/swagger-parser');
const logger = require('../../utils/logger');
const { extractExampleBody } = require('../../utils/bodyFuzzer');

// Detect whether a parsed JSON/YAML object is an OpenAPI (3.x) or Swagger (2.0) document.
const isOpenApiDoc = (rawData) => {
    return !!(rawData && (rawData.openapi || rawData.swagger));
};

// Derive a base URL from the spec's `servers` (OAS3) or `host`/`basePath`/`schemes` (Swagger 2.0).
const deriveBaseUrl = (api, cliBaseUrl) => {
    if (cliBaseUrl) return cliBaseUrl.replace(/\/$/, '');

    if (Array.isArray(api.servers) && api.servers.length > 0) {
        return api.servers[0].url.replace(/\/$/, '');
    }

    if (api.host) {
        const scheme = (api.schemes && api.schemes[0]) || 'https';
        const basePath = api.basePath || '';
        return `${scheme}://${api.host}${basePath}`.replace(/\/$/, '');
    }

    return null;
};

const HTTP_METHODS = ['get', 'post', 'put', 'patch', 'delete', 'options', 'head', 'trace'];

// Walk the dereferenced spec's `paths` object into APInspect's Endpoint[] shape.
const extractOpenApiEndpoints = (api) => {
    const endpoints = [];

    for (const [rawPath, pathItem] of Object.entries(api.paths || {})) {
        for (const method of HTTP_METHODS) {
            const operation = pathItem[method];
            if (!operation) continue;

            endpoints.push({
                path: rawPath.startsWith('/') ? rawPath : `/${rawPath}`,
                methods: [method.toUpperCase()],
                originalName: operation.operationId || operation.summary || `${method.toUpperCase()} ${rawPath}`,
                protocol: 'rest',
                // Sample payload derived from the spec's requestBody — fed to injection/DAST
                // checks so POST/PUT/PATCH endpoints get fuzzed the same way GET query params do.
                body: extractExampleBody(operation.requestBody),
                schema: {
                    parameters: operation.parameters || pathItem.parameters || [],
                    requestBody: operation.requestBody || null,
                    responses: operation.responses || {},
                },
            });
        }
    }

    return endpoints;
};

/**
 * Discover endpoints from an OpenAPI/Swagger spec file.
 * @param {string} filePath - Path to the .json/.yaml/.yml spec file.
 * @param {string|null} cliBaseUrl - Optional base URL override from the CLI.
 * @returns {Promise<{base_url: string, endpoints: Array, protocol: string}>}
 */
const discover = async (filePath, cliBaseUrl = null) => {
    const absolutePath = path.resolve(filePath);

    // dereference() resolves all $ref pointers so downstream code never has to.
    const api = await SwaggerParser.dereference(absolutePath);

    const base_url = deriveBaseUrl(api, cliBaseUrl);
    if (!base_url) {
        throw new Error(
            'Could not determine base URL from the OpenAPI spec (no `servers` or `host` field). ' +
            'Pass one explicitly with -b/--base-url.'
        );
    }

    const endpoints = extractOpenApiEndpoints(api);
    logger.info(`Extracted ${endpoints.length} endpoints from OpenAPI/Swagger spec.`);

    return { base_url, endpoints, protocol: 'rest' };
};

module.exports = { discover, isOpenApiDoc };
