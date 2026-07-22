const fs = require('node:fs');
const path = require('node:path');
const logger = require('../utils/logger');
const openapiAdapter = require('../adapters/rest/openapiAdapter');
const graphqlAdapter = require('../adapters/graphql/graphqlAdapter');
const grpcAdapter = require('../adapters/grpc/grpcAdapter');

// Postman requests carry their payload in `request.body`, shaped differently per mode.
// Pull out something JSON-fuzzable so injection/DAST checks can mutate it, same as they
// already do for OpenAPI requestBody examples and internal-JSON `body`/`payload` fields.
const extractPostmanBody = (requestBody) => {
    if (!requestBody?.mode) return null;

    if (requestBody.mode === 'raw') {
        try {
            return JSON.parse(requestBody.raw);
        } catch {
            return requestBody.raw;
        }
    }

    if (requestBody.mode === 'urlencoded' || requestBody.mode === 'formdata') {
        const list = requestBody[requestBody.mode] || [];
        const obj = {};
        list.forEach(({ key, value, disabled }) => {
            if (!disabled && key) obj[key] = value;
        });
        return obj;
    }

    if (requestBody.mode === 'graphql' && requestBody.graphql) {
        return requestBody.graphql;
    }

    return null;
};

// Simple validation schema
const validateConfig = (config) => {
    const errors = [];
    if (!config.base_url) errors.push('Missing base_url');
    if (!config.endpoints || !Array.isArray(config.endpoints)) errors.push('Missing or invalid endpoints array');
    return errors;
};

// Recursive function to extract endpoints from Postman items
const extractPostmanEndpoints = (items, variables = []) => {
    let endpoints = [];

    items.forEach(item => {
        if (item.item) {
            // It's a folder, recurse
            endpoints = endpoints.concat(extractPostmanEndpoints(item.item, variables));
        } else if (item.request) {
            // It's a request
            const method = item.request.method;
            let url = '';

            // Postman URL can be string or object
            if (typeof item.request.url === 'string') {
                url = item.request.url;
            } else if (item.request.url && item.request.url.raw) {
                url = item.request.url.raw;
            }

            // Simple variable substitution for {{baseUrl}} and others if simple
            const baseUrlVar = variables.find(v => v.key === 'baseUrl');

            // If the URL contains variables, try to strip them if they are part of the base path
            // We essentially want the part AFTER the base URL

            let finalPath = url;

            if (baseUrlVar && finalPath.includes('{{baseUrl}}')) {
                // If we have the variable value, we could replace it, but we want the relative path
                // So we just strip {{baseUrl}}
                finalPath = finalPath.replace('{{baseUrl}}', '');
            } else if (finalPath.includes('{{baseUrl}}')) {
                finalPath = finalPath.replace('{{baseUrl}}', '');
            }

            // Also strip explicit host if it matches derived base_url (handled by logic below mostly)

            // Strip query parameters for now (or keep them? The scanner treats endpoint as path)
            // If we keep query params, it might be good for fuzzing, but for "discovery" 
            // check we usually want base path. 
            // Let's keep them for strictness if they are part of the definition.

            endpoints.push({
                path: finalPath.startsWith('/') ? finalPath : '/' + finalPath,
                methods: [method],
                originalName: item.name,
                body: extractPostmanBody(item.request.body)
            });
        }
    });

    return endpoints;
};

const normalizeEndpoints = (endpoints) => endpoints.map(ep => ({
    ...ep,
    path: ep.path.startsWith('/') ? ep.path : `/${ep.path}`,
    methods: ep.methods.map(m => m.toUpperCase()),
}));

// Ambiguous inputs (Postman collections, OpenAPI/Swagger specs, raw internal JSON) could
// describe a REST API or a single GraphQL endpoint fronted by REST-shaped tooling — the file
// extension alone doesn't tell us. Unambiguous inputs (.graphql/.gql, .proto, a live GraphQL
// URL) already carry their own protocol and skip this prompt entirely.
const resolveAmbiguousStyle = async (cliStyle) => {
    if (cliStyle) return cliStyle;

    const readline = require('readline');
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const answer = await new Promise(resolve => {
        logger.warn('API architecture style not specified.');
        rl.question('? Select API style — rest / graphql / grpc [rest]: ', ans => {
            rl.close();
            resolve(ans.trim().toLowerCase());
        });
    });

    if (answer === 'graphql' || answer === 'grpc') return answer;
    return 'rest';
};

const parse = async (filePath, cliBaseUrl = null, cliStyle = null) => {
    try {
        // A live GraphQL endpoint URL — discovered via introspection, no local spec file involved.
        if (/^https?:\/\//i.test(filePath)) {
            logger.info('Detected GraphQL endpoint URL — discovering via introspection.');
            const discovered = await graphqlAdapter.discover(filePath, cliBaseUrl);
            return {
                base_url: discovered.base_url,
                protocol: discovered.protocol,
                endpoints: normalizeEndpoints(discovered.endpoints),
            };
        }

        const absolutePath = path.resolve(filePath);
        if (!fs.existsSync(absolutePath)) {
            throw new Error(`File not found: ${filePath}`);
        }

        const ext = path.extname(absolutePath).toLowerCase();

        // GraphQL SDL file
        if (ext === '.graphql' || ext === '.gql') {
            logger.info('Detected GraphQL SDL file.');
            const discovered = await graphqlAdapter.discover(absolutePath, cliBaseUrl);
            return {
                base_url: discovered.base_url,
                protocol: discovered.protocol,
                endpoints: normalizeEndpoints(discovered.endpoints),
            };
        }

        // gRPC .proto file
        if (ext === '.proto') {
            logger.info('Detected gRPC .proto file.');
            const discovered = await grpcAdapter.discover(absolutePath, cliBaseUrl);
            return {
                base_url: discovered.base_url,
                protocol: discovered.protocol,
                endpoints: normalizeEndpoints(discovered.endpoints),
                meta: discovered.meta,
            };
        }

        const fileContent = fs.readFileSync(absolutePath, 'utf-8');
        let config = {};

        let rawData;
        if (ext === '.yaml' || ext === '.yml') {
            const yaml = require('js-yaml');
            try {
                rawData = yaml.load(fileContent);
            } catch (e) {
                throw new Error(`Invalid YAML file: ${e.message}`);
            }
        } else {
            try {
                rawData = JSON.parse(fileContent);
            } catch (e) {
                throw new Error('Invalid JSON file.');
            }
        }

        // Detect OpenAPI / Swagger spec (3.x `openapi` or 2.0 `swagger` top-level key)
        if (openapiAdapter.isOpenApiDoc(rawData)) {
            logger.info('Detected OpenAPI/Swagger specification.');
            const style = await resolveAmbiguousStyle(cliStyle);
            const discovered = await openapiAdapter.discover(absolutePath, cliBaseUrl);
            return {
                base_url: discovered.base_url,
                protocol: style,
                endpoints: normalizeEndpoints(discovered.endpoints).map(ep => ({ ...ep, protocol: style })),
            };
        }

        // Detect Postman Collection
        if (rawData.info && rawData.info._postman_id) {
            logger.info('Detected Postman Collection.');
            const style = await resolveAmbiguousStyle(cliStyle);

            const variables = rawData.variable || [];
            const baseUrlVar = variables.find(v => v.key === 'baseUrl');

            // Try to determine base URL
            // 1. From CLI flag
            // 2. From variable
            // 3. Prompt user interactively
            if (cliBaseUrl) {
                config.base_url = cliBaseUrl;
            } else if (baseUrlVar) {
                config.base_url = baseUrlVar.value;
            } else {
                const readline = require('readline');
                const askBaseUrl = () => {
                    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
                    return new Promise(resolve => {
                        logger.warn('No {{baseUrl}} variable found in collection.');
                        rl.question('? Enter the base URL for the scan (e.g., http://localhost:3000): ', ans => {
                            rl.close();
                            resolve(ans.trim());
                        });
                    });
                };
                
                const answer = await askBaseUrl();
                config.base_url = answer || 'http://localhost';
                logger.info(`Using base URL: ${config.base_url}`);
            }

            // Clean trailing slash
            if (config.base_url.endsWith('/')) {
                config.base_url = config.base_url.slice(0, -1);
            }

            config.endpoints = extractPostmanEndpoints(rawData.item, variables);
            config.protocol = style;
            logger.info(`Extracted ${config.endpoints.length} endpoints from Postman collection.`);

        } else {
            // Assume Standard Internal JSON Format
            config = rawData;
            if (!config.protocol) config.protocol = await resolveAmbiguousStyle(cliStyle);
        }

        // Validate
        const validationErrors = validateConfig(config);
        if (validationErrors.length > 0) {
            throw new Error(`Invalid configuration:\n- ${validationErrors.join('\n- ')}`);
        }

        // Normalize endpoints
        config.endpoints = config.endpoints.map(ep => ({
            ...ep,
            path: ep.path.startsWith('/') ? ep.path : `/${ep.path}`,
            methods: ep.methods ? ep.methods.map(m => m.toUpperCase()) : ['GET'],
            protocol: ep.protocol || config.protocol,
            // Internal JSON specs may name the sample request payload `body` or `payload`.
            body: ep.body || ep.payload || null,
        }));

        return config;

    } catch (error) {
        logger.error(`Failed to parse input file: ${error.message}`);
        process.exit(1);
    }
};

const parseRaw = async (filePath) => {
    const absolutePath = path.resolve(filePath);
    if (!fs.existsSync(absolutePath)) {
        throw new Error(`File not found: ${filePath}`);
    }
    const fileContent = fs.readFileSync(absolutePath, 'utf-8');
    return JSON.parse(fileContent);
}

module.exports = { parse, parseRaw };
