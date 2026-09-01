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

// Postman collections in particular routinely list the same (method, path) more than
// once — the same request duplicated across a "happy path" folder and a "negative tests"
// folder, for example. Each duplicate re-spends a full applicability + probe + classify
// pass per checklist item for zero additional coverage, so collapse to one entry per
// (method, path) right after parsing, before the engine ever sees the endpoint list.
const dedupeEndpoints = (endpoints) => {
    const seen = new Map();
    let dropped = 0;
    for (const ep of endpoints) {
        const method = (ep.methods?.[0] || 'GET').toUpperCase();
        const key = `${method} ${ep.path}`;
        if (seen.has(key)) {
            dropped++;
        } else {
            seen.set(key, ep);
        }
    }
    if (dropped > 0) {
        logger.info(`Deduplicated ${dropped} duplicate endpoint(s) (same method + path listed more than once).`);
    }
    return Array.from(seen.values());
};

// Counts leaf requests under a Postman item list, recursing through nested folders.
const countPostmanRequests = (items) => {
    let count = 0;
    for (const item of items) {
        if (item.item) count += countPostmanRequests(item.item);
        else if (item.request) count += 1;
    }
    return count;
};

// Groups a Postman collection's top-level items into selectable buckets: one per direct
// subfolder, plus a synthetic bucket for any requests sitting directly at the root
// alongside those folders. Returns [] when the collection is flat (no folders at all),
// so callers can skip the selection step entirely for the common case.
const getPostmanFolderGroups = (items) => {
    if (!items.some(item => item.item)) return [];

    const groups = [];
    const ungrouped = [];
    for (const item of items) {
        if (item.item) {
            groups.push({ name: item.name, items: item.item, count: countPostmanRequests(item.item) });
        } else if (item.request) {
            ungrouped.push(item);
        }
    }
    if (ungrouped.length > 0) {
        groups.push({ name: '(ungrouped requests)', items: ungrouped, count: ungrouped.length });
    }
    return groups;
};

// Postman collections are commonly organized into folders (by resource, by role, by
// workflow...). When folders are present, ask the user which ones to actually scan
// instead of always running the whole collection.
const promptFolderSelection = async (groups) => {
    const readline = require('readline');
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

    logger.info('This collection is organized into folders:');
    groups.forEach((g, i) => {
        logger.info(`  ${i + 1}) ${g.name} (${g.count} request${g.count === 1 ? '' : 's'})`);
    });

    const answer = await new Promise(resolve => {
        rl.question('? Select folder(s) to scan — comma-separated numbers, or press Enter to scan all: ', ans => {
            rl.close();
            resolve(ans.trim());
        });
    });

    if (!answer) return groups;

    const indices = answer.split(',').map(s => Number.parseInt(s.trim(), 10) - 1);
    const selected = indices
        .filter(i => Number.isInteger(i) && i >= 0 && i < groups.length)
        .map(i => groups[i]);

    if (selected.length === 0) {
        logger.warn('No valid folder selected — scanning the entire collection.');
        return groups;
    }
    return selected;
};

// Non-interactive counterpart to promptFolderSelection, driven by --folder — matches
// folder names case-insensitively so CI runs never have to hit the interactive prompt.
const filterFolderGroupsByName = (groups, names) => {
    const wanted = names.map(n => n.toLowerCase());
    const missing = wanted.filter(n => !groups.some(g => g.name.toLowerCase() === n));
    if (missing.length > 0) {
        const available = groups.map(g => g.name).join(', ');
        throw new Error(`Folder(s) not found in collection: ${missing.join(', ')}. Available: ${available}`);
    }
    return groups.filter(g => wanted.includes(g.name.toLowerCase()));
};

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

const parse = async (filePath, cliBaseUrl = null, cliStyle = null, cliFolders = null) => {
    try {
        // A live GraphQL endpoint URL — discovered via introspection, no local spec file involved.
        if (/^https?:\/\//i.test(filePath)) {
            logger.info('Detected GraphQL endpoint URL — discovering via introspection.');
            const discovered = await graphqlAdapter.discover(filePath, cliBaseUrl);
            return {
                base_url: discovered.base_url,
                protocol: discovered.protocol,
                endpoints: dedupeEndpoints(normalizeEndpoints(discovered.endpoints)),
                scanName: new URL(filePath).hostname,
            };
        }

        const absolutePath = path.resolve(filePath);
        if (!fs.existsSync(absolutePath)) {
            throw new Error(`File not found: ${filePath}`);
        }

        const ext = path.extname(absolutePath).toLowerCase();
        // Report file name for this input — stable across repeat scans of the
        // same file so its reports land in the same reports/<scanName>/ dir.
        const scanNameFromFile = path.basename(absolutePath, ext);

        // GraphQL SDL file
        if (ext === '.graphql' || ext === '.gql') {
            logger.info('Detected GraphQL SDL file.');
            const discovered = await graphqlAdapter.discover(absolutePath, cliBaseUrl);
            return {
                base_url: discovered.base_url,
                protocol: discovered.protocol,
                endpoints: dedupeEndpoints(normalizeEndpoints(discovered.endpoints)),
                scanName: scanNameFromFile,
            };
        }

        // gRPC .proto file
        if (ext === '.proto') {
            logger.info('Detected gRPC .proto file.');
            const discovered = await grpcAdapter.discover(absolutePath, cliBaseUrl);
            return {
                base_url: discovered.base_url,
                protocol: discovered.protocol,
                endpoints: dedupeEndpoints(normalizeEndpoints(discovered.endpoints)),
                meta: discovered.meta,
                scanName: scanNameFromFile,
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
                endpoints: dedupeEndpoints(normalizeEndpoints(discovered.endpoints).map(ep => ({ ...ep, protocol: style }))),
                scanName: scanNameFromFile,
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

            // Report file name for this scan — defaults to the whole collection, but
            // narrows to the selected folder(s) below so a folder-scoped scan gets its
            // own stable reports/<scanName>/ dir distinct from a full-collection scan.
            config.scanName = rawData.info.name || scanNameFromFile;

            // Scope to specific folder(s) if the collection has any.
            let items = rawData.item;
            const folderGroups = getPostmanFolderGroups(rawData.item);
            if (folderGroups.length > 0) {
                const selectedGroups = (cliFolders && cliFolders.length > 0)
                    ? filterFolderGroupsByName(folderGroups, cliFolders)
                    : await promptFolderSelection(folderGroups);

                if (selectedGroups.length < folderGroups.length) {
                    items = selectedGroups.flatMap(g => g.items);
                    logger.info(`Scanning selected folder(s): ${selectedGroups.map(g => g.name).join(', ')}`);
                    config.scanName = selectedGroups.map(g => g.name).join('+');
                }
            }

            config.endpoints = extractPostmanEndpoints(items, variables);
            config.protocol = style;
            logger.info(`Extracted ${config.endpoints.length} endpoints from Postman collection.`);

        } else {
            // Assume Standard Internal JSON Format
            config = rawData;
            if (!config.protocol) config.protocol = await resolveAmbiguousStyle(cliStyle);
            config.scanName = config.name || scanNameFromFile;
        }

        // Validate
        const validationErrors = validateConfig(config);
        if (validationErrors.length > 0) {
            throw new Error(`Invalid configuration:\n- ${validationErrors.join('\n- ')}`);
        }

        // Normalize endpoints
        config.endpoints = dedupeEndpoints(config.endpoints.map(ep => ({
            ...ep,
            path: ep.path.startsWith('/') ? ep.path : `/${ep.path}`,
            methods: ep.methods ? ep.methods.map(m => m.toUpperCase()) : ['GET'],
            protocol: ep.protocol || config.protocol,
            // Internal JSON specs may name the sample request payload `body` or `payload`.
            body: ep.body || ep.payload || null,
        })));

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

module.exports = { parse, parseRaw, getPostmanFolderGroups };
