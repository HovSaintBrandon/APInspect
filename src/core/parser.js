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

// Resolves a Postman variable reference like "{{access_token}}" against the
// collection's own `variable` array. No Postman *environment* file is loaded by
// this parser, so a reference to an environment-only variable can't be resolved
// here — callers must treat a still-templated result as unusable, not a literal.
const resolvePostmanVar = (value, variables) => {
    if (typeof value !== 'string') return value;
    const match = value.match(/^\{\{([^}]+)\}\}$/);
    if (!match) return value;
    const found = variables.find(v => v.key === match[1]);
    return found ? found.value : value;
};

const _stillTemplated = (value) => typeof value === 'string' && /^\{\{.*\}\}$/.test(value);
const _usable = (value) => Boolean(value) && !_stillTemplated(value);

// Per-Postman-auth-type resolvers: `fields` is the auth block's own key/value list
// (already run through resolvePostmanVar), each returning the Context#auth shape
// or null if this type's required field(s) are missing/unresolved. oauth2 and
// other types aren't listed — no reliable static credential to pull out of them.
const _COLLECTION_AUTH_RESOLVERS = {
    bearer: (fields) => (_usable(fields.token) ? { type: 'bearer', token: fields.token } : null),
    basic: (fields) => (_usable(fields.username) && _usable(fields.password)
        ? { type: 'basic', username: fields.username, password: fields.password }
        : null),
    // query-param API keys aren't a header this tool can inject generically, so only `in: header` qualifies.
    apikey: (fields) => ((!fields.in || fields.in === 'header') && _usable(fields.key) && _usable(fields.value)
        ? { type: 'header', key: fields.key, value: fields.value }
        : null),
};

// Pulls the collection-level `auth` block (Postman v2.1 schema) into the same
// { type, token|username|password|key,value } shape Context#getAuthHeaders()
// already understands. This is a *fallback* auth source, used only when the
// operator didn't pass -t/-u/-p/--auth-file (see authResolver.resolveAuthMap) —
// for a collection captured with a working session already baked in (common for
// pentest working collections), a scan can then exercise authenticated-only
// checks (BOLA, mass assignment, ...) without re-supplying the same credential
// on the command line. Returns null if the collection has no auth block, its type
// isn't one of the above, or its value(s) only resolve to an unfilled {{env_var}}.
const extractCollectionAuth = (rawData, variables) => {
    const auth = rawData.auth;
    const resolver = auth && _COLLECTION_AUTH_RESOLVERS[auth.type];
    if (!resolver || !Array.isArray(auth[auth.type])) return null;

    const fields = {};
    for (const f of auth[auth.type]) {
        if (f && f.key) fields[f.key] = resolvePostmanVar(f.value, variables);
    }
    return resolver(fields);
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

// Flattens every folder in a Postman collection into one selectable list — at the root
// AND at any nesting depth, so a subfolder of a subfolder is just as selectable as a
// top-level folder. Each entry's `count`/`items` cover every descendant (its own nested
// subfolders included), so selecting a folder scans it whole; `path` is the slash-joined
// chain of parent folder names down to this one (e.g. "Orders/Admin"), needed to tell
// apart two folders that share a name under different parents and to address a subfolder
// directly via --folder. Returns [] when the collection is flat (no folders at all, at
// any depth), so callers can skip the selection step entirely for the common case.
const getPostmanFolderGroups = (items, parentPath = []) => {
    if (parentPath.length === 0 && !items.some(item => item.item)) return [];

    const groups = [];
    const ungrouped = [];
    for (const item of items) {
        if (item.item) {
            const currentPath = [...parentPath, item.name];
            groups.push({
                name: item.name,
                path: currentPath.join('/'),
                depth: currentPath.length,
                items: item.item,
                count: countPostmanRequests(item.item),
            });
            groups.push(...getPostmanFolderGroups(item.item, currentPath));
        } else if (item.request) {
            ungrouped.push(item);
        }
    }
    // The synthetic "ungrouped" bucket only applies at the root — same convention as
    // before nesting was supported. A stray request left inside a subfolder next to its
    // own subfolders is just included whenever that subfolder is scanned as a whole.
    if (ungrouped.length > 0 && parentPath.length === 0) {
        groups.push({ name: '(ungrouped requests)', path: '(ungrouped requests)', depth: 1, items: ungrouped, count: ungrouped.length });
    }
    return groups;
};

// Postman collections are commonly organized into folders (by resource, by role, by
// workflow...), sometimes nested several levels deep. When folders are present, ask the
// user which ones to actually scan instead of always running the whole collection —
// picking a folder with subfolders scans it whole; picking one of its subfolders scans
// just that slice. Indentation mirrors nesting depth so the hierarchy reads at a glance.
const promptFolderSelection = async (groups) => {
    const readline = require('readline');
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });

    logger.info('This collection is organized into folders:');
    groups.forEach((g, i) => {
        const indent = '  '.repeat(g.depth - 1);
        logger.info(`  ${i + 1}) ${indent}${g.name} (${g.count} request${g.count === 1 ? '' : 's'})`);
    });

    const answer = await new Promise(resolve => {
        rl.question(
            '? Select folder(s) to scan — comma-separated numbers (pick a parent for everything inside it, ' +
            'or an indented subfolder for just that slice), or press Enter to scan all: ',
            ans => {
                rl.close();
                resolve(ans.trim());
            }
        );
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
// `groups` now spans every nesting depth, so a bare name (e.g. "Admin") matches a folder
// by its own name wherever it sits; a "Parent/Child" path (e.g. "Orders/Admin") matches
// by full path instead, needed when the same folder name shows up under more than one
// parent — matching by name alone in that case is ambiguous and errors out.
const filterFolderGroupsByName = (groups, names) => {
    const selected = [];
    const missing = [];
    const ambiguous = [];

    for (const rawName of names) {
        const wanted = rawName.toLowerCase();
        let matches = groups.filter(g => g.path.toLowerCase() === wanted);
        if (matches.length === 0) {
            matches = groups.filter(g => g.name.toLowerCase() === wanted);
        }

        if (matches.length === 0) missing.push(rawName);
        else if (matches.length > 1) ambiguous.push({ rawName, matches });
        else selected.push(matches[0]);
    }

    if (missing.length > 0) {
        const available = groups.map(g => g.path).join(', ');
        throw new Error(`Folder(s) not found in collection: ${missing.join(', ')}. Available: ${available}`);
    }
    if (ambiguous.length > 0) {
        const detail = ambiguous
            .map(a => `"${a.rawName}" matches ${a.matches.map(m => m.path).join(' and ')} — use the full "Parent/Child" path to disambiguate`)
            .join('; ');
        throw new Error(`Ambiguous folder name(s): ${detail}`);
    }
    return selected;
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

            // Fallback auth source — see extractCollectionAuth. Only used by the CLI
            // when no -t/-u/-p/--auth-file was given (authResolver.resolveAuthMap).
            config.collectionAuth = extractCollectionAuth(rawData, variables);
            if (config.collectionAuth) {
                logger.info(`Collection defines its own ${config.collectionAuth.type} auth — used automatically if no -t/-u/-p/--auth-file is given.`);
            }

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
                    // Full path (not just the leaf name) in both the log and scanName —
                    // two subfolders can share a name under different parents, and the
                    // path is what actually tells a report directory apart.
                    logger.info(`Scanning selected folder(s): ${selectedGroups.map(g => g.path).join(', ')}`);
                    config.scanName = selectedGroups.map(g => g.path).join('+');
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
