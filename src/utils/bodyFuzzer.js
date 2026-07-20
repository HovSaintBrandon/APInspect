// Utilities for exercising a request body's fields during injection/DAST checks.
// A check hands in the endpoint's known-good payload (harvested from a Postman
// collection, an OpenAPI requestBody example, or an internal JSON spec's `body`/
// `payload` field) and gets back one mutated copy per string field per fuzz payload,
// so POST/PUT/PATCH bodies get the same treatment query params already receive.

const isPlainObject = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

// Walk `body`, replacing each string leaf (one at a time) with `payload`.
// Returns [{ body: <mutated clone>, field: 'a.b[0].c' }, ...].
const generateFuzzedBodies = (body, payload) => {
    if (body === null || body === undefined) return [];

    const mutations = [];

    const walk = (node, path) => {
        if (typeof node === 'string') {
            mutations.push({ field: path || '(root)', originalType: 'string' });
            return;
        }
        if (Array.isArray(node)) {
            node.forEach((item, i) => walk(item, `${path}[${i}]`));
            return;
        }
        if (isPlainObject(node)) {
            for (const key of Object.keys(node)) {
                walk(node[key], path ? `${path}.${key}` : key);
            }
        }
    };

    walk(body, '');

    const setAtPath = (clone, path, value) => {
        const segments = path
            .replace(/\[(\d+)\]/g, '.$1')
            .split('.')
            .filter(Boolean);

        let cursor = clone;
        for (let i = 0; i < segments.length - 1; i++) {
            cursor = cursor[segments[i]];
        }
        cursor[segments[segments.length - 1]] = value;
        return clone;
    };

    return mutations.map(({ field }) => {
        const clone = JSON.parse(JSON.stringify(body));
        if (field === '(root)') {
            return { body: payload, field };
        }
        setAtPath(clone, field, payload);
        return { body: clone, field };
    });
};

// Best-effort sample body from an OpenAPI/Swagger requestBody object.
// Prefers an explicit example/examples entry; falls back to generating
// placeholder values from the JSON schema shape.
const extractExampleBody = (requestBody) => {
    if (!requestBody) return null;

    const jsonContent = requestBody.content && (
        requestBody.content['application/json'] ||
        requestBody.content['application/*+json']
    );
    if (!jsonContent) return null;

    if (jsonContent.example !== undefined) return jsonContent.example;
    if (jsonContent.examples) {
        const first = Object.values(jsonContent.examples)[0];
        if (first && first.value !== undefined) return first.value;
    }
    if (jsonContent.schema) return generateSampleFromSchema(jsonContent.schema);

    return null;
};

const generateSampleFromSchema = (schema, depth = 0) => {
    if (!schema || depth > 6) return null;
    if (schema.example !== undefined) return schema.example;
    if (schema.default !== undefined) return schema.default;

    switch (schema.type) {
        case 'object': {
            const obj = {};
            const props = schema.properties || {};
            for (const key of Object.keys(props)) {
                obj[key] = generateSampleFromSchema(props[key], depth + 1);
            }
            return obj;
        }
        case 'array':
            return [generateSampleFromSchema(schema.items, depth + 1)];
        case 'string':
            return schema.enum ? schema.enum[0] : 'sample_string';
        case 'integer':
        case 'number':
            return 1;
        case 'boolean':
            return true;
        default:
            return schema.properties ? generateSampleFromSchema({ ...schema, type: 'object' }, depth) : null;
    }
};

module.exports = { generateFuzzedBodies, extractExampleBody };
