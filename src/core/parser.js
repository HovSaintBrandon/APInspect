const fs = require('fs');
const path = require('path');
const logger = require('../utils/logger');

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
                originalName: item.name
            });
        }
    });

    return endpoints;
};

const parse = async (filePath) => {
    try {
        const absolutePath = path.resolve(filePath);
        if (!fs.existsSync(absolutePath)) {
            throw new Error(`File not found: ${filePath}`);
        }

        const fileContent = fs.readFileSync(absolutePath, 'utf-8');
        let config = {};

        let rawData;
        try {
            rawData = JSON.parse(fileContent);
        } catch (e) {
            throw new Error('Invalid JSON file.');
        }

        // Detect Postman Collection
        if (rawData.info && rawData.info._postman_id) {
            logger.info('Detected Postman Collection.');

            const variables = rawData.variable || [];
            const baseUrlVar = variables.find(v => v.key === 'baseUrl');

            // Try to determine base URL
            // 1. From variable
            // 2. Default to localhost
            if (baseUrlVar) {
                config.base_url = baseUrlVar.value;
            } else {
                config.base_url = 'http://localhost';
                logger.warn('No {{baseUrl}} variable found. Defaulting to http://localhost');
            }

            // Clean trailing slash
            if (config.base_url.endsWith('/')) {
                config.base_url = config.base_url.slice(0, -1);
            }

            config.endpoints = extractPostmanEndpoints(rawData.item, variables);
            logger.info(`Extracted ${config.endpoints.length} endpoints from Postman collection.`);

        } else {
            // Assume Standard Internal JSON Format
            config = rawData;
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
            methods: ep.methods ? ep.methods.map(m => m.toUpperCase()) : ['GET']
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
