const fs = require('node:fs');
const path = require('node:path');
const axios = require('axios');
const logger = require('../utils/logger');
const { InfrastructureError } = require('../utils/errors');

/**
 * Resolve a CLI's auth options (--auth-file, --token, --username/--password) into
 * a role => authValue map, same shape the `scan` command has always produced.
 * Shared so single-target commands (e.g. `headers`) don't have to re-implement it.
 *
 * @param {object} options - Commander options object (authFile, token, username, password).
 * @returns {Promise<object>} authMap — { roleName: { type, token|username|password|... } }
 */
const resolveAuthMap = async (options) => {
    let authMap = {};

    if (options.authFile) {
        const absPath = path.resolve(options.authFile);
        if (!fs.existsSync(absPath)) {
            throw new Error(`Auth file not found: ${options.authFile}`);
        }
        const authConfig = require(absPath);

        if (authConfig.login_endpoint && authConfig.roles) {
            logger.info(`Fetching dynamic tokens from ${authConfig.login_endpoint}...`);

            for (const role of authConfig.roles) {
                try {
                    const res = await axios({
                        method: authConfig.method || 'POST',
                        url: authConfig.login_endpoint,
                        data: role.payload,
                        headers: { 'Content-Type': 'application/json' }
                    });

                    const pathParts = (authConfig.token_path || 'token').split('.');
                    let token = res.data;
                    for (const part of pathParts) {
                        if (token) token = token[part];
                    }

                    if (token) {
                        authMap[role.name] = { type: 'bearer', token };
                        logger.info(`✅ Successfully fetched token for role: ${role.name}`);
                    } else {
                        throw new InfrastructureError(
                            `Token path '${authConfig.token_path}' not found in response for role '${role.name}'. ` +
                            `Cannot proceed — scan without authentication would manufacture false confidence.`
                        );
                    }
                } catch (err) {
                    if (err.name === 'InfrastructureError') throw err;
                    throw new InfrastructureError(`Failed to fetch token for role '${role.name}': ${err.message}`);
                }
            }
        } else if (Array.isArray(authConfig.roles)) {
            logger.info(`Processing ${authConfig.roles.length} roles from auth file...`);

            for (const role of authConfig.roles) {
                if (role.auth_type === 'basic') {
                    const encoded = Buffer.from(
                        `${role.credentials.username}:${role.credentials.password}`
                    ).toString('base64');
                    authMap[role.name] = {
                        type: 'basic',
                        header: `Basic ${encoded}`,
                        username: role.credentials.username,
                        password: role.credentials.password
                    };
                    logger.info(`🔑 Loaded Basic Auth for role: ${role.name} (user: ${role.credentials.username})`);

                } else if (role.auth_type === 'bearer') {
                    try {
                        const res = await axios({
                            method: role.method || 'POST',
                            url: role.login_endpoint,
                            data: role.payload,
                            headers: { 'Content-Type': 'application/json' }
                        });

                        const pathParts = (role.token_path || 'token').split('.');
                        let token = res.data;
                        for (const part of pathParts) {
                            if (token) token = token[part];
                        }

                        if (token) {
                            authMap[role.name] = { type: 'bearer', token };
                            logger.info(`✅ Fetched Bearer token for role: ${role.name}`);
                        } else {
                            throw new InfrastructureError(
                                `token_path '${role.token_path}' not found in response for role '${role.name}'. ` +
                                `Cannot proceed — scan without authentication would manufacture false confidence.`
                            );
                        }
                    } catch (err) {
                        if (err.name === 'InfrastructureError') throw err;
                        throw new InfrastructureError(`Failed to fetch token for role '${role.name}': ${err.message}`);
                    }
                } else {
                    logger.warn(`⚠ Unknown auth_type '${role.auth_type}' for role ${role.name} — skipping.`);
                }
            }
        } else {
            authMap = authConfig;
            logger.info(`Loaded auth map with ${Object.keys(authMap).length} roles.`);
        }
    } else if (options.token) {
        authMap = { default: { type: 'bearer', token: options.token } };
        logger.info('Using provided bearer token.');
    } else if (options.username && options.password) {
        authMap = { default: { type: 'basic', username: options.username, password: options.password } };
        logger.info('Using provided Basic Auth credentials.');
    } else {
        authMap = { unauthenticated: null };
    }

    return authMap;
};

/**
 * Convert a resolved authValue ({ type: 'bearer'|'basic', ... }) into a headers object.
 */
const authValueToHeaders = (authValue) => {
    if (!authValue) return {};
    if (authValue.type === 'bearer') {
        return { Authorization: `Bearer ${authValue.token}` };
    }
    if (authValue.type === 'basic') {
        const encoded = Buffer.from(`${authValue.username}:${authValue.password}`).toString('base64');
        return { Authorization: authValue.header || `Basic ${encoded}` };
    }
    return {};
};

module.exports = { resolveAuthMap, authValueToHeaders };
