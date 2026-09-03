const fs = require('node:fs');
const path = require('node:path');
const axios = require('axios');
const logger = require('../utils/logger');
const { InfrastructureError } = require('../utils/errors');

// A bearer/refresh token is always base64url text (letters, digits, - _ .), never a
// comma, quote, or colon. Those three characters catch the single most common paste
// mistake with --token/--refresh: copying straight out of a JSON auth response
// (e.g. {"token": "...", "refreshToken": "...", "idToken": "..."}) and grabbing one
// field's surrounding punctuation along with it — which, once the shell drops the
// quotes around it, silently glues the next field's value onto the end of this one
// instead of erroring immediately.
const TOKEN_PASTE_ARTIFACT = /["',]|:\s*"/;

const assertLooksLikeToken = (value, flagName) => {
    if (!value || !TOKEN_PASTE_ARTIFACT.test(value)) return;
    throw new Error(
        `--${flagName} value contains a comma/quote/colon, which is never valid inside a bearer or refresh token. ` +
        'This usually means a whole JSON blob (e.g. {"token": "...", "refreshToken": "...", "idToken": "..."}) got ' +
        `pasted in instead of just one field's value — pass only the ${flagName} string itself.`
    );
};

/**
 * Resolve a CLI's auth options (--auth-file, --token, --username/--password) into
 * a role => authValue map, same shape the `scan` command has always produced.
 * Shared so single-target commands (e.g. `headers`) don't have to re-implement it.
 *
 * @param {object} options - Commander options object (authFile, token, username, password).
 * @param {object|null} [collectionAuth] - fallback auth extracted from the input
 *   collection itself (parser.js's extractCollectionAuth), used only when none of
 *   the CLI auth options above were given — a scan against a collection that
 *   already has a working session baked in doesn't need it re-supplied on the
 *   command line.
 * @returns {Promise<object>} authMap — { roleName: { type, token|username|password|... } }
 */
const resolveAuthMap = async (options, collectionAuth = null) => {
    assertLooksLikeToken(options.token, 'token');
    assertLooksLikeToken(options.refresh, 'refresh');

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
        if (options.refresh) {
            Object.assign(authMap.default, {
                refreshToken: options.refresh,
                tokenUrl: options.tokenUrl,
                clientId: options.clientId,
                clientSecret: options.clientSecret,
            });
            logger.info('Refresh token provided — the access token will be renewed automatically if it expires mid-scan.');
        }
    } else if (options.username && options.password) {
        authMap = { default: { type: 'basic', username: options.username, password: options.password } };
        logger.info('Using provided Basic Auth credentials.');
    } else if (collectionAuth) {
        authMap = { default: { ...collectionAuth } };
        logger.info(`No -t/-u/-p/--auth-file given — using the ${collectionAuth.type} auth already defined in the collection.`);
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

module.exports = { resolveAuthMap, authValueToHeaders, assertLooksLikeToken };
