/**
 * src/core/configSchema.js
 *
 * Loads and validates apinspect.config.yaml for the declarative scan path.
 * Every field the runner or the gate needs comes from here — the declarative
 * CLI never accepts a flag that changes what gets run (see allowlist.js for
 * the same rule applied specifically to target hosts).
 */
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const yaml = require('js-yaml');

const VALID_FAIL_ON = ['none', 'low', 'medium', 'high', 'critical'];

function validateConfig(config) {
    const errors = [];
    if (!config || typeof config !== 'object') {
        return ['Config must be a YAML object.'];
    }
    if (config.version !== 1) {
        errors.push(`Unsupported config version: ${JSON.stringify(config.version)} (expected 1).`);
    }
    if (!config.target?.base_url) {
        errors.push('target.base_url is required.');
    }
    if (!Array.isArray(config.target?.allowlist) || config.target.allowlist.length === 0) {
        errors.push('target.allowlist must be a non-empty array of hostnames.');
    }
    if (!Array.isArray(config.endpoints) || config.endpoints.length === 0) {
        errors.push('endpoints must be a non-empty array.');
    } else {
        config.endpoints.forEach((ep, i) => {
            if (!ep.path) errors.push(`endpoints[${i}].path is required.`);
            if (!Array.isArray(ep.methods) || ep.methods.length === 0) {
                errors.push(`endpoints[${i}].methods must be a non-empty array.`);
            }
            if (!Array.isArray(ep.checks) || ep.checks.length === 0) {
                errors.push(`endpoints[${i}].checks must be a non-empty array.`);
            }
        });
    }
    const failOn = config.gate?.fail_on;
    if (failOn !== undefined && !VALID_FAIL_ON.includes(failOn)) {
        errors.push(`gate.fail_on must be one of: ${VALID_FAIL_ON.join(', ')} (got ${JSON.stringify(failOn)}).`);
    }
    if (config.auth && config.auth.type === 'keycloak' && !config.auth.token_env) {
        errors.push('auth.token_env is required when auth.type is "keycloak".');
    }
    return errors;
}

/**
 * @param {string} configPath
 * @returns {{config: object, configHash: string}} the validated, defaulted config
 *   and a stable hash of its raw content — the same hash `cache.js` already uses
 *   for checklist.json, so two runs are only comparable when this matches.
 * @throws {Error} if the file is missing, isn't valid YAML, or fails validation
 */
function loadConfig(configPath) {
    const absolutePath = path.resolve(configPath);
    if (!fs.existsSync(absolutePath)) {
        throw new Error(`Config file not found: ${configPath}`);
    }

    const raw = fs.readFileSync(absolutePath, 'utf-8');
    let config;
    try {
        config = yaml.load(raw);
    } catch (e) {
        throw new Error(`Invalid YAML in ${configPath}: ${e.message}`);
    }

    const errors = validateConfig(config);
    if (errors.length > 0) {
        throw new Error(`Invalid ${path.basename(configPath)}:\n- ${errors.join('\n- ')}`);
    }

    // Defaults — every field the runner/gate/artifacts writer reads is
    // guaranteed present after this, so nothing downstream needs `?.` guards
    // for config shape (only for genuinely optional runtime data).
    config.gate = { fail_on: 'high', fail_on_partial: true, max_new_findings: null, ...config.gate };
    config.output = { dir: '.apinspect/runs', formats: ['json', 'sarif'], ...config.output };
    config.redact_fields = config.redact_fields || [];

    const configHash = crypto.createHash('sha256').update(raw).digest('hex').substring(0, 16);

    return { config, configHash };
}

/**
 * Resolves apinspect.config.yaml's `auth` block into the { type, token } shape
 * Context.getAuthHeaders() expects — a pre-provisioned token read from the
 * environment, no live login flow. Shared by the CLI's declarative scan and
 * the MCP server's run_check tool, so they can never disagree about how a
 * declarative-mode request authenticates.
 *
 * @param {object} config - validated config from loadConfig()
 * @returns {{type: 'bearer', token: string}|null}
 * @throws {Error} `.code === 'AUTH_FAILED'` if token_env is unset;
 *   `.code === 'CONFIG_ERROR'` for an unsupported auth.type
 */
function resolveDeclarativeAuth(config) {
    if (!config.auth) return null;

    if (config.auth.type === 'keycloak') {
        const token = process.env[config.auth.token_env];
        if (!token) {
            const err = new Error(`Auth failed: environment variable "${config.auth.token_env}" is not set.`);
            err.code = 'AUTH_FAILED';
            throw err;
        }
        return { type: 'bearer', token };
    }

    const err = new Error(`Unsupported auth.type: "${config.auth.type}". Supported: keycloak.`);
    err.code = 'CONFIG_ERROR';
    throw err;
}

module.exports = { loadConfig, validateConfig, resolveDeclarativeAuth, VALID_FAIL_ON };
