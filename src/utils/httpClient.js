const axios = require('axios');
const logger = require('./logger');

/**
 * @param {string} baseURL
 * @param {object} headers
 * @param {number} timeout
 * @param {object|null} context
 * @param {string[]|null} allowlist - declarative-mode only (see src/core/allowlist.js).
 *   Every other caller passes nothing here, so this is purely additive — no
 *   change to any existing (non-declarative) call site's behavior. When set,
 *   the base host is checked up front and every redirect hop is re-checked via
 *   axios's beforeRedirect — "allowlisted" has to survive a redirect off-host,
 *   not just the URL a config author actually typed in.
 */
const createClient = (baseURL, headers = {}, timeout = 5000, context = null, allowlist = null) => {
    const axiosConfig = {
        baseURL,
        timeout,
        headers,
        validateStatus: () => true // Don't throw on error status codes
    };

    if (allowlist) {
        const { assertHostAllowed, assertHostnameAllowed } = require('../core/allowlist');
        assertHostAllowed(baseURL, allowlist);
        axiosConfig.beforeRedirect = (redirectOptions) => {
            assertHostnameAllowed(redirectOptions.hostname, allowlist);
        };
    }

    const instance = axios.create(axiosConfig);

    // Automatically resolve {{variables}} in the URL before request is sent.
    // The URL specifically goes through resolvePath() (not resolveString) since
    // it's always a path, never an arbitrary string — that lets it also collapse
    // "//" left behind by stripping out an embedded {{base_url}}/{{baseUrl}}.
    instance.interceptors.request.use(req => {
        if (context && req.url) {
            req.url = context.resolvePath(req.url);

            // Also resolve variables inside the JSON body (if present)
            if (req.data && typeof req.data === 'string') {
                try {
                    req.data = JSON.parse(context.resolveString(req.data));
                } catch(e) {
                    req.data = context.resolveString(req.data);
                }
            } else if (req.data && typeof req.data === 'object') {
                const strData = JSON.stringify(req.data);
                req.data = JSON.parse(context.resolveString(strData));
            }
        }
        return req;
    });

    // Record every request/response exchange onto the context so the engine can
    // attach a full evidence trail to hardcoded-check results without every check
    // module having to return its raw HTTP exchange (see engine.js _runHardcodedCheck).
    // validateStatus is always `() => true` here, so every HTTP response (2xx-5xx)
    // reaches this success handler — only genuine network errors reject.
    instance.interceptors.response.use(res => {
        if (context) {
            if (!context._exchangeLog) context._exchangeLog = [];
            context._exchangeLog.push({
                request: {
                    method: (res.config.method || '').toUpperCase(),
                    url: res.config.url,
                    headers: res.config.headers || {},
                    body: res.config.data ?? null,
                },
                response: {
                    status: res.status,
                    headers: res.headers,
                    body: typeof res.data === 'string'
                        ? res.data.substring(0, 2000)
                        : JSON.stringify(res.data ?? null).substring(0, 2000),
                },
            });
        }
        return res;
    });

    return instance;
};

module.exports = { createClient };
