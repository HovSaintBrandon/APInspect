// Exchanges a refresh_token for a new access token via an OAuth2/OIDC token
// endpoint, so a short-lived bearer token can be renewed mid-scan instead of
// expiring partway through a long run and turning later checks into false
// AUTH_BLOCKED/401 noise.
//
// tokenUrl/clientId default to values derived from the *current* access token's
// own claims (iss/azp) — the shape every Keycloak-issued token (the only IdP
// APInspect has been pointed at so far) already carries — so a bare `--refresh
// <token>` works without also requiring `--token-url`/`--client-id` for the
// common case. Both can still be overridden explicitly for other IdPs or
// confidential clients.
const axios = require('axios');
const { decode } = require('./jwtCodec');
const { InfrastructureError } = require('../../utils/errors');

// Refresh this many seconds before actual expiry — gives whatever uses the token
// (an in-flight scan request, the `refresh` command's next scheduled wakeup) enough
// margin that it won't land server-side a few hundred ms after exp. Shared by
// Context#ensureFreshToken (mid-scan refresh) and the standalone `refresh` command.
const REFRESH_SKEW_SECONDS = 30;

const deriveTokenUrl = (currentToken) => {
    const { payload } = decode(currentToken);
    if (!payload.iss) return null;
    return `${payload.iss.replace(/\/+$/, '')}/protocol/openid-connect/token`;
};

const deriveClientId = (currentToken) => {
    const { payload } = decode(currentToken);
    return payload.azp || payload.client_id || null;
};

/**
 * @param {object} opts
 * @param {string} opts.currentToken - the access token about to expire (used to derive tokenUrl/clientId when not given)
 * @param {string} opts.refreshToken
 * @param {string} [opts.tokenUrl] - OAuth2 token endpoint; derived from currentToken's `iss` claim if omitted
 * @param {string} [opts.clientId] - OAuth2 client_id; derived from currentToken's `azp`/`client_id` claim if omitted
 * @param {string} [opts.clientSecret] - only needed for confidential clients
 * @returns {Promise<{accessToken: string, refreshToken: string, expiresIn: number|undefined}>}
 * @throws {InfrastructureError} if tokenUrl/clientId can't be resolved, or the refresh request fails
 */
const refreshAccessToken = async ({ currentToken, refreshToken, tokenUrl, clientId, clientSecret }) => {
    const resolvedTokenUrl = tokenUrl || deriveTokenUrl(currentToken);
    const resolvedClientId = clientId || deriveClientId(currentToken);

    if (!resolvedTokenUrl) {
        throw new InfrastructureError(
            'Cannot refresh the bearer token: no --token-url given and the current access token has no "iss" claim to derive one from.'
        );
    }
    if (!resolvedClientId) {
        throw new InfrastructureError(
            'Cannot refresh the bearer token: no --client-id given and the current access token has no "azp"/"client_id" claim to derive one from.'
        );
    }

    const body = new URLSearchParams({
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: resolvedClientId,
    });
    if (clientSecret) body.set('client_secret', clientSecret);

    let response;
    try {
        response = await axios.post(resolvedTokenUrl, body.toString(), {
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            validateStatus: () => true,
        });
    } catch (err) {
        throw new InfrastructureError(`Token refresh request to ${resolvedTokenUrl} failed: ${err.message}`);
    }

    if (response.status < 200 || response.status >= 300 || !response.data?.access_token) {
        const detail = typeof response.data === 'string' ? response.data.slice(0, 500) : JSON.stringify(response.data);
        throw new InfrastructureError(`Token refresh failed (HTTP ${response.status}) at ${resolvedTokenUrl}: ${detail}`);
    }

    return {
        accessToken: response.data.access_token,
        refreshToken: response.data.refresh_token || refreshToken,
        expiresIn: response.data.expires_in,
    };
};

module.exports = { refreshAccessToken, deriveTokenUrl, deriveClientId, REFRESH_SKEW_SECONDS };
