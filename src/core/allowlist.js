/**
 * src/core/allowlist.js
 *
 * Host authorization for the declarative scan path — enforced here and nowhere
 * else. Reads exclusively from the already-loaded apinspect.config.yaml; there
 * is no code path anywhere (CLI flag, and later an MCP tool argument) that can
 * add a host at runtime. Called both before the first request to an endpoint
 * and on every redirect hop (see src/utils/httpClient.js's beforeRedirect
 * wiring) — "allowlisted" has to mean the same thing at every hop, not just
 * the one a config author actually typed in.
 */

function isHostnameAllowed(hostname, allowlist) {
    const needle = String(hostname).toLowerCase();
    return allowlist.some(h => h.toLowerCase() === needle);
}

function isHostAllowed(url, allowlist) {
    try {
        return isHostnameAllowed(new URL(url).hostname, allowlist);
    } catch {
        // Not a parseable absolute URL — never trust it by default.
        return false;
    }
}

function assertHostnameAllowed(hostname, allowlist) {
    if (!isHostnameAllowed(hostname, allowlist)) {
        throw new Error(`Host not allowlisted: ${hostname} (target.allowlist: ${allowlist.join(', ')})`);
    }
}

function assertHostAllowed(url, allowlist) {
    let hostname;
    try {
        hostname = new URL(url).hostname;
    } catch {
        throw new Error(`Cannot authorize host — not a parseable absolute URL: ${url}`);
    }
    assertHostnameAllowed(hostname, allowlist);
}

module.exports = { isHostAllowed, isHostnameAllowed, assertHostAllowed, assertHostnameAllowed };
