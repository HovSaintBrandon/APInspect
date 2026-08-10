// Offline JWT analysis — header and claim inspection, no network/crypto forging involved.
// Findings shape mirrors the rest of the codebase's check results: { id, severity, field, message, recommendation }.

const HMAC_ALGS = new Set(['HS256', 'HS384', 'HS512']);
const ASYMMETRIC_ALGS = new Set(['RS256', 'RS384', 'RS512', 'ES256', 'ES384', 'ES512', 'PS256', 'PS384', 'PS512']);
const NONE_ALGS = new Set(['none', 'None', 'NONE', 'NoNe']);

// Claim/key names that commonly carry authorization decisions — flagged in both the
// claims analysis (as an escalation surface) and reused by jwtForge to know what to tamper with.
const PRIVILEGE_CLAIM_KEYS = ['role', 'roles', 'isAdmin', 'is_admin', 'admin', 'scope', 'scopes', 'permissions', 'user_type', 'type'];

// Key/value patterns that shouldn't appear in a JWT payload — it's base64, not encryption,
// so anything here is plaintext to whoever holds the token.
const SENSITIVE_KEY_PATTERN = /password|secret|ssn|social_security|credit_card|card_number|cvv|api_key|apikey|private_key|pin\b/i;

const analyzeHeader = (header = {}) => {
    const findings = [];
    const alg = header.alg;

    if (!alg || NONE_ALGS.has(alg)) {
        findings.push({
            id: 'JWT-ALG-NONE',
            severity: 'critical',
            field: 'alg',
            message: `Token header declares alg="${alg}" — an unsigned token. If the server trusts this value, authentication is fully bypassable.`,
            recommendation: 'Reject alg=none server-side; pin the expected algorithm(s) explicitly instead of trusting the token\'s own "alg" header.',
        });
    } else if (!HMAC_ALGS.has(alg) && !ASYMMETRIC_ALGS.has(alg)) {
        findings.push({
            id: 'JWT-ALG-UNKNOWN',
            severity: 'medium',
            field: 'alg',
            message: `Unrecognized alg="${alg}".`,
            recommendation: 'Confirm the server explicitly allowlists this algorithm rather than deriving behavior from it dynamically.',
        });
    }

    if (header.typ && !/^(jwt|at\+jwt)$/i.test(header.typ)) {
        findings.push({
            id: 'JWT-TYP-UNUSUAL',
            severity: 'info',
            field: 'typ',
            message: `Unusual "typ" header: "${header.typ}".`,
            recommendation: 'Confirm this is intentional — access tokens are conventionally "JWT" or "at+jwt".',
        });
    }

    if (header.kid !== undefined) {
        findings.push({
            id: 'JWT-KID-PRESENT',
            severity: 'medium',
            field: 'kid',
            message: `Token uses a "kid" (key ID) header ("${header.kid}") to select the signing key — a common injection sink (path traversal, SQLi, command injection) when the server uses it to build a filesystem or database lookup.`,
            recommendation: 'Validate "kid" against a strict allowlist of known key IDs; never use it to build a file path or query directly.',
        });
    }

    if (header.jku) {
        findings.push({
            id: 'JWT-JKU-PRESENT',
            severity: 'high',
            field: 'jku',
            message: `Token declares a "jku" (JWK Set URL): ${header.jku}. If the server fetches signing keys from this token-supplied URL without a strict host allowlist, an attacker can host their own JWKS and mint arbitrary valid tokens.`,
            recommendation: 'Never resolve signing keys from a URL embedded in the token; only trust a fixed, pre-configured JWKS endpoint.',
        });
    }

    if (header.x5u) {
        findings.push({
            id: 'JWT-X5U-PRESENT',
            severity: 'high',
            field: 'x5u',
            message: `Token declares an "x5u" (X.509 URL): ${header.x5u} — the same SSRF/key-injection risk as "jku".`,
            recommendation: 'Never trust a certificate URL embedded in the token itself.',
        });
    }

    if (header.jwk) {
        findings.push({
            id: 'JWT-JWK-EMBEDDED',
            severity: 'critical',
            field: 'jwk',
            message: 'Token embeds its own public key via a "jwk" header. If the server verifies the signature using this embedded key rather than a pre-registered one, an attacker can self-sign arbitrary tokens.',
            recommendation: 'Never trust a key embedded in the token — verify only against pre-registered/trusted keys.',
        });
    }

    return findings;
};

const analyzeClaims = (payload = {}) => {
    const findings = [];
    const nowSec = Math.floor(Date.now() / 1000);

    if (payload.exp === undefined) {
        findings.push({
            id: 'JWT-EXP-MISSING',
            severity: 'high',
            field: 'exp',
            message: 'Token has no "exp" claim — if leaked, it remains valid forever.',
            recommendation: 'Always set a short "exp" on access tokens (5-15 minutes), paired with refresh-token rotation.',
        });
    } else {
        if (payload.exp < nowSec) {
            findings.push({
                id: 'JWT-EXP-PAST',
                severity: 'info',
                field: 'exp',
                message: `Token already expired at ${new Date(payload.exp * 1000).toISOString()}.`,
                recommendation: null,
            });
        }
        const issuedAt = payload.iat ?? nowSec;
        const lifetimeSec = payload.exp - issuedAt;
        if (lifetimeSec > 86400) {
            findings.push({
                id: 'JWT-EXP-TOO-LONG',
                severity: 'medium',
                field: 'exp',
                message: `Token lifetime is ${Math.round(lifetimeSec / 3600)}h — unusually long for an access token.`,
                recommendation: 'Use short-lived access tokens (5-15 min) with refresh-token rotation instead of long-lived access tokens.',
            });
        }
    }

    if (payload.iat === undefined) {
        findings.push({
            id: 'JWT-IAT-MISSING',
            severity: 'info',
            field: 'iat',
            message: 'Token has no "iat" claim.',
            recommendation: 'Include "iat" so token age can be reasoned about independently of "exp".',
        });
    }

    if (payload.iss === undefined) {
        findings.push({
            id: 'JWT-ISS-MISSING',
            severity: 'medium',
            field: 'iss',
            message: 'Token has no "iss" (issuer) claim.',
            recommendation: 'Set and validate "iss" server-side so tokens can\'t be forged or replayed from an unexpected issuer.',
        });
    }

    if (payload.aud === undefined) {
        findings.push({
            id: 'JWT-AUD-MISSING',
            severity: 'high',
            field: 'aud',
            message: 'Token has no "aud" (audience) claim — in a multi-service setup, a token minted for one service can be replayed against another.',
            recommendation: 'Set "aud" to the intended service/API and validate it server-side on every request.',
        });
    }

    if (payload.jti === undefined) {
        findings.push({
            id: 'JWT-JTI-MISSING',
            severity: 'low',
            field: 'jti',
            message: 'Token has no "jti" claim — revocation/replay tracking by token ID is not possible.',
            recommendation: 'Include a unique "jti" if you need denylist-based revocation or replay detection.',
        });
    }

    const sensitiveKeys = Object.keys(payload).filter(k => SENSITIVE_KEY_PATTERN.test(k));
    if (sensitiveKeys.length > 0) {
        findings.push({
            id: 'JWT-PAYLOAD-SENSITIVE-DATA',
            severity: 'high',
            field: sensitiveKeys.join(', '),
            message: `Payload includes sensitive-looking field(s): ${sensitiveKeys.join(', ')}. JWT payloads are base64-encoded, not encrypted — anyone holding the token can read them.`,
            recommendation: 'Remove sensitive data from the payload; store it server-side keyed by a claim like "sub" instead.',
        });
    }

    const privilegeKeys = PRIVILEGE_CLAIM_KEYS.filter(k => k in payload);
    if (privilegeKeys.length > 0) {
        findings.push({
            id: 'JWT-PAYLOAD-PRIVILEGE-CLAIMS',
            severity: 'info',
            field: privilegeKeys.join(', '),
            message: `Payload carries authorization-relevant claim(s): ${privilegeKeys.join(', ')}. These become an escalation surface for any forgery/tampering attack that produces a signature the server accepts.`,
            recommendation: 'Ensure these claims are only ever set by the server, and re-validated against the source of truth on sensitive operations rather than trusted blindly from the token.',
        });
    }

    return findings;
};

module.exports = { analyzeHeader, analyzeClaims, HMAC_ALGS, ASYMMETRIC_ALGS, NONE_ALGS, PRIVILEGE_CLAIM_KEYS };
