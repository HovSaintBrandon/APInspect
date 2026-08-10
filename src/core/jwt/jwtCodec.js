// Base64url helpers + raw JWT decode. Deliberately dependency-free (Buffer/crypto
// only) — a JWT is just three dot-separated base64url segments, no library needed
// to read one, and forging tokens later requires building raw segments anyway.

const base64UrlDecode = (str) => {
    const padded = str.replace(/-/g, '+').replace(/_/g, '/');
    return Buffer.from(padded, 'base64');
};

const base64UrlEncode = (buf) => {
    return buf.toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
};

/**
 * Split and parse a JWT into its header/payload/signature, without verifying anything.
 * @throws {Error} if the token isn't 3 dot-separated segments, or header/payload aren't JSON.
 */
const decode = (token) => {
    const parts = (token || '').split('.');
    if (parts.length !== 3) {
        throw new Error(`Not a well-formed JWT — expected 3 dot-separated segments, got ${parts.length}.`);
    }
    const [headerB64, payloadB64, signatureB64] = parts;

    let header;
    try {
        header = JSON.parse(base64UrlDecode(headerB64).toString('utf8'));
    } catch (e) {
        throw new Error(`Failed to parse JWT header as JSON: ${e.message}`);
    }

    let payload;
    try {
        payload = JSON.parse(base64UrlDecode(payloadB64).toString('utf8'));
    } catch (e) {
        throw new Error(`Failed to parse JWT payload as JSON: ${e.message}`);
    }

    return {
        header,
        payload,
        signature: base64UrlDecode(signatureB64),
        signingInput: `${headerB64}.${payloadB64}`,
        raw: { headerB64, payloadB64, signatureB64 },
    };
};

/** Re-assemble a token from a header/payload object pair and a raw signature Buffer (or none). */
const encode = (header, payload, signatureBuf) => {
    const headerB64 = base64UrlEncode(Buffer.from(JSON.stringify(header)));
    const payloadB64 = base64UrlEncode(Buffer.from(JSON.stringify(payload)));
    const sigB64 = signatureBuf ? base64UrlEncode(signatureBuf) : '';
    return `${headerB64}.${payloadB64}.${sigB64}`;
};

module.exports = { base64UrlDecode, base64UrlEncode, decode, encode };
