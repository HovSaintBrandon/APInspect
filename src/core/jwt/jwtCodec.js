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

// Every standard JWT segment decodes to a JSON object opening with `{"<lowercase-letter>`
// (alg/typ/kid, or exp/iat/sub/iss/...). That fixes the base64url encoding of its first
// 3 output characters to "eyJ" — reliably enough that a segment lacking that prefix is
// almost always a truncated/off-by-one paste (e.g. grabbing the substring after "Bearer "
// but starting one character too late), not a JSON syntax problem worth reporting as one.
const looksTruncated = (segment) => !segment.startsWith('eyJ');

const parseSegment = (segmentB64, label) => {
    try {
        return JSON.parse(base64UrlDecode(segmentB64).toString('utf8'));
    } catch (e) {
        if (looksTruncated(segmentB64)) {
            throw new Error(
                `${label} segment doesn't start with "eyJ" (got "${segmentB64.slice(0, 6)}..."). ` +
                'Every JWT header/payload decodes from a JSON object, which always base64url-encodes to a leading "eyJ" — ' +
                'this token is very likely missing a leading character (a common paste mistake, e.g. copying from ' +
                '"Bearer eyJ..." starting one character too late). Re-copy the full token and try again.'
            );
        }
        throw new Error(`Failed to parse JWT ${label.toLowerCase()} as JSON: ${e.message}`);
    }
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

    const header = parseSegment(headerB64, 'Header');
    const payload = parseSegment(payloadB64, 'Payload');

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
