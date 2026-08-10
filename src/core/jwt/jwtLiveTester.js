// Fires forged tokens at a real, supposedly-authenticated endpoint and classifies
// whether each one got through. Two baselines anchor the classification: a request
// with no Authorization header at all, and one with the original (valid) token.

const axios = require('axios');

const isSuccess = (status) => status >= 200 && status < 300;

const sendWithAuth = async ({ url, method, headers, token }) => {
    const res = await axios({
        method,
        url,
        headers: token ? { ...headers, Authorization: `Bearer ${token}` } : headers,
        validateStatus: () => true,
        maxRedirects: 5,
    });
    return {
        status: res.status,
        bodySample: typeof res.data === 'string'
            ? res.data.slice(0, 500)
            : JSON.stringify(res.data).slice(0, 500),
    };
};

const classify = (forgedRes, noAuthRes, originalRes) => {
    if (isSuccess(noAuthRes.status)) {
        return {
            verdict: 'inconclusive',
            reason: `Endpoint returned ${noAuthRes.status} with no Authorization header at all — it doesn't appear to require auth, so success here can't be attributed to the forged token.`,
        };
    }
    if (isSuccess(forgedRes.status)) {
        return {
            verdict: 'accepted',
            reason: forgedRes.status === originalRes.status
                ? `Forged token was accepted (status ${forgedRes.status}, matching the valid-token baseline) while unauthenticated requests get ${noAuthRes.status}.`
                : `Forged token returned ${forgedRes.status} while unauthenticated requests get ${noAuthRes.status} — the server accepted the forged token.`,
        };
    }
    return {
        verdict: 'rejected',
        reason: `Forged token was rejected (status ${forgedRes.status}).`,
    };
};

/**
 * @param {object} opts
 * @param {string} opts.url
 * @param {string} opts.method
 * @param {object} opts.headers - extra headers to send on every request (auth excluded)
 * @param {string} opts.originalToken - the real token, used to establish the "authenticated success" baseline
 * @param {Array<{name, description, token}>} opts.forgeries
 */
const runLiveForgeryTests = async ({ url, method, headers = {}, originalToken, forgeries }) => {
    const noAuthRes = await sendWithAuth({ url, method, headers, token: null });
    const originalRes = await sendWithAuth({ url, method, headers, token: originalToken });

    const attempts = [];
    for (const forgery of forgeries) {
        try {
            const res = await sendWithAuth({ url, method, headers, token: forgery.token });
            attempts.push({ ...forgery, response: res, verdict: classify(res, noAuthRes, originalRes) });
        } catch (err) {
            attempts.push({ ...forgery, error: err.message, verdict: { verdict: 'error', reason: err.message } });
        }
    }

    return {
        baseline: { noAuth: noAuthRes, originalToken: originalRes },
        attempts,
    };
};

module.exports = { runLiveForgeryTests };
