/**
 * API3:2023 Broken Object Property Level Authorization (mass assignment).
 *
 * Deterministic version of the AI-probe-driven MASSASSIGN checks in the FALCON
 * checklist — no LLM involved. Sends the endpoint's configured body (if any)
 * plus a handful of commonly-privileged extra fields, then checks whether the
 * response reflects them back as accepted. Only meaningful for a body-carrying
 * method; anything else is N/A.
 *
 * Detection is a heuristic (substring match on the serialized response body for
 * each probed field name) — good enough to flag for human review in a CI gate,
 * not a guarantee the field was actually persisted server-side. A field that
 * legitimately appears elsewhere in a normal response (e.g. an endpoint that
 * already returns a "role" field for unrelated reasons) can false-positive;
 * treat a FAIL here as "worth a manual look," same as any heuristic check.
 */
const PRIVILEGE_PROBE_FIELDS = {
    role: 'admin',
    isAdmin: true,
    is_admin: true,
    account_status: 'active',
    email_verified: true,
    permissions: ['*'],
};

module.exports = async (context, client, endpoint) => {
    const method = ((endpoint.methods && endpoint.methods[0]) || 'GET').toUpperCase();
    if (!['POST', 'PUT', 'PATCH'].includes(method)) {
        return {
            status: 'N/A',
            message: `${method} does not carry a request body — mass assignment is not applicable.`,
        };
    }

    const baseBody = (endpoint.body && typeof endpoint.body === 'object') ? endpoint.body : {};
    const probeBody = { ...baseBody, ...PRIVILEGE_PROBE_FIELDS };

    try {
        const response = await client.request({ method, url: endpoint.path, data: probeBody });
        const status = response.status;

        if (status === 401 || status === 403) {
            return {
                status: 'AUTH_BLOCKED',
                message: `Request blocked by auth (${status}) before mass-assignment logic could be exercised.`,
                details: { status },
            };
        }
        if (status === 404) {
            return {
                status: 'ROUTE_NOT_FOUND',
                message: `No route matched for ${method} ${endpoint.path} (404).`,
                details: { status },
            };
        }
        if (status < 200 || status >= 300) {
            return {
                status: 'MANUAL',
                message: `Request rejected with ${status} for an unrelated reason — mass-assignment handling not genuinely exercised.`,
                details: { status },
            };
        }

        const bodyText = typeof response.data === 'string' ? response.data : JSON.stringify(response.data ?? '');
        const reflectedFields = Object.keys(PRIVILEGE_PROBE_FIELDS).filter(field => bodyText.includes(`"${field}"`));

        if (reflectedFields.length > 0) {
            return {
                status: 'FAIL',
                message: `Server accepted/reflected privileged field(s) not part of the configured request body: ${reflectedFields.join(', ')}.`,
                details: { status, reflectedFields },
            };
        }

        return {
            status: 'PASS',
            message: 'Injected privileged fields were not reflected/accepted in the response.',
            details: { status, probedFields: Object.keys(PRIVILEGE_PROBE_FIELDS) },
        };
    } catch (error) {
        return {
            status: 'MANUAL',
            message: `Network error during mass-assignment probe: ${error.message}`,
            details: { error: error.message },
        };
    }
};
