/**
 * API5:2023 Broken Function Level Authorization.
 *
 * NOT IMPLEMENTED in the declarative path yet — same root cause as
 * API1_BOLA.js: a real BFLA test needs a second, lower-privileged identity to
 * confirm it can't reach a higher-privileged function/endpoint, and today's
 * single-identity auth config can't express that. See API1_BOLA.js for the
 * full reasoning; it applies here unchanged.
 */
module.exports = async () => ({
    status: 'NOT_IMPLEMENTED',
    message: 'BFLA testing requires a second, lower-privileged authenticated identity to confirm it cannot reach this function — not yet supported by a single-identity auth config. Needs manual testing until a multi-identity config format is added.',
});
