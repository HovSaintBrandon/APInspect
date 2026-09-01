/**
 * API1:2023 Broken Object Level Authorization.
 *
 * NOT IMPLEMENTED in the declarative path yet — a real BOLA test needs a
 * SECOND authenticated identity to compare against (does identity A's token
 * reach an object identity B owns?), and neither the shared Context.auth model
 * nor apinspect.config.yaml's `auth:` block (a single identity) support a
 * second identity today. Returns a clearly-marked NOT_IMPLEMENTED result
 * rather than a false PASS, so a run's coverage can't be misread as having
 * tested this. Unblocking it needs a config schema addition (a second named
 * identity, plus an "an object identity B owns" per endpoint) — intentionally
 * not invented here since nothing in the spec defines that shape yet.
 */
module.exports = async () => ({
    status: 'NOT_IMPLEMENTED',
    message: 'BOLA testing requires a second authenticated identity to compare object access across — not yet supported by a single-identity auth config. Needs manual testing until a multi-identity config format is added.',
});
