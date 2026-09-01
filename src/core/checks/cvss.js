/**
 * src/core/checks/cvss.js
 *
 * Static, representative CVSS v3.1 vector + severity per check ID — not computed
 * per-finding from live evidence, which is a much harder, more open-ended
 * problem (the vector for "server accepted a mass-assigned field" genuinely
 * depends on which field). Each entry reflects a typical instance of that
 * vulnerability class. `severity` (none|low|medium|high|critical, matching
 * gate.fail_on's vocabulary) is assigned directly rather than derived from the
 * vector via a base-score formula — same pattern checklist.json already uses
 * for the AI-driven path's `severity` field.
 */
const CHECKS = {
    API1_BOLA:         { cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N', severity: 'critical' },
    API2_BROKEN_AUTH:  { cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', severity: 'critical' },
    API3_BOPLA:        { cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:H/A:N', severity: 'high' },
    API4_RATE_LIMIT:   { cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L', severity: 'medium' },
    API5_BFLA:         { cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N', severity: 'critical' },
    API8_MISCONFIG:      { cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N', severity: 'medium' },
    API8_2019_INJECTION: { cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', severity: 'critical' },
};

const getCheckMeta = (checkId) => CHECKS[checkId] || { cvss_vector: null, severity: 'medium' };

module.exports = { CHECKS, getCheckMeta };
