/**
 * src/core/artifacts.js
 *
 * Writes a declarative-mode run's output — findings.json, findings.sarif,
 * manifest.json — under <output.dir>/<timestamp>/, plus a `latest` copy.
 * Redaction happens here, once, on every finding's evidence before anything
 * touches disk — this is the only place in the declarative path that writes
 * scan output, so it's the one place redaction has to be correct for both the
 * CLI and (later) the MCP server, which only ever reads what's already here.
 */
const fs = require('node:fs');
const path = require('node:path');

const DEFAULT_REDACT_HEADERS = new Set(['authorization', 'cookie', 'x-api-key']);

// Body field names redacted by default, in addition to whatever a config's
// redact_fields adds — these are exactly the fields a target commonly echoes
// straight back in a RESPONSE body. Found live: httpbin.org's /bearer
// endpoint returns the caller-supplied token verbatim in its JSON response —
// a real secret sent by a check's own probe request, reflected right back
// into what would otherwise have been written to disk / returned to an MCP
// tool caller unredacted.
const DEFAULT_REDACT_BODY_FIELDS = ['token', 'access_token', 'refresh_token', 'id_token', 'password', 'secret', 'api_key', 'authorization'];

function redactHeaders(headers, extraFields) {
    if (!headers) return headers;
    const redacted = {};
    for (const [key, value] of Object.entries(headers)) {
        const lower = key.toLowerCase();
        redacted[key] = (DEFAULT_REDACT_HEADERS.has(lower) || extraFields.includes(lower)) ? '[REDACTED]' : value;
    }
    return redacted;
}

// A request body is still a parsed object at this point (httpClient.js hasn't
// serialized it) — redact by walking its keys, recursing into nested objects.
function redactBodyObject(body, fieldNames) {
    if (!body || typeof body !== 'object') return body;
    const redacted = Array.isArray(body) ? [] : {};
    for (const [key, value] of Object.entries(body)) {
        if (fieldNames.includes(key.toLowerCase())) {
            redacted[key] = '[REDACTED]';
        } else if (value && typeof value === 'object') {
            redacted[key] = redactBodyObject(value, fieldNames);
        } else {
            redacted[key] = value;
        }
    }
    return redacted;
}

// A response body is already a serialized (and truncated) STRING by the time
// it reaches here — see httpClient.js's exchange logger, which the legacy
// hardcoded-check evidence trail also depends on, so that shape isn't changed
// here. Field-level redaction on already-serialized JSON has to work on the
// raw text instead of object keys: best-effort, same tradeoff API3_BOPLA.js's
// own reflection-detection heuristic already accepts. Matches a plain
// `"field": "value"` pair; doesn't attempt to handle an escaped quote inside
// the value itself.
function redactBodyString(bodyText, fieldNames) {
    if (typeof bodyText !== 'string' || bodyText.length === 0) return bodyText;
    return fieldNames.reduce(
        (text, field) => text.replace(new RegExp(String.raw`("${field}"\s*:\s*")[^"]*(")`, 'gi'), '$1[REDACTED]$2'),
        bodyText
    );
}

/**
 * @param {Array} evidence - raw request/response exchanges from context._exchangeLog
 * @param {string[]} redactFields - additional field/header names from config.redact_fields
 */
function redactEvidence(evidence, redactFields = []) {
    const extra = redactFields.map(f => f.toLowerCase());
    const bodyFieldNames = [...new Set([...DEFAULT_REDACT_BODY_FIELDS, ...extra])];
    return (evidence || []).map(exchange => ({
        request: exchange.request && {
            ...exchange.request,
            headers: redactHeaders(exchange.request.headers, extra),
            body: typeof exchange.request.body === 'object'
                ? redactBodyObject(exchange.request.body, bodyFieldNames)
                : redactBodyString(exchange.request.body, bodyFieldNames),
        },
        response: exchange.response && {
            ...exchange.response,
            headers: redactHeaders(exchange.response.headers, extra),
            body: redactBodyString(exchange.response.body, bodyFieldNames),
        },
    }));
}

function buildSarif(findings) {
    const rules = [...new Set(findings.map(f => f.check_id))].map(id => ({
        id,
        shortDescription: { text: id },
    }));

    const results = findings
        .filter(f => f.status === 'FAIL')
        .map(f => ({
            ruleId: f.check_id,
            level: 'error',
            message: { text: f.message },
            properties: { cvss_vector: f.cvss_vector, severity: f.severity },
            locations: [{
                physicalLocation: {
                    artifactLocation: { uri: f.endpoint },
                    region: { startLine: 1 },
                },
            }],
        }));

    return {
        $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
        version: '2.1.0',
        runs: [{
            tool: { driver: { name: 'apinspect', rules } },
            results,
        }],
    };
}

/**
 * @param {object} opts
 * @param {object} opts.config - validated, defaulted config from configSchema.js
 * @param {string} opts.configHash
 * @param {Array} opts.findings - raw runner.js output (unredacted)
 * @param {boolean} opts.completed
 * @param {string|null} [opts.abortReason]
 * @returns {{runDir: string, findingsPath: string, sarifPath: string|null, manifest: object}}
 */
function writeRun({ config, configHash, findings, completed, abortReason = null }) {
    const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
    const outputDir = config.output.dir;
    const runDir = path.join(process.cwd(), outputDir, timestamp);
    fs.mkdirSync(runDir, { recursive: true });

    // Stamped id (1-based, matching jsonReporter.js's convention for the
    // legacy report format) — the MCP server's explain_finding tool needs a
    // stable, simple way to reference exactly one finding in a run.
    const redactedFindings = findings.map((f, i) => ({ id: i + 1, ...f, evidence: redactEvidence(f.evidence, config.redact_fields) }));

    const findingsPath = path.join(runDir, 'findings.json');
    fs.writeFileSync(findingsPath, JSON.stringify(redactedFindings, null, 2));

    let sarifPath = null;
    if (config.output.formats.includes('sarif')) {
        sarifPath = path.join(runDir, 'findings.sarif');
        fs.writeFileSync(sarifPath, JSON.stringify(buildSarif(redactedFindings), null, 2));
    }

    const manifest = {
        timestamp: new Date().toISOString(),
        config_hash: configHash,
        target: config.target.base_url,
        completed,
        abort_reason: abortReason,
        finding_count: redactedFindings.length,
        fail_count: redactedFindings.filter(f => f.status === 'FAIL').length,
    };
    fs.writeFileSync(path.join(runDir, 'manifest.json'), JSON.stringify(manifest, null, 2));

    // `latest` — a plain copy, not a symlink, so it survives identically on
    // every OS and inside a CI artifact archive (which usually can't preserve
    // a symlink target across upload/download — see the GitLab CI example).
    const latestDir = path.join(process.cwd(), outputDir, 'latest');
    fs.rmSync(latestDir, { recursive: true, force: true });
    fs.mkdirSync(latestDir, { recursive: true });
    fs.copyFileSync(findingsPath, path.join(latestDir, 'findings.json'));
    if (sarifPath) fs.copyFileSync(sarifPath, path.join(latestDir, 'findings.sarif'));
    fs.copyFileSync(path.join(runDir, 'manifest.json'), path.join(latestDir, 'manifest.json'));

    return { runDir, findingsPath, sarifPath, manifest };
}

module.exports = { writeRun, redactEvidence, buildSarif };
