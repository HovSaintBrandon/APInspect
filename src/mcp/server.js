#!/usr/bin/env node
/**
 * src/mcp/server.js
 *
 * The MCP server — local, interactive, and read-mostly. No tool here ever
 * produces a pass/fail verdict (every result is tagged `gating: false`); the
 * declarative CLI (`apinspect scan --config`) is the only mode allowed to gate
 * a build. See docs/APINSPECT-DECLARATIVE-MODE.md for the split's rationale
 * and docs/APINSPECT-MCP-SERVER.md for this server specifically.
 *
 * `list_runs`, `get_findings`, `explain_finding`, `diff_runs` are read-only —
 * they touch only artifact files apinspect scan --config already wrote under
 * .apinspect/runs/. `run_check` is the only tool that touches the target, and
 * reuses the exact same core (src/core/runner.js, allowlist.js, artifacts.js)
 * as the declarative CLI, so neither mode owns its own copy of scan logic.
 */
const fs = require('node:fs');
const path = require('node:path');
const { z } = require('zod');
const { McpServer } = require('@modelcontextprotocol/sdk/server/mcp.js');
const { StdioServerTransport } = require('@modelcontextprotocol/sdk/server/stdio.js');

const { loadConfig, resolveDeclarativeAuth } = require('../core/configSchema');
const { isHostAllowed } = require('../core/allowlist');
const runner = require('../core/runner');
const { redactEvidence } = require('../core/artifacts');
const { createClient } = require('../utils/httpClient');
const Context = require('../core/context');
const packageJson = require('../../package.json');

const DEFAULT_OUTPUT_DIR = '.apinspect/runs';
const AUDIT_LOG_PATH = path.join(process.cwd(), '.apinspect', 'mcp-audit.log');

// run_check constraints — "An agent in a loop should hit a wall well before
// the target does." Deliberately conservative defaults; tune here if a real
// triage session needs more headroom. Session-lifetime only (module-level
// state, resets when the server restarts) — matches how openrouterClient.js's
// _usingAltKey/_requestCount already scope similar counters to one process.
const RUN_CHECK_RATE_LIMIT_MS = 2000;
const RUN_CHECK_SESSION_CAP = 20;
let _runCheckCallCount = 0;
let _lastRunCheckAt = 0;

// Config is loaded once at startup. A missing/invalid config doesn't crash
// the server — list_runs/get_findings/explain_finding/diff_runs only read
// files already on disk and work regardless; only run_check actually needs a
// valid config (it's the only tool that talks to a target).
let _config = null;
let _configHash = null;
let _configLoadError = null;
try {
    const configPath = path.join(process.cwd(), 'apinspect.config.yaml');
    ({ config: _config, configHash: _configHash } = loadConfig(configPath));
} catch (err) {
    _configLoadError = err.message;
}

function getOutputDir() {
    return _config?.output?.dir || DEFAULT_OUTPUT_DIR;
}

function textResult(payload) {
    return { content: [{ type: 'text', text: JSON.stringify(payload, null, 2) }] };
}

function errorResult(message) {
    return { content: [{ type: 'text', text: message }], isError: true };
}

function listRunIds() {
    const base = path.join(process.cwd(), getOutputDir());
    if (!fs.existsSync(base)) return [];
    return fs.readdirSync(base, { withFileTypes: true })
        .filter(d => d.isDirectory() && d.name !== 'latest')
        .map(d => d.name)
        .sort()
        .reverse(); // ISO timestamp directory names — lexical sort is chronological
}

function readRun(runId) {
    const runDir = path.join(process.cwd(), getOutputDir(), runId);
    const manifestPath = path.join(runDir, 'manifest.json');
    const findingsPath = path.join(runDir, 'findings.json');
    if (!fs.existsSync(manifestPath) || !fs.existsSync(findingsPath)) return null;
    return {
        manifest: JSON.parse(fs.readFileSync(manifestPath, 'utf8')),
        findings: JSON.parse(fs.readFileSync(findingsPath, 'utf8')),
    };
}

function appendAuditLog(entry) {
    fs.mkdirSync(path.dirname(AUDIT_LOG_PATH), { recursive: true });
    fs.appendFileSync(AUDIT_LOG_PATH, `${JSON.stringify({ timestamp: new Date().toISOString(), ...entry })}\n`);
}

// A request `path` isn't guaranteed to actually be relative — axios treats an
// absolute URL (including a bare protocol-relative "//host/..." — see axios's
// own isAbsoluteURL, which matches an OPTIONAL scheme before "//") as an
// override of `baseURL` entirely, bypassing it. The existing allowlist wiring
// in httpClient.js only re-checks on a *redirect* hop; a value that overrides
// baseURL outright never redirects, it just IS the request. This is the one
// genuinely new attack surface run_check introduces (every other endpoint
// path in this tool comes from a trusted config/collection file, not a live
// tool argument) — reject it before ever building a client.
//
// Deliberately not a hand-rolled "is this absolute" regex: an early version
// of this check matched only "<scheme>://", missing the protocol-relative
// case entirely (a real gap: it just happened not to be exploitable against
// this axios/Node version's specific error behavior, which isn't something to
// rely on going forward). Instead, resolve `reqPath` against target.base_url
// with the same WHATWG URL parser allowlist.js already uses everywhere else,
// and validate the RESOLVED destination — this is what actually decides
// where axios will send the request, so checking anything else is checking
// the wrong thing.
function resolvesOutsideAllowlist(reqPath, baseUrl, allowlist) {
    let resolved;
    try {
        resolved = new URL(reqPath, baseUrl);
    } catch {
        return true; // unparseable — never trust it
    }
    return !isHostAllowed(resolved.href, allowlist);
}

const server = new McpServer({ name: 'apinspect', version: packageJson.version });

server.registerTool('list_runs', {
    title: 'List runs',
    description: 'Lists completed apinspect declarative-mode scan runs (apinspect scan --config), newest first, with summary counts from each run\'s manifest.json. Read-only.',
    inputSchema: {
        limit: z.number().int().positive().max(100).optional().describe('Max runs to return (default 20).'),
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
}, async ({ limit }) => {
    const runs = listRunIds().slice(0, limit || 20).map(runId => {
        const run = readRun(runId);
        return run ? { run_id: runId, ...run.manifest } : { run_id: runId, error: 'manifest.json/findings.json unreadable or missing' };
    });
    return textResult({ gating: false, runs });
});

server.registerTool('get_findings', {
    title: 'Get findings',
    description: 'Returns findings for one run, optionally filtered by severity or check ID. Read-only — reads findings.json already written by apinspect scan --config; evidence in the result is already redacted.',
    inputSchema: {
        run_id: z.string().describe('A run_id from list_runs, or "latest".'),
        severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
        check_id: z.string().optional(),
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
}, async ({ run_id, severity, check_id }) => {
    const run = readRun(run_id);
    if (!run) return errorResult(`Run not found: "${run_id}". Use list_runs to see available run IDs.`);

    let findings = run.findings;
    if (severity) findings = findings.filter(f => f.severity === severity);
    if (check_id) findings = findings.filter(f => f.check_id === check_id);

    return textResult({ gating: false, run_id, count: findings.length, findings });
});

server.registerTool('explain_finding', {
    title: 'Explain finding',
    description: 'Returns full evidence and the CVSS vector for one finding, identified by run_id + its 1-based id from get_findings. Read-only.',
    inputSchema: {
        run_id: z.string().describe('A run_id from list_runs, or "latest".'),
        finding_id: z.number().int().positive().describe('The `id` field from get_findings.'),
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
}, async ({ run_id, finding_id }) => {
    const run = readRun(run_id);
    if (!run) return errorResult(`Run not found: "${run_id}". Use list_runs to see available run IDs.`);

    const finding = run.findings.find(f => f.id === finding_id);
    if (!finding) return errorResult(`Finding id ${finding_id} not found in run "${run_id}".`);

    return textResult({ gating: false, ...finding });
});

server.registerTool('diff_runs', {
    title: 'Diff runs',
    description: 'Compares FAIL findings between two runs (added / resolved / unchanged), matched by check_id + method + endpoint. Warns if the runs\' config_hash differs — the endpoint/check set may have changed, making the diff potentially misleading. Read-only.',
    inputSchema: {
        run_id_a: z.string().describe('The baseline run_id.'),
        run_id_b: z.string().describe('The run_id to compare against the baseline.'),
    },
    annotations: { readOnlyHint: true, openWorldHint: false },
}, async ({ run_id_a, run_id_b }) => {
    const a = readRun(run_id_a);
    const b = readRun(run_id_b);
    if (!a) return errorResult(`Run not found: "${run_id_a}".`);
    if (!b) return errorResult(`Run not found: "${run_id_b}".`);

    const keyOf = (f) => `${f.check_id}::${f.method}::${f.endpoint}`;
    const failsOf = (run) => new Map(run.findings.filter(f => f.status === 'FAIL').map(f => [keyOf(f), f]));
    const aFails = failsOf(a);
    const bFails = failsOf(b);

    const added = [...bFails.entries()].filter(([k]) => !aFails.has(k)).map(([, f]) => f);
    const resolved = [...aFails.entries()].filter(([k]) => !bFails.has(k)).map(([, f]) => f);
    const unchanged = [...bFails.entries()].filter(([k]) => aFails.has(k)).map(([, f]) => f);

    const configHashMatch = a.manifest.config_hash === b.manifest.config_hash;

    return textResult({
        gating: false,
        config_hash_match: configHashMatch,
        warning: configHashMatch ? null : 'config_hash differs between these two runs — the endpoint/check set may have changed, so this diff can be misleading.',
        added_findings: added,
        resolved_findings: resolved,
        unchanged_findings: unchanged,
    });
});

server.registerTool('run_check', {
    title: 'Run check',
    description: `Runs named checks against one endpoint on the configured target, ad hoc — for triage, not gating (result is tagged gating: false and never written to .apinspect/runs/). The only tool that touches the target; rate-limited (${RUN_CHECK_RATE_LIMIT_MS}ms between calls) and capped at ${RUN_CHECK_SESSION_CAP} calls per server session. Known check IDs: ${[...runner.VALID_CHECK_IDS].join(', ')}. There is no host/base_url argument — the target always comes from apinspect.config.yaml's target.base_url, and every path is confirmed to resolve within target.allowlist (including any redirect) before a request is sent.`,
    inputSchema: {
        path: z.string().describe('Endpoint path, relative to target.base_url in apinspect.config.yaml.'),
        method: z.enum(['GET', 'POST', 'PUT', 'PATCH', 'DELETE']).default('GET'),
        checks: z.array(z.string()).min(1).describe('Check IDs to run against this endpoint.'),
        body: z.record(z.string(), z.any()).optional().describe('Request body for POST/PUT/PATCH.'),
    },
    annotations: { readOnlyHint: false, destructiveHint: false, openWorldHint: true },
}, async ({ path: reqPath, method, checks, body }) => {
    if (!_config) {
        return errorResult(`Cannot run checks: apinspect.config.yaml failed to load (${_configLoadError}). run_check needs a valid config for target.base_url/target.allowlist.`);
    }

    if (_runCheckCallCount >= RUN_CHECK_SESSION_CAP) {
        return errorResult(`Session cap reached (${RUN_CHECK_SESSION_CAP} run_check calls) — restart the MCP server to reset.`);
    }
    const now = Date.now();
    const sinceLastCall = now - _lastRunCheckAt;
    if (_lastRunCheckAt !== 0 && sinceLastCall < RUN_CHECK_RATE_LIMIT_MS) {
        return errorResult(`Rate limited — wait ${Math.ceil((RUN_CHECK_RATE_LIMIT_MS - sinceLastCall) / 1000)}s between run_check calls.`);
    }

    // Resolved-destination bypass check — see resolvesOutsideAllowlist's comment above.
    if (resolvesOutsideAllowlist(reqPath, _config.target.base_url, _config.target.allowlist)) {
        appendAuditLog({ endpoint: reqPath, method, checks, outcome: 'rejected: path resolves outside target.allowlist' });
        return errorResult(`Rejected: "${reqPath}" resolves outside target.allowlist. Pass a path relative to target.base_url instead.`);
    }

    const unknownChecks = checks.filter(id => !runner.isKnownCheck(id));
    if (unknownChecks.length > 0) {
        return errorResult(`Unknown check ID(s): ${unknownChecks.join(', ')}. Known: ${[...runner.VALID_CHECK_IDS].join(', ')}`);
    }

    _runCheckCallCount++;
    _lastRunCheckAt = now;

    let auth;
    try {
        auth = resolveDeclarativeAuth(_config);
    } catch (err) {
        appendAuditLog({ endpoint: reqPath, method, checks, outcome: `auth_error: ${err.message}` });
        return errorResult(err.message);
    }

    let context, client;
    try {
        context = new Context({ base_url: _config.target.base_url, auth, endpoints: [] });
        client = createClient(_config.target.base_url, context.getAuthHeaders(), 10000, context, _config.target.allowlist);
    } catch (err) {
        appendAuditLog({ endpoint: reqPath, method, checks, outcome: `allowlist_error: ${err.message}` });
        return errorResult(err.message);
    }

    const endpoint = { path: reqPath, methods: [method], body };
    const results = [];
    let outcome = 'ok';
    try {
        for (const checkId of checks) {
            const finding = await runner.runCheck(checkId, endpoint, context, client);
            finding.evidence = redactEvidence(finding.evidence, _config.redact_fields);
            results.push(finding);
        }
    } catch (err) {
        outcome = `error: ${err.message}`;
    }

    appendAuditLog({ endpoint: reqPath, method, checks, outcome, finding_count: results.length });

    return textResult({ gating: false, endpoint: reqPath, method, results });
});

async function main() {
    const transport = new StdioServerTransport();
    await server.connect(transport);
}

main().catch((err) => {
    process.stderr.write(`[apinspect-mcp] Fatal error: ${err.stack || err.message}\n`);
    process.exit(1);
});
