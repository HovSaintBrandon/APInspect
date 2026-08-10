const logger = require('../utils/logger');
const Context = require('./context');
const adapters = require('../adapters');
const { AI_CONFIDENCE_THRESHOLD, AI_FAIL_CONFIDENCE_THRESHOLD } = require('../config/aiConfig');
const { InfrastructureError } = require('../utils/errors');
const { isFail } = require('./statuses');

// ---------------------------------------------------------------------------
// Checklist-driven AI layer
// ---------------------------------------------------------------------------
const checklist = require('../config/checklist.json');
const { getApplicableItems } = require('./ai/applicabilityEngine');
const { synthesizeProbe }    = require('./ai/probeSynthesizer');
const { classifyVerdict }    = require('./ai/verdictClassifier');

// Build a severity lookup from checklist IDs
const _checklistSeverityMap = {};
for (const item of checklist) {
    _checklistSeverityMap[item.id] = item.severity || 'Info';
}

// ---------------------------------------------------------------------------
// Hardcoded checks registry
// In a real implementation, this could dynamically load from the defined directory
// ---------------------------------------------------------------------------
const checksRegistry = {
    'discovery/endpointDiscovery': require('../checks/discovery/endpointDiscovery'),
    'discovery/httpMethods':        require('../checks/discovery/httpMethods'),
    'authentication/authRequired':  require('../checks/authentication/authRequired'),
    'misconfigurations/cors':        require('../checks/misconfigurations/cors'),
    'misconfigurations/securityHeaders': require('../checks/misconfigurations/securityHeaders'),
    'dataExposure/sensitiveData':    require('../checks/dataExposure/sensitiveData'),
    'dataExposure/sensitiveDataAI':  require('../checks/dataExposure/sensitiveDataAI'),
    'errorHandling/stackTrace':      require('../checks/errorHandling/stackTrace'),
    'rateLimiting/bruteForce':       require('../checks/rateLimiting/bruteForce'),
    'injection/sqliXss':             require('../checks/injection/sqliXss'),
    'injection/pathTraversal':       require('../checks/injection/pathTraversal'),
    'graphql/introspectionEnabled': require('../checks/graphql/introspectionEnabled'),
    'graphql/queryDepth':            require('../checks/graphql/queryDepth'),
    'grpc/metadataAuthStripping':    require('../checks/grpc/metadataAuthStripping'),
    'grpc/reflectionEnabled':        require('../checks/grpc/reflectionEnabled'),
    'grpc/tlsEnforcement':           require('../checks/grpc/tlsEnforcement'),
    'grpc/messageSizeLimits':        require('../checks/grpc/messageSizeLimits'),
};

// Which protocols a *legacy* (non-checklist) hardcoded check is meaningful against.
// GraphQL/REST both speak plain HTTP so generic checks (auth stripping, CORS, injection, etc.)
// still produce meaningful results against GraphQL — verified in practice. gRPC does not: its
// client facade ignores the HTTP-semantic `method` field entirely (there's no OPTIONS/TRACE/etc.
// in gRPC), so those same generic checks silently invoke the endpoint's one RPC regardless of
// what method they think they're testing and report bogus results. Protocol-specific checks
// (graphql/*, grpc/*) are restricted to their own protocol.
const legacyCheckAppliesTo = (checkName, protocol) => {
    const targetProtocol = protocol || 'rest';
    if (checkName.startsWith('graphql/')) return targetProtocol === 'graphql';
    if (checkName.startsWith('grpc/')) return targetProtocol === 'grpc';
    return targetProtocol === 'rest' || targetProtocol === 'graphql';
};

// Checklist items (or legacy hardcoded module names) whose entire job is to
// characterize an endpoint's basic behaviour — reachability, auth enforcement,
// headers, CORS, error verbosity. These stay meaningful (and keep running) even
// when the endpoint is gated as unhealthy/blocked, because their job IS to
// report exactly that kind of thing. Everything else tests something deeper
// (data exposure, mass assignment, business logic, rate limiting) that a gated
// request never actually exercised, so it gets suppressed instead of guessed at.
const GATE_EXEMPT_CHECKS = new Set([
    'AUTH-01', 'DISC-01', 'DISC-02', 'MISC-01', 'MISC-02', 'ERR-01',
    'authentication/authRequired', 'discovery/endpointDiscovery', 'discovery/httpMethods',
    'misconfigurations/cors', 'misconfigurations/securityHeaders', 'errorHandling/stackTrace',
]);

class Engine {
    constructor(config) {
        this.context = new Context(config);
        const adapter = adapters[config.protocol || 'rest'];
        if (!adapter) throw new Error(`Unknown protocol "${config.protocol}" — no adapter registered.`);
        this.client  = adapter.createClient(config, this.context);
        // Legacy: flat list of hardcoded checks loaded via loadChecks()
        this.checks  = [];
        // Checklist-driven mode flag — enabled by loadChecklist()
        this._checklistMode = false;
        // Optional persistent AI cache (AICache instance), set by setCache()
        this._cache = null;
        // Per-endpoint gate decisions computed once up front by _computeEndpointGates()
        // (Map<endpoint, {status, message}|null>) — null means the endpoint is healthy
        // and reachable, so nothing is gated.
        this._endpointGates = null;
    }

    // -------------------------------------------------------------------------
    // Attach a persistent AI cache (optional — called by CLI if --cache is set)
    // -------------------------------------------------------------------------
    setCache(cacheInstance) {
        this._cache = cacheInstance;
    }

    // -------------------------------------------------------------------------
    // Legacy API — hardcoded checks loaded by name, run in order
    // -------------------------------------------------------------------------
    loadChecks(checkNames = Object.keys(checksRegistry)) {
        checkNames.forEach(name => {
            if (checksRegistry[name]) {
                this.checks.push({ name, run: checksRegistry[name] });
            } else {
                logger.warn(`Check ${name} not found.`);
            }
        });
    }

    // -------------------------------------------------------------------------
    // New API — switches the engine into checklist-driven mode
    // -------------------------------------------------------------------------
    loadChecklist() {
        this._checklistMode = true;
        logger.info(`[Engine] Checklist mode enabled. Loaded ${checklist.length} items.`);
    }

    // -------------------------------------------------------------------------
    // Shared result normalizer — used by both hardcoded and AI-probe paths
    // -------------------------------------------------------------------------
    _normalizeResult(checkName, endpoint, result) {
        // Derive the checklist item id from the check name (e.g. "checklist/AUTH-01" → "AUTH-01")
        const itemId = checkName.startsWith('checklist/') ? checkName.slice('checklist/'.length) : null;
        const severity = (itemId && _checklistSeverityMap[itemId]) || 'Info';

        // Map status to confirmation axis
        const isTbc = result.status === 'TO BE CONFIRMED' || result.status === 'MANUAL';
        const confirmationStatus = isTbc ? 'to_be_confirmed' : 'confirmed';

        return {
            check:    checkName,
            endpoint: endpoint.path,
            method:   endpoint.methods?.[0] || 'GET',
            status:   result.status,
            severity,
            confirmation_status: confirmationStatus,
            message:  result.message,
            details:  result.details,
            // AI-specific fields (undefined for rule-based checks)
            ai_confidence: result.ai_confidence,
            ai_reasoning:  result.ai_reasoning,
            evidence_cited: result.evidence_cited,
            // Evidence trail — full request/response/reasoning, for every check
            // (hardcoded checks get theirs from the httpClient exchange log; see
            // _runHardcodedCheck / _buildHardcodedEvidenceTrail).
            evidence_trail: result.evidence_trail || null,
        };
    }

    // -------------------------------------------------------------------------
    // Confidence guardrail — applied centrally for all AI results
    // -------------------------------------------------------------------------
    _applyGuardrail(normalized, checkName) {
        if (normalized.ai_confidence === undefined) return normalized; // Not an AI check

        const threshold = isFail(normalized.status) ? AI_FAIL_CONFIDENCE_THRESHOLD : AI_CONFIDENCE_THRESHOLD;

        if (normalized.ai_confidence < threshold) {
            logger.warn(
                `[DOWNGRADE] ${checkName}: AI confidence ` +
                `${normalized.ai_confidence.toFixed(2)} < ${threshold} ` +
                `(${normalized.status} → TO BE CONFIRMED)`
            );
            normalized.status  = 'TO BE CONFIRMED';
            normalized.confirmation_status = 'to_be_confirmed';
            normalized.message = `Low AI confidence (${normalized.ai_confidence.toFixed(2)}) — ${normalized.message}`;
        }

        return normalized;
    }

    // -------------------------------------------------------------------------
    // Build an evidence_trail for a hardcoded check from whatever HTTP exchanges
    // it made, without requiring every check module to return its raw request/
    // response. httpClient's response interceptor logs every exchange onto
    // context._exchangeLog; _runHardcodedCheck resets that log immediately before
    // each check runs, so by the time this is called it holds exactly this check's
    // own requests.
    // -------------------------------------------------------------------------
    _buildHardcodedEvidenceTrail(exchanges) {
        if (!exchanges || exchanges.length === 0) return null;
        const primary = exchanges[exchanges.length - 1];
        return {
            request:  primary.request,
            response: primary.response,
            ai_reasoning: null,
            evidence_cited: null,
            ...(exchanges.length > 1 && {
                note: `${exchanges.length} requests were sent during this check; showing the most recent one.`,
            }),
        };
    }

    // -------------------------------------------------------------------------
    // Deterministic guard against a false PASS caused by the request never
    // reaching the code under test: if a hardcoded check whose job is NOT auth/
    // reachability/header/error characterization (see GATE_EXEMPT_CHECKS) got a
    // 401/403 on its primary request and still returned PASS, that PASS only
    // proves auth ran first — it says nothing about what the check actually
    // claims to verify. Only ever tightens PASS → AUTH_BLOCKED; a FAIL a check
    // found even under a 401 (e.g. a leak inside the error body itself) is left
    // alone, mirroring verdictClassifier's _findPassOverride.
    // -------------------------------------------------------------------------
    _applyHardcodedAuthBlockedOverride(checkName, result, exchanges) {
        if (result.status !== 'PASS') return result;

        const itemId = checkName.startsWith('checklist/') ? checkName.slice('checklist/'.length) : checkName;
        if (GATE_EXEMPT_CHECKS.has(itemId)) return result;

        const primary = exchanges?.[exchanges.length - 1];
        if (!primary || (primary.response.status !== 401 && primary.response.status !== 403)) return result;

        logger.warn(`[Engine] ${checkName}: request was blocked by auth (${primary.response.status}) — downgrading PASS to AUTH_BLOCKED.`);
        return {
            ...result,
            status: 'AUTH_BLOCKED',
            message: `Request returned ${primary.response.status} before ${itemId}'s logic could be exercised — this is a coverage gap, not a passing control. Original message: ${result.message}`,
        };
    }

    // -------------------------------------------------------------------------
    // Execute a hardcoded check module (pre-existing path, unchanged behaviour)
    // -------------------------------------------------------------------------
    async _runHardcodedCheck(check, endpoint) {
        this.context._exchangeLog = [];
        const result = await check.run(this.context, this.client, endpoint);
        if (!result) return;

        const exchanges = this.context._exchangeLog || [];
        const withOverride = this._applyHardcodedAuthBlockedOverride(check.name, result, exchanges);
        const withEvidence = {
            ...withOverride,
            evidence_trail: withOverride.evidence_trail || this._buildHardcodedEvidenceTrail(exchanges),
        };

        const normalized = this._normalizeResult(check.name, endpoint, withEvidence);
        this._applyGuardrail(normalized, check.name);
        this.context.addResult(normalized);
        this._logResult(normalized);
    }

    // -------------------------------------------------------------------------
    // Shared evidence_trail builder for the AI-probe path (classified verdicts
    // and the deterministic short-circuits below all use this same shape).
    // -------------------------------------------------------------------------
    _buildProbeEvidenceTrail(probeSpec, httpResponse, extra = {}) {
        return {
            request: {
                method:      probeSpec.method,
                path:        probeSpec.path,
                headers:     probeSpec.headers || {},
                body:        probeSpec.body || null,
                query_params: probeSpec.query_params || null,
                expectation: probeSpec.expectation,
            },
            response: {
                status:  httpResponse.status,
                headers: httpResponse.headers,
                // Truncate body to 2000 chars — enough for triage, not a data dump
                body:    typeof httpResponse.data === 'string'
                    ? httpResponse.data.substring(0, 2000)
                    : JSON.stringify(httpResponse.data).substring(0, 2000),
            },
            ai_reasoning:  extra.ai_reasoning ?? null,
            evidence_cited: extra.evidence_cited ?? null,
        };
    }

    // -------------------------------------------------------------------------
    // Execute an AI-synthesized probe (new path)
    // -------------------------------------------------------------------------
    async _runAiProbe(checklistItem, endpoint, resolvedPath) {
        const checkName = `checklist/${checklistItem.id}`;

        // 1. Synthesize probe spec (cache-aware, throws InfrastructureError if AI unreachable).
        // The prompt is given the already-resolved path (real harvested IDs baked in) so the
        // AI isn't left to invent its own concrete value for {{booking_id}}-style variables —
        // inventing one independently is exactly how the AI-probe engine and the deterministic
        // engine ended up testing two different URLs for "the same" endpoint. The cache key
        // still hashes the endpoint's original template path (see cache.js), so a harvested ID
        // changing between runs doesn't invalidate cached applicability/probe decisions.
        const probeSpec = await synthesizeProbe(checklistItem, endpoint, this._cache, resolvedPath);

        if (!probeSpec) {
            // Synthesizer returned null — incompatible combo, emit N/A
            this.context.addResult(this._normalizeResult(checkName, endpoint, {
                status:  'N/A',
                message: `Probe synthesis determined this test is not applicable to ${endpoint.path}.`,
            }));
            logger.info(`[N/A] ${checkName}: Not applicable to ${endpoint.path}`);
            return;
        }

        // 2. Execute probe via the shared HTTP client
        let httpResponse;
        try {
            httpResponse = await this.client.request({
                method:  probeSpec.method,
                url:     probeSpec.path,
                headers: probeSpec.headers || {},
                data:    probeSpec.body    || undefined,
                params:  probeSpec.query_params || undefined,
            });
        } catch (err) {
            logger.warn(`[Engine] Probe execution failed for ${checkName}: ${err.message}`);
            this.context.addResult(this._normalizeResult(checkName, endpoint, {
                status:  'TO BE CONFIRMED',
                message: `Probe execution error: ${err.message}`,
            }));
            return;
        }

        // 3. Deterministic short-circuits — decide these from the raw HTTP artifacts
        // before ever asking the AI to classify them, so the verdict for "the request
        // never reached the code under test" doesn't depend on what the AI would have
        // guessed (that dependency is exactly what caused the same 401 to come back as
        // FAILED on some endpoints and N/A on others). Also saves an AI call each time.
        if (httpResponse.status === 404) {
            this.context.addResult(this._normalizeResult(checkName, endpoint, {
                status:  'ROUTE_NOT_FOUND',
                message: `Probe request ${probeSpec.method} ${probeSpec.path} returned 404 — no route matched, so ${checklistItem.id} could not be meaningfully tested.`,
                evidence_trail: this._buildProbeEvidenceTrail(probeSpec, httpResponse),
            }));
            logger.warn(`[ROUTE_NOT_FOUND] ${checkName}: ${probeSpec.method} ${probeSpec.path} → 404`);
            return;
        }

        const isAuthCheck = checklistItem.category === 'Authentication';
        if (!isAuthCheck && (httpResponse.status === 401 || httpResponse.status === 403)) {
            this.context.addResult(this._normalizeResult(checkName, endpoint, {
                status:  'AUTH_BLOCKED',
                message: `Probe request ${probeSpec.method} ${probeSpec.path} was blocked by auth (${httpResponse.status}) before ${checklistItem.id}'s logic could be exercised. This is a coverage gap, not a passing control — see the AUTH checklist items for whether auth enforcement itself is sound.`,
                evidence_trail: this._buildProbeEvidenceTrail(probeSpec, httpResponse),
            }));
            logger.warn(`[AUTH_BLOCKED] ${checkName}: ${probeSpec.method} ${probeSpec.path} → ${httpResponse.status}`);
            return;
        }

        // 4. Classify verdict (throws InfrastructureError if AI unreachable)
        const verdict = await classifyVerdict(probeSpec, httpResponse);
        const normalized = this._normalizeResult(checkName, endpoint, {
            ...verdict,
            evidence_trail: this._buildProbeEvidenceTrail(probeSpec, httpResponse, verdict),
        });
        this._applyGuardrail(normalized, checkName);
        this.context.addResult(normalized);
        this._logResult(normalized);
    }

    // -------------------------------------------------------------------------
    // Console logger
    // -------------------------------------------------------------------------
    _logResult(r) {
        const label = `[${r.status}] ${r.check}`;
        if (isFail(r.status)) {
            logger.error(`${label}: ${r.message}`);
        } else if (r.status === 'PASS') {
            logger.success(`${label}`);
        } else if (r.status === 'N/A') {
            logger.info(`${label}: ${r.message}`);
        } else {
            // MANUAL / TO BE CONFIRMED / AUTH_BLOCKED / ROUTE_NOT_FOUND / ENDPOINT_UNHEALTHY / UNRESOLVED_PATH
            logger.warn(`${label}: ${r.message}`);
        }
    }

    // -------------------------------------------------------------------------
    // Per-endpoint gate: one baseline request to find out, before spending any
    // checklist item's request/AI call, whether this endpoint is even reachable
    // (not a 404) and healthy (not 5xx). Reused for both the per-endpoint skip
    // decision and the whole-scan preflight abort below.
    // -------------------------------------------------------------------------
    async _probeEndpointGate(endpoint, resolvedPath) {
        const method = endpoint.methods?.includes('GET') ? 'GET' : (endpoint.methods?.[0] || 'GET');
        try {
            const response = await this.client.request({ method, url: resolvedPath });
            if (response.status === 404) {
                return {
                    status:  'ROUTE_NOT_FOUND',
                    message: `Baseline ${method} ${resolvedPath} returned 404 — no route matched. Checks that require a real request were skipped; see discovery/endpointDiscovery for confirmation and authentication/authRequired for what could still be evaluated.`,
                };
            }
            if (response.status >= 500) {
                return {
                    status:  'ENDPOINT_UNHEALTHY',
                    message: `Baseline ${method} ${resolvedPath} returned ${response.status} — the endpoint is erroring. Downstream checks that depend on normal behaviour were skipped as unreliable; see errorHandling/stackTrace for the underlying failure.`,
                };
            }
            return null; // healthy, route matched
        } catch (err) {
            return {
                status:  'ENDPOINT_UNHEALTHY',
                message: `Baseline probe ${method} ${resolvedPath} failed: ${err.message}. Downstream checks were skipped as unreliable.`,
            };
        }
    }

    // -------------------------------------------------------------------------
    // Compute gates for every REST endpoint up front (one request each), so the
    // main loop never re-probes and so the whole-scan preflight below can look
    // at every endpoint's outcome before any checklist item runs.
    // -------------------------------------------------------------------------
    async _computeEndpointGates() {
        const gates = new Map();
        for (const endpoint of this.context.endpoints) {
            if ((endpoint.protocol || 'rest') !== 'rest') continue;

            const resolvedPath = this.context.resolvePath(endpoint.path);
            if (this.context.hasUnresolvedVariables(endpoint.path)) {
                gates.set(endpoint, {
                    status:  'UNRESOLVED_PATH',
                    message: `Path still contains an unresolved template variable after resolution (resolved to "${resolvedPath}") — no request was sent. Populate the missing variable (e.g. via discovery, or manually with the matching {{name}}) and re-run.`,
                });
                continue;
            }

            gates.set(endpoint, await this._probeEndpointGate(endpoint, resolvedPath));
        }
        return gates;
    }

    // -------------------------------------------------------------------------
    // Cheap whole-scan sanity check: if literally every REST endpoint came back
    // 404, that's not 306 individual findings, it's one misconfiguration (wrong
    // --base-url, or a path template that never resolved) — abort immediately
    // instead of burning the full checklist against a target that was never
    // actually reached.
    // -------------------------------------------------------------------------
    _preflightCheck(gates) {
        const restGateResults = [...gates.values()];
        if (restGateResults.length === 0) return;

        const allRouteNotFound = restGateResults.every(g => g?.status === 'ROUTE_NOT_FOUND');
        if (allRouteNotFound) {
            throw new InfrastructureError(
                `Preflight check failed: every REST endpoint in this scan (${restGateResults.length}) returned 404 on a baseline request. ` +
                `This almost always means --base-url is wrong, or a path template (e.g. {{base_url}}, {{id}}) never resolved. ` +
                `Aborting before running the full checklist against a target that was never actually reached — fix the base URL/path templates and re-run.`
            );
        }
    }

    // -------------------------------------------------------------------------
    // Main run loop
    // -------------------------------------------------------------------------
    async run() {
        logger.title('Starting APInspect Scan...');
        logger.info(`Target: ${this.context.baseUrl}`);

        try {
            if (this._checklistMode) {
                this._endpointGates = await this._computeEndpointGates();
                this._preflightCheck(this._endpointGates);
            }
            await this._runEndpoints();
        } finally {
            // Persist whatever got cached even if an InfrastructureError aborted the
            // scan partway through — otherwise every applicability decision and probe
            // spec synthesized before the abort is thrown away, and the next attempt
            // (even with --cache committed) starts from zero instead of resuming.
            if (this._cache) this._cache.save();
        }

        logger.title('\nScan Complete.');
        return this.context.getResults();
    }

    async _runEndpoints() {
        for (const endpoint of this.context.endpoints) {
            logger.subTitle(`\nTesting Endpoint: ${endpoint.path} [${endpoint.methods.join(', ')}]`);

            // ---------------------------------------------------------------
            // CHECKLIST MODE — driven by checklist.json + AI applicability
            // ---------------------------------------------------------------
            if (this._checklistMode) {
                const endpointProtocol = endpoint.protocol || 'rest';
                const gate = this._endpointGates?.get(endpoint) || null;

                // 0. Cheaply exclude items tagged for a different protocol before spending
                // an AI call on applicability — e.g. GraphQL-only items on a REST endpoint.
                const protocolRelevantItems = checklist.filter(
                    item => !item.applies_to || item.applies_to.includes(endpointProtocol)
                );
                for (const item of checklist) {
                    if (item.applies_to && !item.applies_to.includes(endpointProtocol)) {
                        this.context.addResult(this._normalizeResult(
                            `checklist/${item.id}`, endpoint, {
                                status:  'N/A',
                                message: `Not applicable to protocol "${endpointProtocol}".`,
                            }
                        ));
                    }
                }

                // 0b. Endpoint is gated (unresolved path template, 404, or 5xx on the
                // baseline probe) — don't even spend the applicability AI call. Whether
                // "DISC-01 applies to this endpoint" is not in question here; what's in
                // question is whether the request could be meaningfully sent at all, and
                // the gate already answered that. Only the small set of checks whose job
                // IS to characterize reachability/auth/headers/errors still run for real
                // (skipped too for UNRESOLVED_PATH, where no request can be sent at all).
                if (gate) {
                    for (const item of protocolRelevantItems) {
                        if (gate.status !== 'UNRESOLVED_PATH' && GATE_EXEMPT_CHECKS.has(item.id) && item.maps_to_check && checksRegistry[item.maps_to_check]) {
                            try {
                                await this._runHardcodedCheck(
                                    { name: `checklist/${item.id}`, run: checksRegistry[item.maps_to_check] },
                                    endpoint
                                );
                            } catch (err) {
                                if (err.name === 'InfrastructureError') throw err;
                                logger.error(`[Engine] Error processing ${item.id} on ${endpoint.path}: ${err.message}`);
                            }
                        } else {
                            this.context.addResult(this._normalizeResult(`checklist/${item.id}`, endpoint, gate));
                        }
                    }
                    logger.warn(`[${gate.status}] ${endpoint.path}: ${gate.message}`);
                    continue;
                }

                // 1. Ask the applicability engine which items apply to this endpoint
                // (pass the persistent cache through — without it, applicability decisions
                // never survive past the in-process session Map, so every fresh invocation
                // re-spends one AI call per endpoint even with --cache committed).
                const applicability = await getApplicableItems(endpoint, protocolRelevantItems, this._cache);
                const applicableSet = new Set(applicability.applicable_ids);

                for (const item of protocolRelevantItems) {
                    if (!applicableSet.has(item.id)) {
                        // Emit N/A for excluded items so the report is complete
                        this.context.addResult(this._normalizeResult(
                            `checklist/${item.id}`, endpoint, {
                                status:  'N/A',
                                message: `Not applicable to this endpoint (filtered by applicability engine).`,
                            }
                        ));
                        continue;
                    }

                    try {
                        if (item.maps_to_check && checksRegistry[item.maps_to_check]) {
                            // Branch A: hardcoded module exists → run it directly
                            await this._runHardcodedCheck(
                                { name: `checklist/${item.id}`, run: checksRegistry[item.maps_to_check] },
                                endpoint
                            );
                        } else if (item.requires_ai_probe) {
                            if (item.requires_auth_session && !this.context.auth) {
                                // Narrow precondition gate: BOLA, mass assignment, and
                                // post-auth data-exposure checks are untestable without a
                                // real session — the docs already say so (see
                                // docs/APINSPECT-PIPELINE-SETUP.md). Skip the AI call
                                // entirely rather than spending a synthesize+classify pass
                                // to learn what we already know: MANUAL.
                                this.context.addResult(this._normalizeResult(
                                    `checklist/${item.id}`, endpoint, {
                                        status:  'MANUAL',
                                        message: `Requires an authenticated session to test meaningfully — no auth configured for this scan (-t/-u/-p/--auth-file).`,
                                    }
                                ));
                                logger.warn(`[MANUAL] checklist/${item.id}: No auth session — skipped without spending an AI call.`);
                            } else {
                                // Branch B: judgment-call item → synthesize + execute + classify
                                const resolvedPath = this.context.resolvePath(endpoint.path);
                                await this._runAiProbe(item, endpoint, resolvedPath);
                            }
                        } else {
                            logger.warn(`[Engine] Checklist item ${item.id} has no handler — skipping.`);
                        }
                    } catch (err) {
                        // Re-throw infrastructure errors to abort the scan immediately
                        if (err.name === 'InfrastructureError') throw err;
                        logger.error(`[Engine] Error processing ${item.id} on ${endpoint.path}: ${err.message}`);
                    }
                }

            // ---------------------------------------------------------------
            // LEGACY MODE — flat list of hardcoded checks (unchanged behaviour)
            // ---------------------------------------------------------------
            } else {
                for (const check of this.checks) {
                    if (!legacyCheckAppliesTo(check.name, endpoint.protocol)) continue;
                    try {
                        await this._runHardcodedCheck(check, endpoint);
                    } catch (err) {
                        logger.error(`Check ${check.name} threw an error: ${err.message}`);
                    }
                }
            }
        }
    }
}

module.exports = Engine;
