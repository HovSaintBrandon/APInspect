const logger = require('../utils/logger');
const Context = require('./context');
const adapters = require('../adapters');
const { AI_CONFIDENCE_THRESHOLD, AI_FAIL_CONFIDENCE_THRESHOLD } = require('../config/aiConfig');
const { InfrastructureError } = require('../utils/errors');

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
            method:   (endpoint.methods && endpoint.methods[0]) || 'GET',
            status:   result.status,
            severity,
            confirmation_status: confirmationStatus,
            message:  result.message,
            details:  result.details,
            // AI-specific fields (undefined for rule-based checks)
            ai_confidence: result.ai_confidence,
            ai_reasoning:  result.ai_reasoning,
            evidence_cited: result.evidence_cited,
            // Evidence trail — populated by _runAiProbe, null for hardcoded checks
            evidence_trail: result.evidence_trail || null,
        };
    }

    // -------------------------------------------------------------------------
    // Confidence guardrail — applied centrally for all AI results
    // -------------------------------------------------------------------------
    _applyGuardrail(normalized, checkName) {
        if (normalized.ai_confidence === undefined) return normalized; // Not an AI check

        const isFail     = normalized.status === 'FAIL' || normalized.status === 'FAILED';
        const threshold  = isFail ? AI_FAIL_CONFIDENCE_THRESHOLD : AI_CONFIDENCE_THRESHOLD;

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
    // Execute a hardcoded check module (pre-existing path, unchanged behaviour)
    // -------------------------------------------------------------------------
    async _runHardcodedCheck(check, endpoint) {
        const result = await check.run(this.context, this.client, endpoint);
        if (!result) return;

        const normalized = this._normalizeResult(check.name, endpoint, result);
        this._applyGuardrail(normalized, check.name);
        this.context.addResult(normalized);
        this._logResult(normalized);
    }

    // -------------------------------------------------------------------------
    // Execute an AI-synthesized probe (new path)
    // -------------------------------------------------------------------------
    async _runAiProbe(checklistItem, endpoint) {
        const checkName = `checklist/${checklistItem.id}`;

        // 1. Synthesize probe spec (cache-aware, throws InfrastructureError if AI unreachable)
        const probeSpec = await synthesizeProbe(checklistItem, endpoint, this._cache);

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

        // 3. Classify verdict (throws InfrastructureError if AI unreachable)
        const verdict = await classifyVerdict(probeSpec, httpResponse);
        const normalized = this._normalizeResult(checkName, endpoint, {
            ...verdict,
            // Attach full evidence trail for triageability
            evidence_trail: {
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
                ai_reasoning:  verdict.ai_reasoning,
                evidence_cited: verdict.evidence_cited,
            },
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
        if (r.status === 'FAIL' || r.status === 'FAILED') {
            logger.error(`${label}: ${r.message}`);
        } else if (r.status === 'PASS') {
            logger.success(`${label}`);
        } else if (r.status === 'N/A') {
            logger.info(`${label}: ${r.message}`);
        } else {
            // MANUAL / TO BE CONFIRMED
            logger.warn(`${label}: ${r.message}`);
        }
    }

    // -------------------------------------------------------------------------
    // Main run loop
    // -------------------------------------------------------------------------
    async run() {
        logger.title('Starting APInspect Scan...');
        logger.info(`Target: ${this.context.baseUrl}`);

        for (const endpoint of this.context.endpoints) {
            logger.subTitle(`\nTesting Endpoint: ${endpoint.path} [${endpoint.methods.join(', ')}]`);

            // ---------------------------------------------------------------
            // CHECKLIST MODE — driven by checklist.json + AI applicability
            // ---------------------------------------------------------------
            if (this._checklistMode) {
                const endpointProtocol = endpoint.protocol || 'rest';

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

                // 1. Ask the applicability engine which items apply to this endpoint
                const applicability = await getApplicableItems(endpoint, protocolRelevantItems);
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
                            // Branch B: judgment-call item → synthesize + execute + classify
                            await this._runAiProbe(item, endpoint);
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
                        const result = await check.run(this.context, this.client, endpoint);

                        if (result) {
                            const normalized = this._normalizeResult(check.name, endpoint, result);
                            this._applyGuardrail(normalized, check.name);
                            this.context.addResult(normalized);
                            this._logResult(normalized);
                        }
                    } catch (err) {
                        logger.error(`Check ${check.name} threw an error: ${err.message}`);
                    }
                }
            }
        }

        logger.title('\nScan Complete.');

        // Persist cache if it was used
        if (this._cache) this._cache.save();

        return this.context.getResults();
    }
}

module.exports = Engine;
