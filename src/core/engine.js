const logger = require('../utils/logger');
const Context = require('./context');
const { createClient } = require('../utils/httpClient');
const { AI_CONFIDENCE_THRESHOLD, AI_FAIL_CONFIDENCE_THRESHOLD } = require('../config/aiConfig');

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
};

class Engine {
    constructor(config) {
        this.context = new Context(config);
        this.client  = createClient(config.base_url, this.context.getAuthHeaders(), 5000, this.context);
        // Legacy: flat list of hardcoded checks loaded via loadChecks()
        this.checks  = [];
        // Checklist-driven mode flag — enabled by loadChecklist()
        this._checklistMode = false;
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

        // 1. Synthesize probe spec
        const probeSpec = await synthesizeProbe(checklistItem, endpoint);

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

        // 3. Classify verdict
        const verdict = await classifyVerdict(probeSpec, httpResponse);
        const normalized = this._normalizeResult(checkName, endpoint, verdict);
        // Guardrail already applied inside verdictClassifier, but run again
        // centrally to keep the policy in one place.
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
                // 1. Ask the applicability engine which items apply to this endpoint
                const applicability = await getApplicableItems(endpoint, checklist);
                const applicableSet = new Set(applicability.applicable_ids);

                for (const item of checklist) {
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
                        logger.error(`[Engine] Error processing ${item.id} on ${endpoint.path}: ${err.message}`);
                    }
                }

            // ---------------------------------------------------------------
            // LEGACY MODE — flat list of hardcoded checks (unchanged behaviour)
            // ---------------------------------------------------------------
            } else {
                for (const check of this.checks) {
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
        return this.context.getResults();
    }
}

module.exports = Engine;
