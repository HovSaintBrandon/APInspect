const logger = require('../utils/logger');
// We use a basic singularize fallback below

// Field-name heuristic for "this looks like an entity identifier" — id/uuid/code/
// ref/number variants, in any casing or snake/camel form. Deliberately narrow: the
// goal is real cross-referenceable identifiers (health_id, contact_id, account_id),
// not every scalar field on a record.
const IDENTIFIER_KEY = /(^|_)(id|uuid|code|ref|number)$/i;

// Excluded even if it matches IDENTIFIER_KEY above — these are secret-shaped, not
// identifier-shaped, and harvested sample records get fed straight into AI probe
// prompts later, so a field like "otp_code" or "pin_number" must never end up there.
const SECRET_KEY = /password|secret|token|otp|pin|cvv|ssn/i;

// Pulls every identifier-shaped, non-secret scalar field off a harvested record —
// the reduced shape stored in Context#sampleRecords for cross-object probe synthesis.
// Returns null if nothing qualifies (e.g. the record's only "id"-like field is the
// resource's own primary key, already captured by the single-variable harvest above).
const extractIdentifierFields = (record) => {
    const fields = {};
    for (const [key, value] of Object.entries(record)) {
        if ((typeof value !== 'string' && typeof value !== 'number') || value === '') continue;
        if (!IDENTIFIER_KEY.test(key) || SECRET_KEY.test(key)) continue;
        fields[key] = value;
    }
    return Object.keys(fields).length > 0 ? fields : null;
};

// Simple singularizer since we don't know if 'pluralize' is installed
const toSingular = (word) => {
    if (word.endsWith('ies')) return word.slice(0, -3) + 'y';
    if (word.endsWith('ses')) return word.slice(0, -2);
    if (word.endsWith('s') && !word.endsWith('ss')) return word.slice(0, -1);
    return word;
};

// Separately from the single-variable harvest in _harvestPass (which only ever
// keeps one id for path substitution), also captures up to two DISTINCT array
// entries' full identifier-field sets. Two different array entries are, by
// construction, two different entities — exactly the "record A" / "record B"
// pair the AI probe layer needs to test cross-object identifier confusion
// (BOLA-01) with real, resolvable foreign IDs instead of guesses.
const _harvestSampleRecords = (context, targetArray, resolvedPath) => {
    for (const item of targetArray.slice(0, 2)) {
        if (!item || typeof item !== 'object') continue;
        const idFields = extractIdentifierFields(item);
        if (idFields) context.addSampleRecord(`GET ${resolvedPath}`, idFields);
    }
};

/**
 * One pass over every GET list-endpoint, harvesting one variable per endpoint
 * whose path is already fully resolved. Factored out of runDiscovery so it can
 * be repeated — a nested resource like /bookings/{{booking_id}}/sessions can't
 * be pinged until booking_id exists, which only happens once /bookings itself
 * has been harvested, so a single pass is order-dependent on how the spec lists
 * endpoints. Re-running until nothing new shows up removes that dependency.
 * @returns {Promise<number>} variables harvested this pass
 */
const _harvestPass = async (context, client) => {
    let harvestedCount = 0;

    for (const endpoint of context.endpoints) {
        // We only want to execute safe GET requests to list endpoints
        if (!endpoint.methods.includes('GET')) continue;

        const resolvedPath = context.resolvePath(endpoint.path);

        // If the path STILL contains unresolved variables (e.g., {{id}}), we can't hit it yet.
        // It's a detail endpoint, not a list endpoint — maybe next pass.
        if (resolvedPath.includes('{{')) {
            continue;
        }

        try {
            logger.info(`[Discovery] Pinging GET ${resolvedPath}...`);
            const response = await client.request({
                method: 'GET',
                url: resolvedPath,
                // Don't log full response to avoid noise
            });

            if (response.status >= 200 && response.status < 300 && response.data) {
                // Heuristic: Look for an array in the response to harvest an ID from
                let targetArray = null;
                
                if (Array.isArray(response.data)) {
                    targetArray = response.data;
                } else if (typeof response.data === 'object') {
                    // Search top-level keys for an array (e.g., { success: true, bookings: [...] })
                    for (const key of Object.keys(response.data)) {
                        if (Array.isArray(response.data[key]) && response.data[key].length > 0) {
                            targetArray = response.data[key];
                            break;
                        }
                    }
                }

                if (targetArray && targetArray.length > 0) {
                    const firstItem = targetArray[0];
                    if (firstItem && typeof firstItem === 'object') {
                        // Extract a potential ID
                        const idValue = firstItem._id || firstItem.id || firstItem.uuid || firstItem.code || firstItem.staffNumber || firstItem.idNumber;

                        if (idValue) {
                            // Derive variable name from path (e.g., /api/v2/bookings -> booking_id)
                            const segments = resolvedPath.split('/').filter(Boolean);
                            const lastSegment = segments[segments.length - 1];
                            const singular = toSingular(lastSegment);
                            const varName = `${singular}_id`;

                            // Only set if not already set manually
                            if (!context.getVariable(varName)) {
                                context.setVariable(varName, idValue);
                                logger.success(`[Discovery] Harvested ${varName} = ${idValue}`);
                                harvestedCount++;
                            }
                        }
                    }

                    _harvestSampleRecords(context, targetArray, resolvedPath);
                }
            }
        } catch (err) {
            logger.warn(`[Discovery] Failed to ping ${resolvedPath}: ${err.message}`);
        }
    }

    return harvestedCount;
};

// Bounded rather than "until convergence" — a spec with a genuine circular
// reference (A needs B's id, B needs A's id) would otherwise loop until every
// pass harvests 0, which it always eventually does, so this cap just bounds
// how many endpoint-deep a resolution chain can be before we give up.
const MAX_PASSES = 5;

/**
 * Runs the initial discovery phase to harvest IDs and populate the Context Variable Store.
 * @param {Context} context - The APInspect context object
 * @param {AxiosInstance} client - The configured HTTP client
 */
const runDiscovery = async (context, client) => {
    logger.title('Phase 1: Discovery & Variable Harvesting');
    let totalHarvested = 0;

    for (let pass = 0; pass < MAX_PASSES; pass++) {
        const harvestedThisPass = await _harvestPass(context, client);
        totalHarvested += harvestedThisPass;
        if (harvestedThisPass === 0) break;
    }

    if (totalHarvested === 0) {
        logger.info('[Discovery] No new variables were harvested.');
    } else {
        logger.info(`[Discovery] Successfully populated ${totalHarvested} variable(s) into the Context Store.`);
    }
};

module.exports = { runDiscovery };
