const logger = require('../utils/logger');
// We use a basic singularize fallback below

// Simple singularizer since we don't know if 'pluralize' is installed
const toSingular = (word) => {
    if (word.endsWith('ies')) return word.slice(0, -3) + 'y';
    if (word.endsWith('ses')) return word.slice(0, -2);
    if (word.endsWith('s') && !word.endsWith('ss')) return word.slice(0, -1);
    return word;
};

/**
 * Runs the initial discovery phase to harvest IDs and populate the Context Variable Store.
 * @param {Context} context - The APInspect context object
 * @param {AxiosInstance} client - The configured HTTP client
 */
const runDiscovery = async (context, client) => {
    logger.title('Phase 1: Discovery & Variable Harvesting');
    let harvestedCount = 0;

    for (const endpoint of context.endpoints) {
        // We only want to execute safe GET requests to list endpoints
        if (!endpoint.methods.includes('GET')) continue;

        const resolvedPath = context.resolveString(endpoint.path);

        // If the path STILL contains unresolved variables (e.g., {{id}}), we can't hit it yet.
        // It's a detail endpoint, not a list endpoint.
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
                }
            }
        } catch (err) {
            logger.warn(`[Discovery] Failed to ping ${resolvedPath}: ${err.message}`);
        }
    }

    if (harvestedCount === 0) {
        logger.info('[Discovery] No new variables were harvested.');
    } else {
        logger.info(`[Discovery] Successfully populated ${harvestedCount} variables into the Context Store.`);
    }
};

module.exports = { runDiscovery };
