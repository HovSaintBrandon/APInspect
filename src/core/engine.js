const logger = require('../utils/logger');
const Context = require('./context');
const { createClient } = require('../utils/httpClient');

// Registry of available checks
// In a real implementation, this could dynamically load from the defined directory
const checksRegistry = {
    'discovery/endpointDiscovery': require('../checks/discovery/endpointDiscovery'),
    'discovery/httpMethods': require('../checks/discovery/httpMethods'),
    'authentication/authRequired': require('../checks/authentication/authRequired'),
    'misconfigurations/cors': require('../checks/misconfigurations/cors'),
    'misconfigurations/securityHeaders': require('../checks/misconfigurations/securityHeaders'),
    'dataExposure/sensitiveData': require('../checks/dataExposure/sensitiveData'),
    'errorHandling/stackTrace': require('../checks/errorHandling/stackTrace'),
    'rateLimiting/bruteForce': require('../checks/rateLimiting/bruteForce'),
    'injection/sqliXss': require('../checks/injection/sqliXss'),
    'injection/pathTraversal': require('../checks/injection/pathTraversal'),
};

class Engine {
    constructor(config) {
        this.context = new Context(config);
        this.client = createClient(config.base_url, this.context.getAuthHeaders());
        this.checks = [];
    }

    loadChecks(checkNames = Object.keys(checksRegistry)) {
        checkNames.forEach(name => {
            if (checksRegistry[name]) {
                this.checks.push({ name, run: checksRegistry[name] });
            } else {
                logger.warn(`Check ${name} not found.`);
            }
        });
    }

    async run() {
        logger.title('Starting APInspect Scan...');
        logger.info(`Target: ${this.context.baseUrl}`);

        // Iterate over endpoints
        for (const endpoint of this.context.endpoints) {
            logger.subTitle(`Testing Endpoint: ${endpoint.path} [${endpoint.methods.join(', ')}]`);

            for (const check of this.checks) {
                try {
                    // logger.info(`Running check: ${check.name}`);
                    const result = await check.run(this.context, this.client, endpoint);

                    if (result) {
                        // Normalize result structure
                        const normalizedResult = {
                            check: check.name,
                            endpoint: endpoint.path,
                            method: endpoint.methods[0], // Simplified
                            status: result.status, // PASS, FAIL, MANUAL
                            message: result.message,
                            details: result.details
                        };

                        this.context.addResult(normalizedResult);

                        // Log immediate output
                        if (result.status === 'FAIL') {
                            logger.error(`[FAIL] ${check.name}: ${result.message}`);
                        } else if (result.status === 'PASS') {
                            logger.success(`[PASS] ${check.name}`);
                        } else {
                            logger.warn(`[MANUAL] ${check.name}: ${result.message}`);
                        }
                    }
                } catch (err) {
                    logger.error(`Check ${check.name} threw an error: ${err.message}`);
                }
            }
        }

        logger.title('Scan Complete.');
        return this.context.getResults();
    }
}

module.exports = Engine;
