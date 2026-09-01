/**
 * src/core/checks/index.js
 *
 * The declarative path's check registry — every check ID apinspect.config.yaml
 * can reference. runner.js looks up by ID here; it never chooses which checks
 * to run, only executes the ones the config already named.
 */
module.exports = {
    API1_BOLA: require('./API1_BOLA'),
    API2_BROKEN_AUTH: require('./API2_BROKEN_AUTH'),
    API3_BOPLA: require('./API3_BOPLA'),
    API4_RATE_LIMIT: require('./API4_RATE_LIMIT'),
    API5_BFLA: require('./API5_BFLA'),
    API8_MISCONFIG: require('./API8_MISCONFIG'),
    API8_2019_INJECTION: require('./API8_2019_INJECTION'),
};
