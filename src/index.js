// Provide a programmatic export as well
const Engine = require('./core/engine');
const parser = require('./core/parser');

module.exports = {
    Engine,
    parser
};

// If executed directly (not common given CLI structure, but good for testing)
if (require.main === module) {
    require('./cli/index');
}
