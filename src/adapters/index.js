const { createClient: createHttpClient } = require('../utils/httpClient');
const grpcAdapter = require('./grpc/grpcAdapter');

// Registry of transport factories per protocol. REST and GraphQL both run over plain HTTP
// and share the axios-based client; gRPC needs its own transport, wrapped in grpcAdapter to
// present the same axios-shaped facade (see grpcAdapter.js for why).
module.exports = {
    rest: {
        createClient: (config, context) => createHttpClient(config.base_url, { ...context.headers, ...context.getAuthHeaders() }, 5000, context),
    },
    graphql: {
        createClient: (config, context) => createHttpClient(config.base_url, { ...context.headers, ...context.getAuthHeaders() }, 5000, context),
    },
    grpc: {
        createClient: (config) => grpcAdapter.createClient(config),
    },
};
