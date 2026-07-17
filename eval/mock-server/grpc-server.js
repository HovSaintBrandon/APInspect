const path = require('path');
const grpc = require('@grpc/grpc-js');
const protoLoader = require('@grpc/proto-loader');

const packageDefinition = protoLoader.loadSync(path.join(__dirname, 'grpc-service.proto'), {
    keepCase: true, longs: String, enums: String, defaults: true, oneofs: true,
});
const proto = grpc.loadPackageDefinition(packageDefinition).mockapp;

// Intentionally vulnerable: returns user data regardless of whether auth metadata is present,
// mirroring the REST/GraphQL mock endpoints' "vulnerable by default" convention for eval fixtures.
const getUser = (call, callback) => {
    callback(null, { id: call.request.id, email: `user${call.request.id}@example.com`, role: 'admin' });
};

const server = new grpc.Server();
server.addService(proto.UserService.service, { GetUser: getUser });

const PORT = process.env.GRPC_MOCK_PORT || 50061;
server.bindAsync(`127.0.0.1:${PORT}`, grpc.ServerCredentials.createInsecure(), (err, boundPort) => {
    if (err) {
        console.error('Failed to bind gRPC server:', err);
        process.exit(1);
    }
    console.log(`Mock gRPC server running on port ${boundPort}`);
});
