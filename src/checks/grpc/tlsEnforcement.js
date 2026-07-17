// Verifies the server doesn't accept a plaintext (insecure) channel. The scan's own client
// connects insecure by default (config.grpcInsecure !== false) — if the call actually reaches
// the application layer (even an error response like NOT_FOUND), the plaintext channel was
// accepted. A transport-level failure (UNAVAILABLE with a connect/handshake failure) indicates
// the server refused the insecure connection, which is the desired posture.
module.exports = async (context, client, endpoint) => {
    if (context.getVariable('__grpcTlsChecked')) {
        return null;
    }
    context.setVariable('__grpcTlsChecked', true);

    try {
        await client.request({ method: 'RPC', url: endpoint.path, headers: {}, data: {} });
        return {
            status: 'FAIL',
            message: 'Server accepted a plaintext (insecure) gRPC connection — TLS is not enforced.',
            details: { channel: 'insecure' },
        };
    } catch (error) {
        if (error.response) {
            // We got as far as an application-level gRPC status — the insecure channel was accepted.
            return {
                status: 'FAIL',
                message: `Server accepted a plaintext gRPC connection (reached application layer with ${error.response.data.grpc_status}) — TLS is not enforced.`,
                details: { channel: 'insecure', grpc_status: error.response.data.grpc_status },
            };
        }

        const transportFailure = /connect|handshake|unavailable|ssl|tls/i.test(error.message || '');
        if (transportFailure) {
            return {
                status: 'PASS',
                message: 'Plaintext gRPC connection was rejected at the transport layer — TLS appears enforced.',
                details: {},
            };
        }

        return {
            status: 'MANUAL',
            message: `Could not determine TLS enforcement: ${error.message}`,
            details: { error: error.message },
        };
    }
};
