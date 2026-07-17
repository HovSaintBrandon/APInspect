// gRPC analogue of authentication/authRequired.js — strips auth metadata (instead of an
// HTTP Authorization header) and confirms the server rejects the unauthenticated call.
module.exports = async (context, client, endpoint) => {
    if (!context.auth) {
        return {
            status: 'MANUAL',
            message: 'No auth configuration provided. Skipping gRPC metadata auth check.',
        };
    }

    try {
        await client.request({
            method: 'RPC',
            url: endpoint.path,
            headers: {}, // No authorization metadata attached
            data: {},
        });

        // Call succeeded without credentials — looks like it's publicly accessible.
        return {
            status: 'FAIL',
            message: `gRPC method ${endpoint.path} responded successfully without authentication metadata.`,
            details: { access: 'unauthenticated' },
        };
    } catch (error) {
        if (error.response) {
            const status = error.response.status;
            if (status === 401 || status === 403) {
                return {
                    status: 'PASS',
                    message: `gRPC method ${endpoint.path} correctly rejected an unauthenticated call (${error.response.data.grpc_status}).`,
                    details: { status, grpc_status: error.response.data.grpc_status },
                };
            }
            return {
                status: 'MANUAL',
                message: `gRPC method returned ${error.response.data.grpc_status} without auth metadata. Needs manual verification.`,
                details: { status, grpc_status: error.response.data.grpc_status },
            };
        }

        return {
            status: 'MANUAL',
            message: `Network error during gRPC auth check: ${error.message}`,
            details: { error: error.message },
        };
    }
};
