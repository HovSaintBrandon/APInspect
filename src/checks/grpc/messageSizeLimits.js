// Full request-message-body size testing requires knowing the target message's field names
// (proto-loader silently drops unknown fields), which isn't available from the schema summary
// captured at discovery time. Instead, this probes at the transport level: gRPC metadata size
// is a common resource-exhaustion vector independent of any specific message schema — attach an
// oversized metadata value and confirm the server rejects it rather than allocating for it.
const OVERSIZED_VALUE = 'A'.repeat(1024 * 1024); // 1MB

module.exports = async (context, client, endpoint) => {
    if (context.getVariable('__grpcMsgSizeChecked')) {
        return null;
    }
    context.setVariable('__grpcMsgSizeChecked', true);

    try {
        await client.request({
            method: 'RPC',
            url: endpoint.path,
            headers: { 'x-apinspect-oversized-probe': OVERSIZED_VALUE },
            data: {},
        });
        return {
            status: 'FAIL',
            message: 'Server accepted a 1MB oversized gRPC metadata value with no rejection — no size limit detected (potential resource-exhaustion vector).',
            details: {},
        };
    } catch (error) {
        if (error.response && (error.response.status === 400 || error.response.status === 413)) {
            return {
                status: 'PASS',
                message: `Server rejected oversized metadata (${error.response.data.grpc_status}) — size limiting appears enforced.`,
                details: {},
            };
        }
        if (!error.response) {
            return {
                status: 'PASS',
                message: 'Oversized metadata caused a transport-level rejection — size limiting appears enforced.',
                details: {},
            };
        }
        return {
            status: 'MANUAL',
            message: `Oversized metadata probe returned an ambiguous result (${error.response.data.grpc_status}) — verify manually.`,
            details: {},
        };
    }
};
