// Full reflection probing requires speaking the grpc.reflection.v1alpha.ServerReflection
// bidi-streaming protocol, which needs its own dynamically-built client independent of the
// target's .proto file. That's a heavier lift than a single unary check module can do safely,
// so this flags the item for manual verification with a concrete, actionable next step rather
// than faking a result — the same "declare scope, don't silently skip" approach used for
// streaming RPCs elsewhere in the gRPC adapter.
module.exports = async (context) => {
    // Reflection is a server-wide property, not per-method — only surface this once per scan.
    if (context.getVariable('__grpcReflectionChecked')) {
        return null;
    }
    context.setVariable('__grpcReflectionChecked', true);

    return {
        status: 'MANUAL',
        message: 'Automated reflection-service probing is not yet implemented. Verify manually with: ' +
            'grpcurl -plaintext <target> list — if this returns a service list, reflection is enabled ' +
            'and should be disabled in production.',
    };
};
