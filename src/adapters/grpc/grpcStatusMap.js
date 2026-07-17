// Maps gRPC status codes (grpc.status.*) to their closest HTTP-equivalent, so existing
// checks written against HTTP status codes (401/403/429/etc.) work unmodified against gRPC.
// https://grpc.github.io/grpc/core/md_doc_statuscodes.html
const GRPC_TO_HTTP = {
    0:  200, // OK
    1:  499, // CANCELLED
    2:  500, // UNKNOWN
    3:  400, // INVALID_ARGUMENT
    4:  504, // DEADLINE_EXCEEDED
    5:  404, // NOT_FOUND
    6:  409, // ALREADY_EXISTS
    7:  403, // PERMISSION_DENIED
    8:  429, // RESOURCE_EXHAUSTED
    9:  400, // FAILED_PRECONDITION
    10: 409, // ABORTED
    11: 400, // OUT_OF_RANGE
    12: 501, // UNIMPLEMENTED
    13: 500, // INTERNAL
    14: 503, // UNAVAILABLE
    15: 500, // DATA_LOSS
    16: 401, // UNAUTHENTICATED
};

const GRPC_STATUS_NAMES = {
    0: 'OK', 1: 'CANCELLED', 2: 'UNKNOWN', 3: 'INVALID_ARGUMENT', 4: 'DEADLINE_EXCEEDED',
    5: 'NOT_FOUND', 6: 'ALREADY_EXISTS', 7: 'PERMISSION_DENIED', 8: 'RESOURCE_EXHAUSTED',
    9: 'FAILED_PRECONDITION', 10: 'ABORTED', 11: 'OUT_OF_RANGE', 12: 'UNIMPLEMENTED',
    13: 'INTERNAL', 14: 'UNAVAILABLE', 15: 'DATA_LOSS', 16: 'UNAUTHENTICATED',
};

const toHttpStatus = (grpcCode) => GRPC_TO_HTTP[grpcCode] ?? 500;
const toStatusName = (grpcCode) => GRPC_STATUS_NAMES[grpcCode] || 'UNKNOWN';

module.exports = { toHttpStatus, toStatusName, GRPC_TO_HTTP, GRPC_STATUS_NAMES };
