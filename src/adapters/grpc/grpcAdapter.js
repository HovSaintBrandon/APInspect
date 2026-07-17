const path = require('path');
const protoLoader = require('@grpc/proto-loader');
const grpc = require('@grpc/grpc-js');
const logger = require('../../utils/logger');
const { toHttpStatus, toStatusName } = require('./grpcStatusMap');

const isProtoFile = (filePath) => path.extname(filePath).toLowerCase() === '.proto';

// Walk a loaded package definition's namespace (e.g. `pkg.sub.Service`) to find the
// generated service constructor.
const resolveServiceConstructor = (protoDescriptor, fullServiceName) => {
    const parts = fullServiceName.split('.');
    let node = protoDescriptor;
    for (const part of parts) {
        if (!node || !node[part]) return null;
        node = node[part];
    }
    return node;
};

// Recursively walk a proto-loader package definition tree to find every Service definition,
// tracking its fully-qualified name (e.g. "myapp.v1.UserService").
const findServices = (node, prefix = []) => {
    const services = [];
    for (const [key, value] of Object.entries(node)) {
        if (!value) continue;
        if (typeof value === 'function' && value.service) {
            services.push({ fullName: [...prefix, key].join('.'), definition: value.service });
        } else if (typeof value === 'object') {
            services.push(...findServices(value, [...prefix, key]));
        }
    }
    return services;
};

/**
 * Discover gRPC services/RPCs from a .proto file.
 * @param {string} protoPath - Path to the .proto file.
 * @param {string|null} target - "host:port" of the gRPC server to scan.
 * @returns {Promise<{base_url: string, endpoints: Array, protocol: string, meta: object}>}
 */
const discover = async (protoPath, target = null) => {
    if (!target) {
        throw new Error('A gRPC target ("host:port") is required. Pass one with -b/--base-url.');
    }

    const absolutePath = path.resolve(protoPath);
    const packageDefinition = await protoLoader.load(absolutePath, {
        keepCase: true,
        longs: String,
        enums: String,
        defaults: true,
        oneofs: true,
    });
    const protoDescriptor = grpc.loadPackageDefinition(packageDefinition);
    const services = findServices(protoDescriptor);

    const endpoints = [];
    for (const service of services) {
        for (const [methodName, methodDef] of Object.entries(service.definition)) {
            endpoints.push({
                path: `/${service.fullName}/${methodName}`,
                methods: ['RPC'],
                protocol: 'grpc',
                originalName: `${service.fullName}.${methodName}`,
                schema: {
                    requestType: methodDef.requestType && methodDef.requestType.type && methodDef.requestType.type.name,
                    responseType: methodDef.responseType && methodDef.responseType.type && methodDef.responseType.type.name,
                    requestStream: !!methodDef.requestStream,
                    responseStream: !!methodDef.responseStream,
                },
            });
        }
    }

    logger.info(`Extracted ${endpoints.length} gRPC methods from ${services.length} service(s).`);

    return {
        base_url: target,
        endpoints,
        protocol: 'grpc',
        meta: { protoPath: absolutePath, target },
    };
};

// Cache of built grpc.Client instances, keyed by "target|serviceFullName", so we don't
// rebuild a client per-call.
const buildClientFactory = (config) => {
    const { protoPath, target } = config.meta || {};
    const packageDefinition = protoLoader.loadSync(protoPath, {
        keepCase: true, longs: String, enums: String, defaults: true, oneofs: true,
    });
    const protoDescriptor = grpc.loadPackageDefinition(packageDefinition);
    const clientCache = new Map();

    return (serviceFullName) => {
        if (clientCache.has(serviceFullName)) return clientCache.get(serviceFullName);

        const ServiceCtor = resolveServiceConstructor(protoDescriptor, serviceFullName);
        if (!ServiceCtor) {
            throw new Error(`gRPC service "${serviceFullName}" not found in loaded proto definition.`);
        }

        const credentials = config.grpcInsecure === false
            ? grpc.credentials.createSsl()
            : grpc.credentials.createInsecure();

        const client = new ServiceCtor(target, credentials);
        clientCache.set(serviceFullName, client);
        return client;
    };
};

/**
 * Build an axios-shaped client facade over a dynamic gRPC client, so existing HTTP-oriented
 * check modules (which call `client.request({method, url, headers, data})` and inspect
 * `response.status` / `error.response.status`) work against gRPC unmodified.
 */
const createClient = (config) => {
    const getServiceClient = buildClientFactory(config);

    const request = ({ url, headers = {}, data = {} }) => {
        // url is "/pkg.Service/Method"
        const parts = url.split('/').filter(Boolean);
        const methodName = parts.pop();
        const serviceFullName = parts.join('.');

        const client = getServiceClient(serviceFullName);
        const metadata = new grpc.Metadata();
        for (const [key, value] of Object.entries(headers)) {
            if (value !== undefined && value !== null) metadata.set(key.toLowerCase(), String(value));
        }

        return new Promise((resolve, reject) => {
            const deadline = new Date(Date.now() + 5000);
            client[methodName](data, metadata, { deadline }, (err, response) => {
                if (err) {
                    const httpStatus = toHttpStatus(err.code);
                    const facadeError = new Error(err.details || err.message);
                    facadeError.response = {
                        status: httpStatus,
                        data: { grpc_code: err.code, grpc_status: toStatusName(err.code), message: err.details },
                        headers: {},
                    };
                    reject(facadeError);
                    return;
                }
                resolve({ status: 200, data: response, headers: {} });
            });
        });
    };

    return { request };
};

module.exports = { discover, isProtoFile, createClient };
