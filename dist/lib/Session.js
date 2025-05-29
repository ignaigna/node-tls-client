"use strict";
var __decorate = (this && this.__decorate) || function (decorators, target, key, desc) {
    var c = arguments.length, r = c < 3 ? target : desc === null ? desc = Object.getOwnPropertyDescriptor(target, key) : desc, d;
    if (typeof Reflect === "object" && typeof Reflect.decorate === "function") r = Reflect.decorate(decorators, target, key, desc);
    else for (var i = decorators.length - 1; i >= 0; i--) if (d = decorators[i]) r = (c < 3 ? d(r) : c > 3 ? d(target, key, r) : d(target, key)) || r;
    return c > 3 && r && Object.defineProperty(target, key, r), r;
};
var __metadata = (this && this.__metadata) || function (k, v) {
    if (typeof Reflect === "object" && typeof Reflect.metadata === "function") return Reflect.metadata(k, v);
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.Session = void 0;
const crypto_1 = require("crypto");
const session_1 = require("../interface/session");
const utils_1 = require("../utils");
const decorators_1 = require("../decorators");
const _1 = require(".");
const __version__ = "1.0.0";
class Session {
    sessionId;
    proxy;
    isRotatingProxy;
    clientIdentifier;
    ja3string;
    h2Settings;
    h2SettingsOrder;
    supportedSignatureAlgorithms;
    supportedVersions;
    keyShareCurves;
    certCompressionAlgo;
    pseudoHeaderOrder;
    connectionFlow;
    priorityFrames;
    headerOrder;
    headerPriority;
    randomTlsExtensionOrder;
    forceHttp1;
    debug;
    insecureSkipVerify;
    headers;
    alpnProtocols;
    alpsProtocols;
    timeout;
    disableIPV6;
    disableIPV4;
    jar;
    client;
    isReady = false;
    constructor(options) {
        this.sessionId = (0, crypto_1.randomUUID)();
        this.proxy = options?.proxy || null;
        this.isRotatingProxy = options?.isRotatingProxy ?? false;
        this.alpnProtocols = options?.alpnProtocols || ["h2", "http/1.1"];
        this.alpsProtocols = options?.alpsProtocols || ["http/1.1"];
        this.headers = options?.headers || {
            "User-Agent": `tls-client/${__version__}`,
            "Accept-Encoding": "gzip, deflate, br",
            Accept: "*/*",
            Connection: "keep-alive",
        };
        this.clientIdentifier = options?.clientIdentifier;
        this.ja3string = options?.ja3string;
        this.h2Settings = options?.h2Settings;
        this.h2SettingsOrder = options?.h2SettingsOrder;
        this.supportedSignatureAlgorithms = options?.supportedSignatureAlgorithms;
        this.supportedVersions = options?.supportedVersions;
        this.keyShareCurves = options?.keyShareCurves;
        this.certCompressionAlgo = options?.certCompressionAlgo;
        this.pseudoHeaderOrder = options?.pseudoHeaderOrder;
        this.connectionFlow = options?.connectionFlow;
        this.priorityFrames = options?.priorityFrames;
        this.headerPriority = options?.headerPriority;
        this.randomTlsExtensionOrder = options?.randomTlsExtensionOrder || false;
        this.forceHttp1 = options?.forceHttp1 || false;
        this.debug = options?.debug || false;
        this.insecureSkipVerify = options?.insecureSkipVerify || false;
        this.timeout = options?.timeout || 30 * 1000;
        this.disableIPV4 = options?.disableIPV4 ?? false;
        this.disableIPV6 = options?.disableIPV6 ?? false;
        if (options?.cookieJar) {
            if (options.cookieJar instanceof _1.Cookies) {
                this.jar = options.cookieJar;
            }
            else {
                this.jar = new _1.Cookies();
                const serialized = options.cookieJar.serializeSync();
                if (serialized?.cookies) {
                    for (const cookie of serialized.cookies) {
                        if (cookie.domain && cookie.path && cookie.key && cookie.value) {
                            const url = `https://${cookie.domain}${cookie.path}`;
                            this.jar.setCookieSync(`${cookie.key}=${cookie.value}`, url);
                        }
                    }
                }
            }
        }
        else {
            this.jar = new _1.Cookies();
        }
        this.client = new _1.Client();
    }
    async init() {
        if (this.isReady)
            return true;
        try {
            await this.client.init();
            this.isReady = true;
            return true;
        }
        catch (error) {
            console.error("Initialization error:", error);
            throw new utils_1.TlsClientError(error);
        }
    }
    /**
     * Retrieves all cookies from the jar.
     *
     * @returns An object where keys are URLs and values are objects containing cookies as key-value pairs.
     *
     * @example
      {
         "https://example.com/": {
           "cookie1": "value1",
           "cookie2": "value2"
         },
         "https://anotherdomain.com/": {
           "cookieA": "valueA",
           "cookieB": "valueB"
         }
      }
     */
    get cookies() {
        return this.jar.fetchAllCookies();
    } /**
     * The 'close' method closes the current session.
     */
    async close() {
        const payload = JSON.stringify({
            sessionId: this.sessionId,
        });
        const response = await this.client.destroySession(payload);
        return response;
    }
    /**
     * The 'get' method performs a GET request to the provided URL with the provided options.
     *
     * @param url - The URL to perform the GET request to.
     * @param options - The options for the GET request.
     *
     * @returns The response from the 'execute' method.
     */
    get(url, options) {
        return this.execute("GET", url, {
            headers: options?.headers,
            redirect: options?.redirect,
            additionalDecode: options?.additionalDecode || false,
            proxy: options?.proxy,
            cookies: options?.cookies,
            byteResponse: options?.byteResponse || false,
            hostOverride: options?.hostOverride || null,
            ...options,
        });
    }
    /**
     * The 'delete' method performs a DELETE request to the provided URL with the provided options.
     *
     * @param url - The URL to perform the DELETE request to.
     * @param options - The options for the DELETE request.
     *
     * @returns The response from the 'execute' method.
     */
    delete(url, options) {
        return this.execute("DELETE", url, {
            headers: options?.headers,
            redirect: options?.redirect,
            additionalDecode: options?.additionalDecode || false,
            proxy: options?.proxy,
            cookies: options?.cookies,
            byteResponse: options?.byteResponse || false,
            hostOverride: options?.hostOverride || null,
            ...options,
        });
    }
    /**
     * The 'options' method performs an OPTIONS request to the provided URL with the provided options.
     *
     * @param url - The URL to perform the OPTIONS request to.
     * @param options - The options for the OPTIONS request.
     *
     * @returns The response from the 'execute' method.
     */
    options(url, options) {
        return this.execute("OPTIONS", url, {
            headers: options?.headers,
            redirect: options?.redirect,
            additionalDecode: options?.additionalDecode || false,
            proxy: options?.proxy,
            cookies: options?.cookies,
            hostOverride: options?.hostOverride || null,
            ...options,
        });
    }
    /**
     * The 'head' method performs a HEAD request to the provided URL with the provided options.
     *
     * @param url - The URL to perform the HEAD request to.
     * @param options - The options for the HEAD request.
     *
     * @returns The response from the 'execute' method.
     */
    head(url, options) {
        return this.execute("HEAD", url, {
            headers: options?.headers,
            redirect: options?.redirect,
            additionalDecode: options?.additionalDecode || false,
            proxy: options?.proxy,
            cookies: options?.cookies,
            hostOverride: options?.hostOverride || null,
            ...options,
        });
    }
    /**
     * The 'post' method performs a POST request to the provided URL with the provided options.
     *
     * @param url - The URL to perform the POST request to.
     * @param options - The options for the POST request.
     *
     * @returns The response from the 'execute' method.
     */
    post(url, options) {
        return this.execute("POST", url, {
            body: options?.body,
            headers: options?.headers,
            redirect: options?.redirect,
            additionalDecode: options?.additionalDecode || false,
            proxy: options?.proxy,
            cookies: options?.cookies,
            byteResponse: options?.byteResponse || false,
            hostOverride: options?.hostOverride || null,
            ...options,
        });
    }
    /**
     * The 'patch' method performs a PATCH request to the provided URL with the provided options.
     *
     * @param url - The URL to perform the PATCH request to.
     * @param options - The options for the PATCH request.
     *
     * @returns The response from the 'execute' method.
     */
    patch(url, options) {
        return this.execute("PATCH", url, {
            body: options?.body,
            headers: options?.headers,
            redirect: options?.redirect,
            additionalDecode: options?.additionalDecode || false,
            proxy: options?.proxy,
            cookies: options?.cookies,
            byteResponse: options?.byteResponse || false,
            hostOverride: options?.hostOverride || null,
            ...options,
        });
    }
    /**
     * The 'put' method performs a PUT request to the provided URL with the provided options.
     *
     * @param url - The URL to perform the PUT request to.
     * @param options - The options for the PUT request.
     *
     * @returns The response from the 'execute' method.
     */
    put(url, options) {
        return this.execute("PUT", url, {
            body: options?.body,
            headers: options?.headers,
            redirect: options?.redirect,
            additionalDecode: options?.additionalDecode || false,
            proxy: options?.proxy,
            cookies: options?.cookies,
            byteResponse: options?.byteResponse || false,
            hostOverride: options?.hostOverride || null,
            ...options,
        });
    }
    /**
     * The 'execute' method performs a HTTP request of the provided method to the provided URL with the provided options.
     *
     * @param method - The HTTP method of the request.
     * @param url - The URL to perform the request to.
     * @param options - The options for the request.
     *
     * @returns A new Response object.
     */
    async execute(method, url, options) {
        let headers = options?.headers ? options?.headers : this.headers;
        let requestCookies = [];
        if (options?.cookies) {
            requestCookies = this.jar.mergeCookies(options.cookies, url);
        }
        let skeletonPayload = {
            sessionId: this.sessionId,
            followRedirects: options?.redirect || false,
            forceHttp1: this.forceHttp1,
            withDebug: this.debug,
            headers,
            headerOrder: this.headerOrder,
            insecureSkipVerify: this.insecureSkipVerify,
            additionalDecode: options?.additionalDecode,
            proxyUrl: options?.proxy || this.proxy,
            requestUrl: url,
            requestMethod: method,
            requestBody: options?.body || null,
            requestCookies: requestCookies,
            timeoutMilliseconds: this.timeout || null,
            withRandomTLSExtensionOrder: this.randomTlsExtensionOrder,
            isByteResponse: options?.byteResponse,
            isByteRequest: (0, utils_1.isByteRequest)(headers),
            requestHostOverride: options?.hostOverride,
            disableIPV6: this.disableIPV6,
            disableIPV4: this.disableIPV4,
            isRotatingProxy: options?.isRotatingProxy ?? this.isRotatingProxy,
        };
        if (this.clientIdentifier) {
            skeletonPayload["tlsClientIdentifier"] = this.clientIdentifier;
        }
        else if (this.ja3string) {
            skeletonPayload["customTlsClient"] = {
                ja3String: this.ja3string,
                h2Settings: this.h2Settings,
                h2SettingsOrder: this.h2SettingsOrder,
                pseudoHeaderOrder: this.pseudoHeaderOrder,
                connectionFlow: this.connectionFlow,
                priorityFrames: this.priorityFrames,
                headerPriority: this.headerPriority,
                certCompressionAlgo: this.certCompressionAlgo,
                supportedVersions: this.supportedVersions,
                supportedSignatureAlgorithms: this.supportedSignatureAlgorithms,
                keyShareCurves: this.keyShareCurves,
                alpnProtocols: this.alpnProtocols,
                alpsProtocols: this.alpsProtocols,
            };
        }
        else
            skeletonPayload["tlsClientIdentifier"] = session_1.ClientIdentifier.chrome_131;
        const requestPayloadString = JSON.stringify(skeletonPayload);
        let res = await this.client.request(requestPayloadString);
        let cookies = this.jar.syncCookies(res?.cookies, url);
        await this.client.freeMemory(res.id);
        return new _1.Response({ ...res, cookies });
    }
}
exports.Session = Session;
__decorate([
    (0, decorators_1.verifyClientState)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", []),
    __metadata("design:returntype", Promise)
], Session.prototype, "close", null);
__decorate([
    (0, decorators_1.verifyClientState)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", void 0)
], Session.prototype, "get", null);
__decorate([
    (0, decorators_1.verifyClientState)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", void 0)
], Session.prototype, "delete", null);
__decorate([
    (0, decorators_1.verifyClientState)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", void 0)
], Session.prototype, "options", null);
__decorate([
    (0, decorators_1.verifyClientState)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", void 0)
], Session.prototype, "head", null);
__decorate([
    (0, decorators_1.verifyClientState)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", void 0)
], Session.prototype, "post", null);
__decorate([
    (0, decorators_1.verifyClientState)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", void 0)
], Session.prototype, "patch", null);
__decorate([
    (0, decorators_1.verifyClientState)(),
    __metadata("design:type", Function),
    __metadata("design:paramtypes", [String, Object]),
    __metadata("design:returntype", void 0)
], Session.prototype, "put", null);
