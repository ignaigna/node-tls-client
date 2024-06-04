import { randomUUID } from "crypto";
import {
  sessionOptions,
  h2Settings,
  supportedSignatureAlgorithms,
  supportedVersions,
  pseudoHeaderOrder,
  priorityFrames,
  keyShareCurves,
  certCompressionAlgo,
  priorityParam,
  methods,
  requestOptions,
  GetRequestOptions,
  PostRequestOptions,
  PatchRequestOptions,
  PutRequestOptions,
  DeleteRequestOptions,
  OptionsRequestOptions,
  HeadRequestOptions,
} from "../interface";
import { koffiLoad } from "../interface/koffi";
import { IncomingHttpHeaders } from "http";
import { Cookies, Response } from ".";
import path from "path";
import fs from "fs";
import os from "os";
import { load } from "../utils/koffi";

// Version of the current session.
const __version__ = "1";

/**
 * Session class represents a HTTP session.
 * It provides methods to perform various HTTP requests.
 */
export class Session {
  private sessionId?: string;
  private proxy?: string;
  private clientIdentifier?: string;
  private ja3string?: string;
  private h2Settings?: h2Settings;
  private h2SettingsOrder?: (keyof h2Settings)[];
  private supportedSignatureAlgorithms?: supportedSignatureAlgorithms[];
  private supportedVersions?: supportedVersions[];
  private keyShareCurves?: keyShareCurves[];
  private certCompressionAlgo?: certCompressionAlgo;
  private pseudoHeaderOrder?: pseudoHeaderOrder[];
  private connectionFlow?: number;
  private priorityFrames?: priorityFrames[];
  private headerOrder?: string[];
  private headerPriority?: priorityParam;
  private randomTlsExtensionOrder?: boolean;
  private forceHttp1?: boolean;
  private debug?: boolean;
  private insecureSkipVerify?: boolean;
  private headers: IncomingHttpHeaders;
  private alpnProtocols?: string[];
  private alpsProtocols: string[];
  private jar: Cookies = new Cookies();
  private fetch: Promise<koffiLoad>;

  constructor(options?: sessionOptions) {
    this.fetch = load();

    this.sessionId = randomUUID();
    this.proxy = "";
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
    this.headerOrder = options?.headerOrder;
    this.headerPriority = options?.headerPriority;
    this.randomTlsExtensionOrder = options?.randomTlsExtensionOrder || false;
    this.forceHttp1 = options?.forceHttp1 || false;
    this.debug = options?.debug || false;
    this.insecureSkipVerify = options?.insecureSkipVerify || false;
  }

  /**
   * The 'close' method closes the current session.
   *
   * @returns The response from the 'destroySession' function.
   */
  public async close() {
    const payload = JSON.stringify({
      sessionId: this.sessionId,
    });

    const response = JSON.parse((await this.fetch).destroySession(payload));

    await this.free(response.id);

    return response;
  }

  /**
   * The 'freeMemory' method frees the memory used by the session with the provided id.
   *
   * @param id - The id of the session to free the memory of.
   *
   * @returns The response from the 'destroySession' function.
   */
  private async free(id: string) {
    return (await this.fetch).freeMemory(id);
  }

  /**
   * The 'get' method performs a GET request to the provided URL with the provided options.
   *
   * @param url - The URL to perform the GET request to.
   * @param options - The options for the GET request.
   *
   * @returns The response from the 'execute' method.
   */
  public async get(url: string, options?: GetRequestOptions) {
    return this.execute("GET", url, {
      headers: options?.headers,
      redirect: options?.redirect,
      rejectUnauthorized: options?.rejectUnauthorized
        ? options?.rejectUnauthorized
        : false,
      additionalDecode: options?.additionalDecode
        ? options?.additionalDecode
        : false,
      timeout: options?.timeout,
      proxy: options?.proxy,
      cookies: options?.cookies,
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
  public async delete(url: string, options?: DeleteRequestOptions) {
    return this.execute("DELETE", url, {
      headers: options?.headers,
      redirect: options?.redirect,
      rejectUnauthorized: options?.rejectUnauthorized
        ? options?.rejectUnauthorized
        : false,
      additionalDecode: options?.additionalDecode
        ? options?.additionalDecode
        : false,
      timeout: options?.timeout,
      proxy: options?.proxy,
      cookies: options?.cookies,
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
  public async options(url: string, options?: OptionsRequestOptions) {
    return this.execute("OPTIONS", url, {
      headers: options?.headers,
      redirect: options?.redirect,
      rejectUnauthorized: options?.rejectUnauthorized
        ? options?.rejectUnauthorized
        : false,
      additionalDecode: options?.additionalDecode
        ? options?.additionalDecode
        : false,
      timeout: options?.timeout,
      proxy: options?.proxy,
      cookies: options?.cookies,
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
  public async head(url: string, options?: HeadRequestOptions) {
    return this.execute("HEAD", url, {
      headers: options?.headers,
      redirect: options?.redirect,
      rejectUnauthorized: options?.rejectUnauthorized
        ? options?.rejectUnauthorized
        : false,
      additionalDecode: options?.additionalDecode
        ? options?.additionalDecode
        : false,
      timeout: options?.timeout,
      proxy: options?.proxy,
      cookies: options?.cookies,
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
  public async post(url: string, options?: PostRequestOptions) {
    return this.execute("POST", url, {
      body: options?.body,
      headers: options?.headers,
      redirect: options?.redirect,
      rejectUnauthorized: options?.rejectUnauthorized
        ? options?.rejectUnauthorized
        : false,
      additionalDecode: options?.additionalDecode
        ? options?.additionalDecode
        : false,
      timeout: options?.timeout,
      proxy: options?.proxy,
      cookies: options?.cookies,
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
  public async patch(url: string, options?: PatchRequestOptions) {
    return this.execute("PATCH", url, {
      body: options?.body,
      headers: options?.headers,
      redirect: options?.redirect,
      rejectUnauthorized: options?.rejectUnauthorized
        ? options?.rejectUnauthorized
        : false,
      additionalDecode: options?.additionalDecode
        ? options?.additionalDecode
        : false,
      timeout: options?.timeout,
      proxy: options?.proxy,
      cookies: options?.cookies,
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
  public async put(url: string, options?: PutRequestOptions) {
    return this.execute("PUT", url, {
      body: options?.body,
      headers: options?.headers,
      redirect: options?.redirect,
      rejectUnauthorized: options?.rejectUnauthorized
        ? options?.rejectUnauthorized
        : false,
      additionalDecode: options?.additionalDecode
        ? options?.additionalDecode
        : false,
      timeout: options?.timeout,
      proxy: options?.proxy,
      cookies: options?.cookies,
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
  private async execute(method: methods, url: string, options: requestOptions) {
    let headers = options?.headers ? options?.headers : this.headers;
    let requestCookies: any = [];

    if (options?.cookies) {
      requestCookies = this.jar.merge(options.cookies, url);
    }

    let skeletonPayload: any = {
      sessionId: this.sessionId,
      followRedirects: options?.redirect ? options.redirect : false,
      forceHttp1: this.forceHttp1,
      withDebug: this.debug,
      headers,
      headerOrder: this.headerOrder,
      insecureSkipVerify: options?.rejectUnauthorized
        ? options?.rejectUnauthorized
        : this.insecureSkipVerify,
      additionalDecode: options?.additionalDecode
        ? options?.additionalDecode
        : false,
      proxyUrl: options?.proxy ? options?.proxy : this.proxy,
      requestUrl: url,
      requestMethod: method,
      requestBody: options?.body,
      requestCookies: requestCookies,
      timeoutMillisecond: options?.timeout ? options?.timeout : 30000,
      withRandomTLSExtensionOrder: this.randomTlsExtensionOrder,
    };

    if (this.clientIdentifier) {
      skeletonPayload["tlsClientIdentifier"] = this.clientIdentifier;
    } else if (this.ja3string) {
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
    } else skeletonPayload["tlsClientIdentifier"] = "chrome_120";

    const requestPayloadString = JSON.stringify(skeletonPayload);

    const res = (await this.fetch).request(requestPayloadString);

    if (!res) throw new Error("No response from the server.");

    const response = JSON.parse(res);

    let cookies = this.jar.check(response.cookies, url);

    this.free(response.id);

    return new Response({ ...response, cookies });
  }
}
