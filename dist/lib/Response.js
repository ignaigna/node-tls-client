"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Response = void 0;
class Response {
    response;
    // Indicates whether the response was successful (status in the range 200-299) or not.
    ok;
    // Represents the response headers.
    headers;
    // Represents the HTTP status code of the response.
    status;
    // Represents the URL of the response.
    url;
    constructor(response) {
        this.response = response;
        this.ok = response.status >= 200 && response.status < 300;
        this.headers = response.headers;
        this.status = response.status;
        this.url = response.target;
    }
    /**
     * Returns the body of the response as a string.
     *
     * @returns A promise that resolves with the body of the response as a string.
     */
    async text() {
        return this.response.body.toString();
    }
    /**
     * Returns the body of the response as a JSON object.
     *
     * @template T - The type of the JSON object.
     * @returns A promise that resolves with the body of the response as a JSON object.
     */
    async json() {
        return JSON.parse(this.response.body);
    }
    /**
     * Returns the cookies from the response as an object with key-value pairs.
     *
     * @returns An object containing cookies as key-value pairs.
     */
    get cookies() {
        return this.response.cookies;
    }
}
exports.Response = Response;
