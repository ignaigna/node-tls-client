import { fetchOptions } from "../interface";
import { Response } from "./Response";
import { Session } from "./Session";

/**
 * Makes an HTTP request using the specified URL and options.
 *
 * @param {string} url - The URL to make the request to.
 * @param {fetchOptions} [options] - Optional parameters for the request.
 * @returns {Promise<Response>} The response from the HTTP request.
 * @throws Will throw an error if the HTTP request fails or the method is not allowed.
 */
export async function fetch(
  url: string,
  options?: fetchOptions
): Promise<Response> {
  const session = new Session(options?.options);
  const method = options?.method?.toUpperCase() || "GET";

  try {
    let response;

    switch (method) {
      case "GET":
        response = await session.get(url, options);
        break;
      case "POST":
        response = await session.post(url, options);
        break;
      case "PUT":
        response = await session.put(url, options);
        break;
      case "DELETE":
        response = await session.delete(url, options);
        break;
      case "HEAD":
        response = await session.head(url, options);
        break;
      case "OPTIONS":
        response = await session.options(url, options);
        break;
      case "PATCH":
        response = await session.patch(url, options);
        break;
      default:
        throw new Error(`HTTP method ${method} is not allowed.`);
    }

    return response;
  } catch (error) {
    throw error;
  } finally {
    await session.close();
  }
}
