import { OtaError } from "../../lib/ota/inventory.js";
import { licenseAdministration, licenseCommand, licenseQuery } from "../../lib/ota/license-administration.js";

export function createHandler({ env = process.env, fetchImpl = globalThis.fetch } = {}) {
  return async function handler(request, response) {
    response.setHeader("Cache-Control", "private, no-store");
    response.setHeader("Vary", "Authorization");
    response.setHeader("Allow", "GET, POST");
    const reply = (status, body) => response.status(status).json(body);
    if (!["GET", "POST"].includes(request.method)) return reply(405, { error: "METHOD_NOT_ALLOWED" });
    try {
      const repository = licenseAdministration(env, request.headers?.authorization, fetchImpl);
      if (request.method === "POST" && request.headers?.["content-length"] !== undefined) {
        const length = request.headers["content-length"];
        if (typeof length !== "string" || !/^[0-9]+$/.test(length)) throw new OtaError(400, "INVALID_INPUT");
        if (Number(length) > 4096) throw new OtaError(413, "PAYLOAD_TOO_LARGE");
      }
      await repository.authenticate();
      if (request.method === "GET") {
        return reply(200, { schema_version: 1, license: await repository.get(licenseQuery(request.query)) });
      }
      if (Object.keys(request.query || {}).length) throw new OtaError(400, "INVALID_INPUT");
      if (!/^application\/json(?:\s*;|$)/i.test(request.headers?.["content-type"] || "")) throw new OtaError(415, "JSON_REQUIRED");
      let body = request.body;
      const serialized = typeof body === "string" ? body : JSON.stringify(body);
      if (typeof serialized !== "string") throw new OtaError(400, "INVALID_INPUT");
      // With a pre-parsed platform body, this bounds normalized JSON, not wire whitespace.
      if (Buffer.byteLength(serialized, "utf8") > 4096) throw new OtaError(413, "PAYLOAD_TOO_LARGE");
      if (typeof body === "string") {
        try { body = JSON.parse(body); } catch { throw new OtaError(400, "INVALID_JSON"); }
      }
      return reply(200, { schema_version: 1, receipt: await repository.mutate(licenseCommand(body)) });
    } catch (error) {
      return reply(error instanceof OtaError ? error.status : 503,
        { error: error instanceof OtaError ? error.code : "OTA_UNAVAILABLE" });
    }
  };
}
export default createHandler();
