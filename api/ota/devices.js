import { configuration, inventory, listing, registration, OtaError } from "../../lib/ota/inventory.js";

export function createHandler({ env = process.env, fetchImpl = globalThis.fetch } = {}) {
  return async function handler(request, response) {
    response.setHeader("Cache-Control", "private, no-store");
    response.setHeader("Vary", "Authorization");
    response.setHeader("Allow", "GET, POST");
    const reply = (status, body) => response.status(status).json(body);
    if (!["GET", "POST"].includes(request.method)) return reply(405, { error: "METHOD_NOT_ALLOWED" });
    try {
      const repository = inventory(configuration(env), request.headers?.authorization, fetchImpl);
      if (request.method === "POST" && request.headers?.["content-length"] !== undefined) {
        const length = request.headers["content-length"];
        if (typeof length !== "string" || !/^[0-9]+$/.test(length)) throw new OtaError(400, "INVALID_INPUT");
        if (Number(length) > 4096) throw new OtaError(413, "PAYLOAD_TOO_LARGE");
      }
      const userId = await repository.authenticate();
      if (request.method === "GET") {
        const query = listing(request.query);
        return reply(200, { schema_version: 1, devices: await repository.list(query, userId), limit: query.limit, offset: query.offset });
      }
      if (!/^application\/json(?:\s*;|$)/i.test(request.headers?.["content-type"] || ""))
        throw new OtaError(415, "JSON_REQUIRED");
      let body = request.body;
      // Parsed platform bodies have lost whitespace: this caps normalized JSON,
      // not the original transport bytes. Content-Length is checked above too.
      const serialized = typeof body === "string" ? body : JSON.stringify(body);
      if (typeof serialized !== "string") throw new OtaError(400, "INVALID_INPUT");
      if (Buffer.byteLength(serialized, "utf8") > 4096) throw new OtaError(413, "PAYLOAD_TOO_LARGE");
      if (typeof body === "string") {
        try { body = JSON.parse(body); } catch { throw new OtaError(400, "INVALID_JSON"); }
      }
      const registered = await repository.register(registration(body));
      // Both first registration and an exact retry have the same 200 contract.
      return reply(200, { schema_version: 1, device: registered });
    } catch (error) {
      return reply(error instanceof OtaError ? error.status : 503,
        { error: error instanceof OtaError ? error.code : "OTA_UNAVAILABLE" });
    }
  };
}
export default createHandler();
