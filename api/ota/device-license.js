import { OtaError } from "../../lib/ota/inventory.js";
import { deviceGatewayConfig, deviceGateway } from "../../lib/ota/device-gateway.js";

export function createHandler({ env = process.env, dependencies = {} } = {}) {
  return async (request, response) => {
    response.setHeader("Cache-Control", "private, no-store");
    response.setHeader("Allow", "POST");
    const reply = (status, body) => response.status(status).json(body);
    if (request.method !== "POST") return reply(405, { error: "METHOD_NOT_ALLOWED" });
    try {
      // Gate before parsing private configuration or any request/DB side effect.
      if (env.OTA_DEVICE_GATEWAY_ENABLED !== "true") throw new OtaError(503, "OTA_DEVICE_GATEWAY_DISABLED");
      if (Object.keys(request.query || {}).length) throw new OtaError(400, "INVALID_INPUT");
      const length = request.headers?.["content-length"];
      if (length !== undefined) {
        if (typeof length !== "string" || !/^[0-9]+$/.test(length)) throw new OtaError(400, "INVALID_INPUT");
        if (Number(length) > 4096) throw new OtaError(413, "PAYLOAD_TOO_LARGE");
      }
      if (!/^application\/json(?:\s*;|$)/i.test(request.headers?.["content-type"] || "")) throw new OtaError(415, "JSON_REQUIRED");
      let body = request.body;
      const serialized = typeof body === "string" ? body : JSON.stringify(body);
      if (typeof serialized !== "string") throw new OtaError(400, "INVALID_INPUT");
      if (Buffer.byteLength(serialized) > 4096) throw new OtaError(413, "PAYLOAD_TOO_LARGE");
      if (typeof body === "string") {
        try { body = JSON.parse(body); } catch { throw new OtaError(400, "INVALID_JSON"); }
      }
      const result = await deviceGateway(body, deviceGatewayConfig(env), dependencies);
      return reply(200, result); // Only after transaction COMMIT has succeeded.
    } catch (error) {
      return reply(error instanceof OtaError ? error.status : 503,
        { error: error instanceof OtaError ? error.code : "OTA_GATEWAY_UNAVAILABLE" });
    }
  };
}
export default createHandler();
