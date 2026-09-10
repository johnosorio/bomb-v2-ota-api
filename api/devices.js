const devices = globalThis.__bombDevices || (globalThis.__bombDevices = new Map());

function json(response, status, body) {
  response.status(status).setHeader("Cache-Control", "no-store");
  response.setHeader("Access-Control-Allow-Origin", "*");
  response.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");
  response.setHeader("Access-Control-Allow-Headers", "content-type");
  response.status(status).json(body);
}

export default function handler(request, response) {
  if (request.method === "OPTIONS") return response.status(204).end();
  if (request.method === "GET") {
    const id = request.query.id;
    if (id) return json(response, devices.has(id) ? 200 : 404,
      devices.has(id) ? devices.get(id) : { error: "DEVICE_NOT_FOUND" });
    return json(response, 200, { devices: [...devices.values()] });
  }
  if (request.method !== "POST") return json(response, 405, { error: "METHOD_NOT_ALLOWED" });
  const body = typeof request.body === "string" ? JSON.parse(request.body || "{}") : request.body || {};
  if (!body.device_id || !body.device_type || !body.firmware_version) {
    return json(response, 400, { error: "device_id, device_type y firmware_version son obligatorios" });
  }
  const current = devices.get(body.device_id) || {};
  const device = {
    ...current,
    device_id: String(body.device_id),
    chip_id: String(body.chip_id || current.chip_id || "-"),
    wifi_mac: String(body.wifi_mac || current.wifi_mac || "-"),
    device_type: String(body.device_type),
    firmware_version: String(body.firmware_version),
    ota_channel: String(body.ota_channel || current.ota_channel || "stable"),
    establishment_id: current.establishment_id || null,
    authorization_status: current.authorization_status || "PENDING",
    status: "ONLINE",
    last_seen_at: new Date().toISOString()
  };
  devices.set(device.device_id, device);
  return json(response, 200, device);
}
