import state, { json, recordAudit } from "./_state.js";
export default function handler(request, response) {
  if (request.method === "OPTIONS") return response.status(204).end();
  if (request.method === "GET") { const { id, establishment_id, status, ota_channel } = request.query; if (id) return json(response, state.devices.has(id) ? 200 : 404, state.devices.get(id) || { error: "DEVICE_NOT_FOUND" }); return json(response, 200, { devices: [...state.devices.values()].filter((d) => (!establishment_id || d.establishment_id === establishment_id) && (!status || d.status === status) && (!ota_channel || d.ota_channel === ota_channel)) }); }
  if (request.method !== "POST") return json(response, 405, { error: "METHOD_NOT_ALLOWED" });
  const body = typeof request.body === "string" ? JSON.parse(request.body || "{}") : request.body || {};
  if (!body.device_id || !body.device_type || !body.firmware_version) return json(response, 400, { error: "device_id, device_type y firmware_version son obligatorios" });
  const current = state.devices.get(body.device_id) || {};
  const device = { ...current, device_id: String(body.device_id), chip_id: String(body.chip_id || current.chip_id || "-"), wifi_mac: String(body.wifi_mac || current.wifi_mac || "-"), device_type: String(body.device_type), firmware_version: String(body.firmware_version), ota_channel: String(body.ota_channel || current.ota_channel || "stable"), establishment_id: body.establishment_id ?? current.establishment_id ?? null, authorization_status: body.authorization_status || current.authorization_status || "PENDING", batch_id: body.batch_id ?? current.batch_id ?? null, status: "ONLINE", last_seen_at: new Date().toISOString() };
  state.devices.set(device.device_id, device); recordAudit(current.device_id ? "DEVICE_HEARTBEAT" : "DEVICE_REGISTERED", { actor: body.actor || "device", device_id: device.device_id, establishment_id: device.establishment_id, firmware_version: device.firmware_version }); return json(response, 200, device);
}
