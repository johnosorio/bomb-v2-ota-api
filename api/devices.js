import state, { json, recordAudit } from "./_state.js";

export const LIFECYCLE_STATES = ["DESCUBIERTO", "PENDIENTE_DE_AUTORIZAR", "VINCULADO", "DISPONIBLE", "RESERVADO", "EN_JUEGO", "MANTENIMIENTO", "RETIRADO"];

const transitions = {
  DESCUBIERTO: ["PENDIENTE_DE_AUTORIZAR", "MANTENIMIENTO", "RETIRADO"],
  PENDIENTE_DE_AUTORIZAR: ["VINCULADO", "RETIRADO"],
  VINCULADO: ["DESCUBIERTO", "PENDIENTE_DE_AUTORIZAR", "DISPONIBLE", "MANTENIMIENTO", "RETIRADO"],
  DISPONIBLE: ["DESCUBIERTO", "PENDIENTE_DE_AUTORIZAR", "RESERVADO", "MANTENIMIENTO", "RETIRADO", "VINCULADO"],
  RESERVADO: ["EN_JUEGO", "DISPONIBLE", "MANTENIMIENTO"],
  EN_JUEGO: ["DISPONIBLE", "MANTENIMIENTO"],
  MANTENIMIENTO: ["DISPONIBLE", "RETIRADO"],
  RETIRADO: []
};
const now = () => new Date().toISOString();

function bodyOf(request) {
  if (typeof request.body === "string") {
    try { return JSON.parse(request.body || "{}"); } catch { return null; }
  }
  return request.body || {};
}
function transition(device, next, body) {
  if (!LIFECYCLE_STATES.includes(next)) return { error: "INVALID_LIFECYCLE_STATE", allowed: LIFECYCLE_STATES };
  if (device.lifecycle_state === next) return { device };
  const allowed = transitions[device.lifecycle_state] || [];
  if (!allowed.includes(next)) return { error: "INVALID_LIFECYCLE_TRANSITION", from: device.lifecycle_state, to: next, allowed };
  const event = { from: device.lifecycle_state, to: next, actor: String(body.actor || "establishment"), reason: String(body.reason || "lifecycle transition"), occurred_at: now() };
  device.lifecycle_state = next;
  device.updated_at = event.occurred_at;
  device.lifecycle_history = [event, ...(device.lifecycle_history || [])].slice(0, 200);
  recordAudit("DEVICE_LIFECYCLE_CHANGED", { actor: event.actor, device_id: device.device_id, establishment_id: device.establishment_id, from: event.from, to: event.to, reason: event.reason });
  return { device };
}

function requireDevice(body) {
  if (!body.device_id) return { error: "device_id es obligatorio" };
  const device = state.devices.get(String(body.device_id));
  return device ? { device } : { error: "DEVICE_NOT_FOUND" };
}
const rejectActive = (device) => ["RESERVADO", "EN_JUEGO"].includes(device.lifecycle_state);

function applyAction(device, body) {
  const action = String(body.action || "").toLowerCase();
  if (action === "authorize") {
    if (device.lifecycle_state !== "PENDIENTE_DE_AUTORIZAR") return { error: "DEVICE_NOT_PENDING_AUTHORIZATION", state: device.lifecycle_state };
    device.authorization_status = "AUTHORIZED";
    const result = transition(device, "VINCULADO", body);
    if (result.error) return result;
    recordAudit("DEVICE_AUTHORIZED", { actor: body.actor || "establishment", device_id: device.device_id, establishment_id: device.establishment_id });
    return result;
  }
  if (action === "link") {
    if (!body.establishment_id) return { error: "establishment_id es obligatorio" };
    device.establishment_id = String(body.establishment_id);
    device.batch_id = body.batch_id == null ? null : String(body.batch_id);
    if (device.lifecycle_state === "DESCUBIERTO") {
      const result = transition(device, "PENDIENTE_DE_AUTORIZAR", body);
      if (result.error) return result;
    } else if (device.lifecycle_state !== "PENDIENTE_DE_AUTORIZAR") return { error: "DEVICE_CANNOT_BE_LINKED", state: device.lifecycle_state };
    recordAudit("DEVICE_LINK_REQUESTED", { actor: body.actor || "establishment", device_id: device.device_id, establishment_id: device.establishment_id });
    return { device };
  }
  if (action === "unlink") {
    if (rejectActive(device)) return { error: "DEVICE_ACTIVE_CANNOT_BE_UNLINKED" };
    const previousEstablishment = device.establishment_id;
    device.establishment_id = null; device.batch_id = null; device.authorization_status = "PENDING";
    const result = transition(device, "DESCUBIERTO", body);
    if (result.error) return result;
    recordAudit("DEVICE_UNLINKED", { actor: body.actor || "establishment", device_id: device.device_id, previous_establishment_id: previousEstablishment });
    return result;
  }
  if (action === "transfer") {
    if (!body.establishment_id) return { error: "establishment_id es obligatorio" };
    if (rejectActive(device)) return { error: "DEVICE_ACTIVE_CANNOT_BE_TRANSFERRED" };
    const previousEstablishment = device.establishment_id;
    device.establishment_id = String(body.establishment_id); device.batch_id = body.batch_id == null ? null : String(body.batch_id); device.authorization_status = "PENDING";
    const result = transition(device, "PENDIENTE_DE_AUTORIZAR", body);
    if (result.error) return result;
    recordAudit("DEVICE_TRANSFER_REQUESTED", { actor: body.actor || "establishment", device_id: device.device_id, previous_establishment_id: previousEstablishment, establishment_id: device.establishment_id });
    return result;
  }
  if (action === "replace") {
    if (!body.replaced_by) return { error: "replaced_by es obligatorio" };
    if (rejectActive(device)) return { error: "DEVICE_ACTIVE_CANNOT_BE_REPLACED" };
    const replacement = state.devices.get(String(body.replaced_by));
    if (!replacement) return { error: "REPLACEMENT_DEVICE_NOT_FOUND" };
    if (!["VINCULADO", "DISPONIBLE"].includes(replacement.lifecycle_state)) return { error: "REPLACEMENT_DEVICE_NOT_AVAILABLE", state: replacement.lifecycle_state };
    device.replaced_by = replacement.device_id;
    const result = transition(device, "RETIRADO", body);
    if (result.error) return result;
    recordAudit("DEVICE_REPLACED", { actor: body.actor || "establishment", device_id: device.device_id, replaced_by: replacement.device_id, establishment_id: device.establishment_id });
    return result;
  }
  if (action === "retire") return transition(device, "RETIRADO", body);
  if (body.lifecycle_state) return transition(device, String(body.lifecycle_state), body);
  return { error: "ACTION_OR_LIFECYCLE_STATE_REQUIRED" };
}

export default function handler(request, response) {
  if (request.method === "OPTIONS") return response.status(204).end();
  if (request.method === "GET") {
    const { id, establishment_id, status, ota_channel, lifecycle_state } = request.query;
    if (id) {
      const device = state.devices.get(String(id));
      return json(response, device ? 200 : 404, device || { error: "DEVICE_NOT_FOUND" });
    }
    const devices = [...state.devices.values()].filter((device) =>
      (!establishment_id || device.establishment_id === establishment_id) &&
      (!status || device.status === status) &&
      (!ota_channel || device.ota_channel === ota_channel) &&
      (!lifecycle_state || device.lifecycle_state === lifecycle_state));
    return json(response, 200, { lifecycle_states: LIFECYCLE_STATES, devices });
  }
  const body = bodyOf(request);
  if (!body) return json(response, 400, { error: "INVALID_JSON" });
  if (request.method === "POST") {
    if (!body.device_id || !body.device_type || !body.firmware_version) return json(response, 400, { error: "device_id, device_type y firmware_version son obligatorios" });
    const deviceId = String(body.device_id);
    const current = state.devices.get(deviceId);
    const timestamp = now();
    const device = {
      ...current, device_id: deviceId, chip_id: String(body.chip_id || current?.chip_id || "-"), wifi_mac: String(body.wifi_mac || current?.wifi_mac || "-"),
      device_type: String(body.device_type), firmware_version: String(body.firmware_version), ota_channel: String(body.ota_channel || current?.ota_channel || "stable"),
      establishment_id: body.establishment_id ?? current?.establishment_id ?? null, authorization_status: current?.authorization_status || "PENDING",
      batch_id: body.batch_id ?? current?.batch_id ?? null, lifecycle_state: current?.lifecycle_state || (body.establishment_id ? "PENDIENTE_DE_AUTORIZAR" : "DESCUBIERTO"),
      lifecycle_history: current?.lifecycle_history || [], status: "ONLINE", last_seen_at: timestamp, updated_at: timestamp
    };
    state.devices.set(deviceId, device);
    recordAudit(current ? "DEVICE_HEARTBEAT" : "DEVICE_DISCOVERED", { actor: body.actor || "device", device_id: device.device_id, establishment_id: device.establishment_id, wifi_mac: device.wifi_mac, firmware_version: device.firmware_version });
    return json(response, 200, device);
  }
  if (request.method === "PATCH") {
    const found = requireDevice(body);
    if (found.error) return json(response, 404, found);
    const result = applyAction(found.device, body);
    if (result.error) return json(response, 409, result);
    state.devices.set(found.device.device_id, found.device);
    return json(response, 200, found.device);
  }
  return json(response, 405, { error: "METHOD_NOT_ALLOWED" });
}
