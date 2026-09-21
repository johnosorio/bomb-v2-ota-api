import test from "node:test";
import assert from "node:assert/strict";
import devices from "../api/devices.js";
import state from "../api/_state.js";

function invoke(method, body = {}) {
  const result = { statusCode: 200, body: undefined };
  const response = {
    status(code) {
      result.statusCode = code;
      return this;
    },
    setHeader() {
      return this;
    },
    json(body) {
      result.body = body;
      return this;
    },
    end() {
      result.ended = true;
      return this;
    }
  };
  devices({ method, body }, response);
  return result;
}

function fixture(deviceId, lifecycleState, overrides = {}) {
  return {
    device_id: deviceId,
    chip_id: `chip-${deviceId}`,
    wifi_mac: `mac-${deviceId}`,
    device_type: "BOMB01",
    firmware_version: "0.2.13",
    ota_channel: "stable",
    establishment_id: "old-establishment",
    authorization_status: "AUTHORIZED",
    batch_id: "old-batch",
    lifecycle_state: lifecycleState,
    lifecycle_history: [{
      from: "DESCUBIERTO",
      to: lifecycleState,
      actor: "fixture",
      reason: "fixture",
      occurred_at: "2026-09-21T00:00:00.000Z"
    }],
    status: "ONLINE",
    last_seen_at: "2026-09-21T00:00:00.000Z",
    updated_at: "2026-09-21T00:00:00.000Z",
    ...overrides
  };
}

test.beforeEach(() => {
  state.devices.clear();
  state.audit.length = 0;
});

test("rejected link, unlink, transfer and replace leave device and audit unchanged", () => {
  const cases = [
    ["link", fixture("link-device", "VINCULADO"), { device_id: "link-device", action: "link", establishment_id: "new-establishment", batch_id: "new-batch" }],
    ["unlink", fixture("unlink-device", "RETIRADO"), { device_id: "unlink-device", action: "unlink" }],
    ["transfer", fixture("transfer-device", "MANTENIMIENTO"), { device_id: "transfer-device", action: "transfer", establishment_id: "new-establishment", batch_id: "new-batch" }],
    ["replace-active", fixture("replace-active-device", "RESERVADO"), { device_id: "replace-active-device", action: "replace", replaced_by: "replacement-device" }],
    ["replace-unavailable", fixture("replace-unavailable-device", "VINCULADO"), { device_id: "replace-unavailable-device", action: "replace", replaced_by: "unavailable-replacement" }]
  ];
  state.devices.set("replacement-device", fixture("replacement-device", "VINCULADO"));
  state.devices.set("unavailable-replacement", fixture("unavailable-replacement", "MANTENIMIENTO"));

  for (const [action, device, body] of cases) {
    state.devices.set(device.device_id, device);
    const beforeDevice = structuredClone(device);
    const beforeAudit = structuredClone(state.audit);
    const result = invoke("PATCH", body);

    assert.equal(result.statusCode, 409, action);
    assert.deepEqual(state.devices.get(device.device_id), beforeDevice, action);
    assert.deepEqual(state.audit, beforeAudit, action);
  }
});

test("successful link, unlink, transfer and replace preserve their legacy results and audit", () => {
  const linkDevice = fixture("success-link", "DESCUBIERTO");
  state.devices.set(linkDevice.device_id, linkDevice);
  const link = invoke("PATCH", { device_id: linkDevice.device_id, action: "link", establishment_id: "new-establishment", batch_id: "new-batch" });
  assert.equal(link.statusCode, 200);
  assert.equal(link.body.lifecycle_state, "PENDIENTE_DE_AUTORIZAR");
  assert.equal(link.body.establishment_id, "new-establishment");
  assert.equal(state.audit[0].event, "DEVICE_LINK_REQUESTED");

  const unlinkDevice = fixture("success-unlink", "VINCULADO");
  state.devices.set(unlinkDevice.device_id, unlinkDevice);
  const unlink = invoke("PATCH", { device_id: unlinkDevice.device_id, action: "unlink" });
  assert.equal(unlink.statusCode, 200);
  assert.equal(unlink.body.lifecycle_state, "DESCUBIERTO");
  assert.equal(unlink.body.establishment_id, null);
  assert.equal(state.audit[0].event, "DEVICE_UNLINKED");

  const transferDevice = fixture("success-transfer", "VINCULADO");
  state.devices.set(transferDevice.device_id, transferDevice);
  const transfer = invoke("PATCH", { device_id: transferDevice.device_id, action: "transfer", establishment_id: "transferred-establishment" });
  assert.equal(transfer.statusCode, 200);
  assert.equal(transfer.body.lifecycle_state, "PENDIENTE_DE_AUTORIZAR");
  assert.equal(transfer.body.establishment_id, "transferred-establishment");
  assert.equal(state.audit[0].event, "DEVICE_TRANSFER_REQUESTED");

  const replaceDevice = fixture("success-replace", "DISPONIBLE");
  state.devices.set(replaceDevice.device_id, replaceDevice);
  state.devices.set("available-replacement", fixture("available-replacement", "VINCULADO"));
  const replace = invoke("PATCH", { device_id: replaceDevice.device_id, action: "replace", replaced_by: "available-replacement" });
  assert.equal(replace.statusCode, 200);
  assert.equal(replace.body.lifecycle_state, "RETIRADO");
  assert.equal(replace.body.replaced_by, "available-replacement");
  assert.equal(state.audit[0].event, "DEVICE_REPLACED");
});
