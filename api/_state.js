const demoEstablishment = {
  establishment_id: "01",
  name: "Instalacion de prueba",
  contracted_capacity: 1,
  authorized_bombs: 1,
  allowed_games: ["standalone-demo"],
  offline_grace_days: 7,
  status: "ACTIVE",
  created_at: "2026-09-15T00:00:00.000Z",
  updated_at: "2026-09-15T00:00:00.000Z",
  updated_by: "demo-fixture"
};

const demoLicense = {
  license_id: "demo-license-01",
  establishment_id: "01",
  contracted_capacity: 1,
  authorized_bombs: 1,
  allowed_games: ["standalone-demo"],
  issued_at: "2026-09-15T00:00:00.000Z",
  expires_at: "2099-12-31T23:59:59.000Z",
  offline_grace_days: 7,
  status: "ACTIVE",
  signature: "DEMO-NOT-A-REAL-LICENSE",
  updated_at: "2026-09-15T00:00:00.000Z",
  updated_by: "demo-fixture"
};

const state = globalThis.__bombOtaState || (globalThis.__bombOtaState = {
  devices: new Map(),
  establishments: new Map(),
  licenses: new Map(),
  rollouts: [],
  audit: []
});

state.devices ||= new Map();
state.establishments ||= new Map();
state.licenses ||= new Map();
state.rollouts ||= [];
state.audit ||= [];
if (!state.establishments.has("01")) {
  state.establishments.set("01", demoEstablishment);
}
if (!state.licenses.has(demoLicense.license_id)) {
  state.licenses.set(demoLicense.license_id, demoLicense);
}
export function recordAudit(event, data = {}) { state.audit.unshift({ event, occurred_at: new Date().toISOString(), ...data }); state.audit.splice(1000); }
export function json(response, status, body) { response.status(status).setHeader("Cache-Control", "no-store"); response.setHeader("Access-Control-Allow-Origin", "*"); response.setHeader("Access-Control-Allow-Methods", "GET,POST,PATCH,OPTIONS"); response.setHeader("Access-Control-Allow-Headers", "content-type"); response.status(status).json(body); }
export default state;
