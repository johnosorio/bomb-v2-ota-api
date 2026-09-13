const state = globalThis.__bombOtaState || (globalThis.__bombOtaState = { devices: new Map(), rollouts: [], audit: [] });
export function recordAudit(event, data = {}) { state.audit.unshift({ event, occurred_at: new Date().toISOString(), ...data }); state.audit.splice(1000); }
export function json(response, status, body) { response.status(status).setHeader("Cache-Control", "no-store"); response.setHeader("Access-Control-Allow-Origin", "*"); response.setHeader("Access-Control-Allow-Methods", "GET,POST,PATCH,OPTIONS"); response.setHeader("Access-Control-Allow-Headers", "content-type"); response.status(status).json(body); }
export default state;
