import { createPublicKey, verify } from 'node:crypto';
import { OtaError, configuration, userScopedClient } from './inventory.js';
import { canonicalBytes, exact, matches, MAC, HEX32, REALM, UUID, sha256 } from './device-proof.js';
import { gatewayDatabaseConfig, gatewayTransaction } from './gateway-db.js';

const bad = () => { throw new OtaError(400, 'INVALID_INPUT'); };
const unavailable = () => { throw new OtaError(503, 'PIN_RECOVERY_UNAVAILABLE'); };
export const actions = ['create', 'status', 'cancel', 'consume'];
export function enabled(env) {
  if (env.OTA_PIN_RECOVERY_ENABLED !== 'true') throw new OtaError(503, 'PIN_RECOVERY_DISABLED');
  configuration(env); // Do not start device requests when the human portal is unavailable.
}
export function proofInput(body, realm, fingerprint) {
  return Buffer.from(['BOMB-PIN-RECOVERY', '1', realm, body.action, body.mac,
    fingerprint, body.request_id, body.nonce, ''].join('\n'), 'ascii');
}
export function verifyProof(body, realm) {
  if (!exact(body, ['action', 'mac', 'public_key', 'request_id', 'nonce', 'signature']) ||
      !actions.includes(body.action) || !matches(REALM, realm) || !matches(MAC, body.mac) ||
      !matches(HEX32, body.request_id) || !matches(HEX32, body.nonce)) bad();
  let key, der;
  try {
    der = canonicalBytes(body.public_key, 91);
    key = createPublicKey({ key: der, format: 'der', type: 'spki' });
    if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1' ||
        !key.export({ format: 'der', type: 'spki' }).equals(der)) bad();
  } catch { bad(); }
  const fingerprint = sha256(der);
  if (!verify('sha256', proofInput(body, realm, fingerprint), { key, dsaEncoding: 'ieee-p1363' },
    canonicalBytes(body.signature, 64))) throw new OtaError(401, 'INVALID_DEVICE_PROOF');
  return { mac: body.mac, device_key_sha256: fingerprint, realm };
}
const fields = ['request_id', 'device_id', 'credential_id', 'realm', 'status', 'issued_at', 'expires_at'];
export function snapshot(row, extra = []) {
  if (!exact(row, [...fields, ...extra]) || !matches(HEX32, row.request_id) ||
      !matches(UUID, row.device_id) || !matches(UUID, row.credential_id) || !matches(REALM, row.realm) ||
      !['pending', 'approved', 'rejected', 'cancelled', 'consumed', 'expired'].includes(row.status) ||
      !Number.isSafeInteger(row.issued_at) || row.issued_at < 1 || row.expires_at !== row.issued_at + 600 ||
      (extra.includes('nonce') && !matches(HEX32, row.nonce)) ||
      (extra.includes('device_label') && (typeof row.device_label !== 'string' || row.device_label.length > 160)) ||
      (extra.includes('device_code') && (typeof row.device_code !== 'string' || row.device_code.length > 64))) unavailable();
  return row;
}
export async function deviceRecovery(body, env, { transaction } = {}) {
  enabled(env);
  const identity = verifyProof(body, env.OTA_DEVICE_REALM);
  // Verification precedes DB access. The gateway role cannot approve a request.
  const transact = transaction || gatewayTransaction(gatewayDatabaseConfig(env));
  return transact(async query => {
    const result = await query('SELECT public.ota_pin_device($1::jsonb,$2::text,$3::text,$4::text) AS data',
      [JSON.stringify(identity), body.action, body.request_id, body.nonce]);
    if (result.rows.length !== 1) unavailable();
    const value = snapshot(result.rows[0].data, ['nonce']);
    if (value.request_id !== body.request_id || value.realm !== identity.realm || value.nonce !== body.nonce) unavailable();
    return value;
  });
}
export function administration(env, authorization, fetchImpl) {
  enabled(env);
  const { request, authenticate } = userScopedClient(configuration(env), authorization, fetchImpl, 'RECOVERY_CONFLICT');
  const rpc = (name, args) => request(`/rest/v1/rpc/${name}`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(args)
  });
  return {
    authenticate,
    async list() {
      const rows = await rpc('ota_pin_list', {});
      if (!Array.isArray(rows) || rows.length > 100) unavailable();
      return rows.map(row => snapshot(row, ['device_label', 'device_code']));
    },
    async decide(body) {
      if (!exact(body, ['request_id', 'action']) || !matches(HEX32, body.request_id) ||
          !['approve', 'reject'].includes(body.action)) bad();
      const value = snapshot(await rpc('ota_pin_admin', { p_request_id: body.request_id, p_action: body.action }));
      if (value.request_id !== body.request_id) unavailable();
      return value;
    }
  };
}
export function jsonBody(request) {
  if (!/^application\/json(?:\s*;|$)/i.test(request.headers?.['content-type'] || ''))
    throw new OtaError(415, 'JSON_REQUIRED');
  const length = request.headers?.['content-length'];
  if (length !== undefined && (typeof length !== 'string' || !/^\d+$/.test(length))) bad();
  if (length !== undefined && Number(length) > 4096) throw new OtaError(413, 'PAYLOAD_TOO_LARGE');
  const raw = typeof request.body === 'string' ? request.body : JSON.stringify(request.body);
  if (typeof raw !== 'string') bad();
  if (Buffer.byteLength(raw) > 4096) throw new OtaError(413, 'PAYLOAD_TOO_LARGE');
  try { return JSON.parse(raw); } catch { bad(); }
}
export function failure(error, response) {
  return response.status(error instanceof OtaError ? error.status : 503).json({
    error: error instanceof OtaError ? error.code : 'PIN_RECOVERY_UNAVAILABLE'
  });
}
