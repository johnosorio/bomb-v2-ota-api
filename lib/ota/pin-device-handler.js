import { deviceRecovery, jsonBody, failure } from './pin-recovery.js';
export function createHandler({ env = process.env, transaction } = {}) {
  return async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Allow', 'POST');
    if (req.method !== 'POST') return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    try { return res.status(200).json({ schema_version: 1, recovery: await deviceRecovery(jsonBody(req), env, { transaction }) }); }
    catch (error) { return failure(error, res); }
  };
}
export default createHandler();
