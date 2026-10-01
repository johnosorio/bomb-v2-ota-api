import { administration, jsonBody, failure } from './pin-recovery.js';
export function createHandler({ env = process.env, fetchImpl = globalThis.fetch } = {}) {
  return async (req, res) => {
    res.setHeader('Cache-Control', 'private, no-store');
    res.setHeader('Vary', 'Authorization');
    res.setHeader('Allow', 'GET, POST');
    if (!['GET', 'POST'].includes(req.method)) return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    try {
      const repository = administration(env, req.headers?.authorization, fetchImpl);
      await repository.authenticate();
      if (req.method === 'GET') return res.status(200).json({ schema_version: 1, recoveries: await repository.list() });
      return res.status(200).json({ schema_version: 1, recovery: await repository.decide(jsonBody(req)) });
    } catch (error) { return failure(error, res); }
  };
}
export default createHandler();
