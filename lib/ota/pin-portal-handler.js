import { configuration } from './inventory.js';
import { enabled, failure } from './pin-recovery.js';
export function createHandler({ env = process.env } = {}) {
  return async (req, res) => {
    res.setHeader('Cache-Control', 'no-store');
    if (req.method !== 'GET') return res.status(405).json({ error: 'METHOD_NOT_ALLOWED' });
    try {
      enabled(env);
      const config = configuration(env);
      // Public Auth configuration only: never expose gateway DB or signing keys.
      return res.status(200).json({ supabase_url: config.origin, publishable_key: config.key });
    } catch (error) { return failure(error, res); }
  };
}
export default createHandler();
