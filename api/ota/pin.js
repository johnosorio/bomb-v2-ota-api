import { createHandler as device } from '../../lib/ota/pin-device-handler.js';
import { createHandler as admin } from '../../lib/ota/pin-admin-handler.js';
import { createHandler as portal } from '../../lib/ota/pin-portal-handler.js';
import { jsonBody, failure } from '../../lib/ota/pin-recovery.js';
import { OtaError } from '../../lib/ota/inventory.js';

// One function deployment; device proofs and human JWTs retain separate handlers.
export function createHandler(dependencies = {}) {
  const deviceHandler=device(dependencies), adminHandler=admin(dependencies), portalHandler=portal(dependencies);
  return async (req,res) => {
    res.setHeader('Cache-Control','no-store');
    try {
      const query=req.query || {};
      if(req.method==='GET' && Object.keys(query).length===1 && query.action==='config') return portalHandler(req,res);
      if(Object.keys(query).length) throw new OtaError(400,'INVALID_INPUT');
      if(req.method==='GET')return adminHandler(req,res);
      if(req.method!=='POST')return res.status(405).json({error:'METHOD_NOT_ALLOWED'});
      const body=jsonBody(req);
      // Preserve Node/Vercel IncomingMessage getters such as headers and auth.
      // Spreading req drops inherited properties needed by downstream handlers.
      if(['approve','reject'].includes(body?.action))return adminHandler(req,res);
      return deviceHandler(req,res);
    } catch(error) {return failure(error,res);}
  };
}
export default createHandler();
