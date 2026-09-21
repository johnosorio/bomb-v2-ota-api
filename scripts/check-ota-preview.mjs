// Explicit integration runner; never part of `npm test`. Writes synthetic OTA
// inventory in the operator-approved development project using user JWTs only.
// Provisioning/revocation is performed separately by the coordinator.
import { readFileSync, lstatSync } from 'node:fs';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
const backend=fileURLToPath(new URL('../',import.meta.url));
const {SUPABASE_URL:base,SUPABASE_PUBLISHABLE_KEY:key,OTA_PREVIEW_URL:preview,OTA_PREVIEW_FIXTURE:fixturePath}=process.env;
if(base!=='https://cdurakjehpvcwmvsgire.supabase.co'||!/^sb_publishable_/.test(key||'')) throw Error('Expected approved development Supabase project');
if(!/^https:\/\/bomb-v2-ota-[a-z0-9-]+-johnosorios-projects\.vercel\.app$/.test(preview||'')) throw Error('Expected explicit Preview URL, never production');
if(!fixturePath||!lstatSync(fixturePath).isFile()||(lstatSync(fixturePath).mode&0o777)!==0o600) throw Error('Private fixture required (0600)');
const f=JSON.parse(readFileSync(fixturePath,'utf8'));
if(f.projectRef!=='cdurakjehpvcwmvsgire'||f.closed||!f.provisioned) throw Error('Fixture is not active for this project');
const sessions={};
let passed=0;
const expect=(condition,name)=>{if(!condition) throw Error(name); passed++; console.log(`PASS ${name}`);};
async function rest(path,{token,method='GET',body,object=false}={}) {
  const r=await fetch(base+path,{method,headers:{apikey:key,...(token?{Authorization:`Bearer ${token}`} : {}),'Content-Type':'application/json',Accept:object?'application/vnd.pgrst.object+json':'application/json'},
    body:body===undefined?undefined:JSON.stringify(body),redirect:'error',signal:AbortSignal.timeout(15000)});
  const text=await r.text(); let data; try {data=JSON.parse(text);} catch {data=null;}
  return {status:r.status,data};
}
function http(path,{role,method='GET',body,headers={}}={}) {
  return new Promise((resolve,reject)=>{
    // Pass auth headers through stdin, never CLI arguments or logs.
    const values={...headers,...(role?{Authorization:`Bearer ${sessions[role]}`} : {})};
    const lines=[`request = ${JSON.stringify(method)}`,...Object.entries(values).map(([k,v])=>`header = ${JSON.stringify(k+': '+v)}`)];
    if(body!==undefined) {lines.push('header = "Content-Type: application/json"'); lines.push(`data = ${JSON.stringify(typeof body==='string'?body:JSON.stringify(body))}`);}
    const child=execFile('npx',['--yes','vercel@59.23.2','curl',path,'--deployment',preview,'--','--silent','--show-error','--max-time','25','--write-out','\n_OTA_HTTP_%{http_code}','--config','-'],
      {cwd:backend,timeout:45000,maxBuffer:1024*1024},(error,stdout)=>{
        if(error) return reject(Error('Preview transport failed (details withheld)'));
        const match=stdout.match(/\n_OTA_HTTP_(\d{3})\s*$/);
        if(!match) return reject(Error('Preview status marker missing'));
        const text=stdout.slice(0,match.index); let data; try {data=JSON.parse(text);} catch {data=null;}
        resolve({status:Number(match[1]),data});
      });
    child.stdin.end(lines.join('\n')+'\n');
  });
}
const p='/api/ota/devices';
const query=`?scope_id=${f.scopeA}`;
const input={scope_id:f.scopeA,device_id:`PREVIEW-${f.runId}`,label:'Synthetic OTA integration'};
try {
  for(const [role,user] of Object.entries(f.users)) {
    const result=await rest('/auth/v1/token?grant_type=password',{method:'POST',body:{email:user.email,password:user.password}});
    if(result.status!==200||!result.data?.access_token||result.data.user?.id!==user.id) throw Error(`Auth login failed for synthetic ${role}`);
    sessions[role]=result.data.access_token;
  }
  expect(true,'real Auth sessions established for four synthetic identities');
  if(process.argv.includes('--persistence-only')) {
    const result=await http(p+query,{role:'viewerA'});
    const stored=result.data?.devices?.find(d=>d.device_id===input.device_id);
    expect(result.status===200&&stored?.created_by===f.users.adminA.id,'separate deployment reads original persisted registration');
    const audit=await rest(`/rest/v1/ota_audit_events?device_id=eq.${stored.id}`,{token:sessions.adminA});
    expect(audit.status===200&&audit.data?.length===1,'separate deployment leaves original audit unchanged');
    console.log(JSON.stringify({passed,preview,deviceId:stored.id,mode:'persistence-only'}));
  } else {
  expect((await http(p+query)).status===401,'Preview missing bearer rejected');
  expect((await http(p+query,{headers:{Authorization:'Bearer invalid.preview.token'}})).status===401,'Preview invalid bearer rejected');
  expect((await rest('/rest/v1/ota_devices?select=id')).status===401,'direct REST anonymous read denied');
  expect((await http(p+query,{role:'outsider'})).status===403,'Preview non-member denied');
  expect((await http(p+query,{role:'adminB'})).status===403,'Preview foreign admin denied');
  expect((await http(p,{role:'viewerA',method:'POST',body:input})).status===403,'Preview viewer write denied');
  expect((await http(p,{role:'adminA',method:'POST',body:{...input,actor:'spoof'}})).status===400,'Preview caller-supplied actor rejected');
  const created=await http(p,{role:'adminA',method:'POST',body:input});
  expect(created.status===200 && created.data?.device?.created_by===f.users.adminA.id,'Preview registration and server-derived actor');
  const retry=await http(p,{role:'adminA',method:'POST',body:input});
  expect(retry.status===200 && retry.data.device.id===created.data.device.id,'Preview exact retry returns original ID');
  expect((await http(p,{role:'adminA',method:'POST',body:{...input,label:'Different'}})).status===409,'Preview changed-payload conflict');
  expect((await http(p,{role:'adminB',method:'POST',body:{...input,scope_id:f.scopeB}})).status===409,'Preview foreign-ID conflict is generic');
  const listed=await http(p+query,{role:'viewerA'});
  expect(listed.status===200 && listed.data?.devices?.some(d=>d.id===created.data.device.id),'Preview viewer sees persisted inventory');
  const hidden=await rest(`/rest/v1/ota_devices?scope_id=eq.${f.scopeA}`,{token:sessions.adminB});
  expect(hidden.status===200 && Array.isArray(hidden.data) && hidden.data.length===0,'direct REST RLS hides foreign inventory');
  const rpc={p_scope_id:f.scopeA,p_device_id:input.device_id,p_label:input.label};
  expect((await rest('/rest/v1/rpc/ota_register_device',{token:sessions.viewerA,method:'POST',body:rpc,object:true})).status===403,'direct RPC viewer denied');
  expect((await rest('/rest/v1/ota_devices',{token:sessions.adminA,method:'POST',body:{...input,model:'CoreS3',created_by:f.users.adminA.id}})).status===403,'direct table write denied to admin');
  const concurrent=await Promise.all(Array.from({length:4},()=>rest('/rest/v1/rpc/ota_register_device',{token:sessions.adminA,method:'POST',body:rpc,object:true})));
  expect(concurrent.every(r=>r.status===200&&r.data?.id===created.data.device.id),'real PostgREST single-object RPC and concurrent retries');
  const audit=await rest(`/rest/v1/ota_audit_events?device_id=eq.${created.data.device.id}`,{token:sessions.adminA});
  expect(audit.status===200&&audit.data?.length===1&&audit.data[0].actor_id===f.users.adminA.id,'exactly one persisted audit with verified actor');
  expect((await http(p,{role:'adminA',method:'POST',body:JSON.stringify(input)+' '.repeat(4200)})).status===413,'Preview declared oversized body rejected');
  for(const path of ['/docs/OTA_FOUNDATION.md','/supabase/config.toml','/.env.local','/scripts/check-ota-preview.mjs'])
    expect((await http(path)).status===404,`deployment excludes ${path}`);
  const legacy=await http('/api/releases/stable');
  expect(legacy.status===200&&typeof legacy.data?.firmware_url==='string','legacy manifest remains available');
  console.log(JSON.stringify({passed,preview,projectRef:f.projectRef,deviceId:created.data.device.id,scopeId:f.scopeA}));
  }
} catch(error) {console.log(`FAIL ${error.message}`);process.exitCode=1;}
