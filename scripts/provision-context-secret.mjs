import {randomBytes} from 'node:crypto';
import {pathToFileURL} from 'node:url';
import {parseDigestSecret} from '../src/template-fingerprint.js';
const ROOT='https://api.cloudflare.com/client/v4/accounts/a04834f19f0dfd5dc4eb47515d15478d';
const WORKER='/workers/scripts/otpanda-api',DB='/d1/database/626cd908-0951-49cf-92a2-9a54cbbb40a8/query';
const KEY='CONTEXT_DIGEST_SECRET',RING='CONTEXT_DIGEST_KEYRING',DAYS='CONTEXT_RETENTION_DAYS';
export const DEPENDENCIES='SELECT (SELECT count(*) FROM service_routes WHERE template_fp IS NOT NULL) AS rules, (SELECT count(*) FROM incoming_codes WHERE template_fp IS NOT NULL) AS codes, (SELECT count(*) FROM unassigned_context) AS previews';
// No retries, replacement, rotation or activation. Existing provider secret name
// and digest dependents are the durable guards. They are not a provider CAS lock.
// Byte buffers are zeroed; JavaScript strings cannot be zeroed. Never log or persist them.
export async function provisionContextSecret({token,runId,fetchImpl=fetch,generate=()=>randomBytes(32)}){
 if(!token||!/^\d+$/.test(runId??''))throw new Error('boundary_invalid');
 async function api(path,method='GET',body){
  try{const r=await fetchImpl(ROOT+path,{method,redirect:'error',signal:AbortSignal.timeout(30000),headers:{Authorization:'Bearer '+token,'Content-Type':method==='PATCH'?'application/merge-patch+json':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});if(!r.ok)throw new Error();const j=await r.json();if(j?.success!==true||!Array.isArray(j.errors)||j.errors.length)throw new Error();return j.result;}catch{throw new Error('provider_state_unverified_stop');}
 }
 async function names(){const rows=await api(WORKER+'/secrets');if(!Array.isArray(rows)||rows.some(r=>typeof r.name!=='string'||r.type!=='secret_text')||new Set(rows.map(r=>r.name)).size!==rows.length)throw new Error('metadata_unverified');return rows.map(r=>r.name).sort();}
 async function bindings(){const s=await api(WORKER+'/settings');if(!Array.isArray(s?.bindings)||s.bindings.some(b=>typeof b.name!=='string'||typeof b.type!=='string')||new Set(s.bindings.map(b=>b.name)).size!==s.bindings.length)throw new Error('settings_unverified');return s.bindings.filter(b=>b.type!=='secret_text').sort((a,b)=>a.name.localeCompare(b.name));}
 async function preflight(){
  const n=await names(),b=await bindings();if(n.includes(KEY)||n.includes(RING)||b.some(x=>[DAYS,KEY,RING].includes(x.name)))throw new Error('prior_context_configuration_stop');
  const r=await api(DB,'POST',{sql:DEPENDENCIES,params:[]});const rows=r?.[0]?.results;
  if(!Array.isArray(r)||r.length!==1||r[0].success!==true||!Array.isArray(rows)||rows.length!==1||Object.keys(rows[0]).sort().join(',')!=='codes,previews,rules'||Object.values(rows[0]).some(v=>!Number.isSafeInteger(v)||v!==0))throw new Error('dependencies_nonzero_or_unverified');
  return {names:n,bindings:b};
 }
 const before=await preflight(),fresh=await preflight();
 if(JSON.stringify(before)!==JSON.stringify(fresh))throw new Error('prewrite_drift_stop');
 let bytes;
 try{
  bytes=generate();if(!(bytes instanceof Uint8Array)||bytes.byteLength!==32)throw new Error('generation_invalid');
  const text=Buffer.from(bytes).toString('base64url');if(!parseDigestSecret(text))throw new Error('generation_format_invalid');
  await api(WORKER+'/secrets-bulk','PATCH',{secrets:{[KEY]:{name:KEY,text,type:'secret_text'}}});
  const after=await names(),postBindings=await bindings();
  if(JSON.stringify(after)!==JSON.stringify([...before.names,KEY].sort())||JSON.stringify(postBindings)!==JSON.stringify(before.bindings))throw new Error('postwrite_drift_or_unverified_stop');
  return {status:'secret_present_retention_not_activated',keyId:'0000'};
 }finally{bytes?.fill(0);}
}
export function contextExecutionAllowed(e){
 return e.GITHUB_ACTIONS==='true'&&e.GITHUB_EVENT_NAME==='workflow_dispatch'&&e.GITHUB_REF==='refs/heads/main'&&e.GITHUB_REPOSITORY==='otpanda/api'&&e.CONTEXT_CONFIRM==='initial-context-secret-once'&&/^[a-f0-9]{40}$/.test(e.CONTEXT_EXPECTED_SHA??'')&&e.CONTEXT_EXPECTED_SHA===e.GITHUB_SHA;
}
if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href){
 const e=process.env;
 const allowed=contextExecutionAllowed(e);
 if(!allowed){console.error('Context provisioning refused: execution boundary.');process.exitCode=1;}
 else try{await provisionContextSecret({token:e.CLOUDFLARE_API_TOKEN,runId:e.GITHUB_RUN_ID});console.log('Context secret present; retention not activated. Preserve key.');}catch{console.error('Context provisioning stopped. Do not rerun or replace key. Reconcile provider metadata, digest dependencies and this run without regeneration.');process.exitCode=1;}
}
