import {randomBytes} from 'node:crypto';
import {pathToFileURL} from 'node:url';

const ACCOUNT='a04834f19f0dfd5dc4eb47515d15478d';
const DATABASE='626cd908-0951-49cf-92a2-9a54cbbb40a8';
const SCRIPT='otpanda-api';
const KEY_ID='initial-v1';
const API=`https://api.cloudflare.com/client/v4/accounts/${ACCOUNT}`;
const SECRETS=`${API}/workers/scripts/${SCRIPT}/secrets`;
const COUNTS='SELECT (SELECT count(*) FROM code_records)+(SELECT count(*) FROM incoming_codes)+(SELECT count(*) FROM oauth_transactions)+(SELECT count(*) FROM totp_seeds) AS dependencies';

// Never print request bodies, responses, headers, caught errors, or key values.
// Dependencies are injectable for tests; the CLI uses only native Node APIs.
export async function provisionInitialKey({token,runId,fetchImpl=fetch,generate=()=>randomBytes(32),now=Date.now,healthUrl}) {
  if(!token||!/^\d+$/.test(runId??'')||!healthUrl)throw new Error('preflight_failed');
  async function api(url,method='GET',body) {
    try {
      const response=await fetchImpl(url,{method,redirect:'error',signal:AbortSignal.timeout(30000),headers:{Authorization:`Bearer ${token}`,'Content-Type':method==='PATCH'?'application/merge-patch+json':'application/json'},...(body===undefined?{}:{body:JSON.stringify(body)})});
      if(!response.ok)throw new Error();
      const data=await response.json();
      if(data?.success!==true||!Array.isArray(data.errors)||data.errors.length!==0)throw new Error();
      return data.result;
    } catch {throw new Error('provider_result_unverified');}
  }
  async function query(sql,params=[]) {
    const result=await api(`${API}/d1/database/${DATABASE}/query`,'POST',{sql,params});
    if(!Array.isArray(result)||result.length!==1||result[0]?.success!==true||!Array.isArray(result[0].results))throw new Error('database_result_unverified');
    return result[0];
  }
  async function secretNames() {
    const result=await api(SECRETS);
    if(!Array.isArray(result)||result.some(x=>typeof x?.name!=='string'||x.type!=='secret_text')||new Set(result.map(x=>x.name)).size!==result.length)throw new Error('metadata_unverified');
    return new Set(result.map(x=>x.name));
  }
  try {
    const response=await fetchImpl(healthUrl,{redirect:'error',signal:AbortSignal.timeout(30000)});
    const data=await response.json();
    if(!response.ok||data?.service!=='otpanda-api'||data.authentication!=='disabled')throw new Error();
  } catch {throw new Error('bootstrap_unverified');}
  const names=await secretNames();
  if(names.has('ENCRYPTION_KEYRING')||names.has('ACTIVE_KEY_ID'))throw new Error('initial_secret_already_present');
  const existing=await query('SELECT singleton FROM initial_key_provisioning');
  if(existing.results.length)throw new Error('initial_attempt_already_reserved');
  const counts=await query(COUNTS);
  if(counts.results.length!==1||counts.results[0].dependencies!==0)throw new Error('ciphertext_dependency_or_unknown_count');
  // Atomic reservation checks dependencies again. Ambiguous reservation stops
  // before generating any key. Uniqueness prevents another run winning twice.
  const reservation=await query(`INSERT INTO initial_key_provisioning(singleton,key_id,run_id,state,created_at) SELECT 1,?,?,'reserved',? WHERE (${COUNTS.replace('SELECT ','').replace(' AS dependencies','')})=0 AND NOT EXISTS(SELECT 1 FROM initial_key_provisioning) RETURNING singleton`,[KEY_ID,runId,now()]);
  if(reservation.results.length!==1||reservation.results[0].singleton!==1)throw new Error('reservation_unverified');
  let bytes;
  try {
    bytes=generate();
    if(!(bytes instanceof Uint8Array)||bytes.byteLength!==32)throw new Error('generation_failed');
    const keyring=JSON.stringify([{id:KEY_ID,key:Buffer.from(bytes).toString('base64url')}]);
    // No automatic retry. Any uncertainty leaves the durable reservation in
    // place, even if the provider actually accepted the write.
    await api(`${SECRETS}-bulk`,'PATCH',{secrets:{ENCRYPTION_KEYRING:{name:'ENCRYPTION_KEYRING',text:keyring,type:'secret_text'},ACTIVE_KEY_ID:{name:'ACTIVE_KEY_ID',text:KEY_ID,type:'secret_text'}}});
    const after=await secretNames();
    if(!after.has('ENCRYPTION_KEYRING')||!after.has('ACTIVE_KEY_ID')||[...names].some(n=>!after.has(n)))throw new Error('binding_metadata_unverified');
    const done=await query("UPDATE initial_key_provisioning SET state='bindings_written' WHERE singleton=1 AND run_id=? AND state='reserved' RETURNING singleton",[runId]);
    if(done.results.length!==1||done.results[0].singleton!==1)throw new Error('completion_unverified');
    return {keyId:KEY_ID,status:'bindings_created_not_activated'};
  } finally {bytes?.fill(0);}
}

// Read-only reconciliation. Never generates, repairs, or replaces key material.
export async function verifyBootstrapReadiness({fetchImpl=fetch}={}) {
  const root='https://otpanda-api.abrahammurciano.workers.dev';
  try {
    const response=await fetchImpl(root+'/ready',{redirect:'error',signal:AbortSignal.timeout(30000)});
    const data=await response.json();
    if(!response.ok||data?.service!=='otpanda-api'||data.database!=='available'||data.keyring!=='valid-format'||data.application!=='setup-required')throw new Error();
    for(const path of ['/auth/login/start','/v1/manage/session']) {
      const denied=await fetchImpl(root+path,{redirect:'error',signal:AbortSignal.timeout(30000)});
      if(denied.status!==503||(await denied.json())?.error!=='setup_required')throw new Error();
    }
    return true;
  }catch{throw new Error('readiness_or_auth_gate_unverified');}
}

if(process.argv[1]&&import.meta.url===pathToFileURL(process.argv[1]).href) {
  // Fixed reviewed destination only. No arbitrary URL receives credentials.
  const allowed=process.env.GITHUB_ACTIONS==='true'&&process.env.GITHUB_EVENT_NAME==='workflow_dispatch'&&process.env.GITHUB_REF==='refs/heads/main'&&process.env.GITHUB_REPOSITORY==='otpanda/api'&&process.env.INITIAL_KEY_CONFIRM==='initial-key-once';
  if(!allowed){console.error('Initial provisioning refused: execution boundary.');process.exitCode=1;}
  else {
    try {
      if(process.argv.includes('--verify-only'))await verifyBootstrapReadiness();
      else {await provisionInitialKey({token:process.env.CLOUDFLARE_API_TOKEN,runId:process.env.GITHUB_RUN_ID,healthUrl:'https://otpanda-api.abrahammurciano.workers.dev/health'});
      await verifyBootstrapReadiness();}
      console.log('Initial key readiness verified; authentication remains disabled. Key ID initial-v1.');
    }catch{console.error('Initial provisioning stopped. Preserve reservation and bindings; reconcile without regeneration.');process.exitCode=1;}
  }
}
