import test from 'node:test';import assert from 'node:assert/strict';import {spawnSync} from 'node:child_process';
import {provisionContextSecret,DEPENDENCIES,contextExecutionAllowed} from '../scripts/provision-context-secret.mjs';import {parseDigestSecret,parseDigestKeys} from '../src/template-fingerprint.js';
const KEY='CONTEXT_DIGEST_SECRET';
function fixture({initial=[],retention=false,counts={rules:0,codes:0,previews:0},fail=null,postDrift=false,nameDrift=null,settingsShape=null}={}){
 const saved=new Map(initial.map(n=>[n,'unchanged'])),requests=[],generated=[];let wrote=false;
 const invoke=()=>provisionContextSecret({token:'fixture-token',runId:'1234',generate:()=>{const b=Uint8Array.from({length:32},(_,i)=>i*7+13);generated.push(b);return b;},fetchImpl:async(url,init)=>{
  assert.ok(url.startsWith('https://api.cloudflare.com/client/v4/accounts/a04834f19f0dfd5dc4eb47515d15478d/'));requests.push({url,method:init.method});assert.equal(init.redirect,'error');
  let result;
  if(url.endsWith('/settings'))result=settingsShape==='missing'?{}:{bindings:[{name:'DB',type:'d1',id:'626cd908-0951-49cf-92a2-9a54cbbb40a8'},...(retention||postDrift&&wrote?[{name:'CONTEXT_RETENTION_DAYS',type:'plain_text',text:'30'}]:[])]};
  else if(url.endsWith('/query')){assert.equal(JSON.parse(init.body).sql,DEPENDENCIES);result=[{success:true,results:[counts]}];}
  else if(url.endsWith('/secrets-bulk')){
   assert.equal(init.method,'PATCH');const b=JSON.parse(init.body);assert.deepEqual(Object.keys(b.secrets),[KEY]);assert.equal(b.secrets[KEY].type,'secret_text');assert.equal(parseDigestSecret(b.secrets[KEY].text).length,32);assert.deepEqual(parseDigestKeys(b.secrets[KEY].text,null).map(k=>k.id),['0000']);saved.set(KEY,b.secrets[KEY].text);wrote=true;
   if(fail==='network')throw new Error('sensitive-provider-error');if(fail==='500')return{ok:false};if(fail==='malformed')return{ok:true,json:async()=>({})};result=[{name:KEY}];
  }else{assert.ok(url.endsWith('/secrets'));let ns=[...saved.keys()];if(wrote&&nameDrift==='missing')ns=ns.filter(n=>n!==KEY);if(wrote&&nameDrift==='extra')ns.push('UNEXPECTED');result=ns.map(name=>({name,type:'secret_text'}));}
  if(url.endsWith('/settings')&&settingsShape==='duplicate')result={bindings:[{name:'DB',type:'d1'},{name:'DB',type:'d1'}]};
  return{ok:true,json:async()=>({success:true,errors:[],result})};
 }});
 return{saved,requests,generated,invoke};
}
test('single secret0000, unrelated bindings preserved, bytes zeroed; rerun refuses',async()=>{
 const f=fixture({initial:['ENCRYPTION_KEYRING']});assert.deepEqual(await f.invoke(),{status:'secret_present_retention_not_activated',keyId:'0000'});assert.equal(f.saved.get('ENCRYPTION_KEYRING'),'unchanged');assert.ok(f.generated[0].every(x=>x===0));await assert.rejects(f.invoke(),/prior_context/);assert.equal(f.generated.length,1);assert.equal(f.requests.filter(r=>r.method==='PATCH').length,1);
});
for(const name of [KEY,'CONTEXT_DIGEST_KEYRING'])test('existing '+name+' blocks before generation/write',async()=>{const f=fixture({initial:[name]});await assert.rejects(f.invoke(),/prior_context/);assert.equal(f.generated.length,0);assert.ok(f.requests.every(r=>r.method==='GET'));});
test('retention already configured blocks',async()=>{const f=fixture({retention:true});await assert.rejects(f.invoke(),/prior_context/);assert.equal(f.generated.length,0);});
for(const counts of [{rules:1,codes:0,previews:0},{rules:0,codes:1,previews:0},{rules:0,codes:0,previews:1},{rules:0,codes:'0',previews:0},{rules:0,previews:0}])test('nonzero or unknown dependencies refuse '+JSON.stringify(counts),async()=>{const f=fixture({counts});await assert.rejects(f.invoke(),/dependencies/);assert.equal(f.generated.length,0);});
for(const fail of ['network','500','malformed'])test('ambiguous accepted write '+fail+' stops with no retry; name blocks rerun',async()=>{const f=fixture({fail});await assert.rejects(f.invoke(),/provider_state_unverified_stop/);assert.equal(f.requests.filter(r=>r.method==='PATCH').length,1);assert.ok(f.generated[0].every(x=>x===0));await assert.rejects(f.invoke(),/prior_context/);assert.equal(f.generated.length,1);});
test('postwrite binding drift stops',async()=>{const f=fixture({postDrift:true});await assert.rejects(f.invoke(),/postwrite_drift/);assert.ok(f.generated[0].every(x=>x===0));});
test('CLI boundary without permission refuses and never echoes secret input',()=>{const p=spawnSync(process.execPath,['scripts/provision-context-secret.mjs'],{encoding:'utf8',env:{CLOUDFLARE_API_TOKEN:'sensitive-sentinel'}});assert.equal(p.status,1);assert.ok(!p.stdout.includes('sensitive')&&!p.stderr.includes('sensitive'));assert.match(p.stderr,/execution boundary/);});

for(const nameDrift of ['missing','extra'])test('postwrite secret delta '+nameDrift+' refuses',async()=>{const f=fixture({nameDrift});await assert.rejects(f.invoke(),/postwrite_drift/);assert.ok(f.generated[0].every(x=>x===0));});
for(const settingsShape of ['missing','duplicate'])test('unknown settings '+settingsShape+' refuses before generation',async()=>{const f=fixture({settingsShape});await assert.rejects(f.invoke(),/settings_unverified/);assert.equal(f.generated.length,0);});
test('positive exact execution boundary and each wrong field refused',()=>{const e={GITHUB_ACTIONS:'true',GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_REF:'refs/heads/main',GITHUB_REPOSITORY:'otpanda/api',CONTEXT_CONFIRM:'initial-context-secret-once',CONTEXT_EXPECTED_SHA:'a'.repeat(40),GITHUB_SHA:'a'.repeat(40)};assert.equal(contextExecutionAllowed(e),true);for(const k of Object.keys(e))assert.equal(contextExecutionAllowed({...e,[k]:'wrong'}),false,k);});
test('ambiguous failure never logs provider text, generated text or token',async()=>{const f=fixture({fail:'network'}),out=[],methods=['log','warn','error'],old=methods.map(k=>console[k]);let error;try{methods.forEach(k=>console[k]=(...a)=>out.push(a.join(' ')));try{await f.invoke();}catch(e){error=e;}assert.ok(error);const text=String(error)+out.join(' ');for(const secret of ['sensitive-provider-error','fixture-token',Buffer.from(Uint8Array.from({length:32},(_,i)=>i*7+13)).toString('base64url')])assert.ok(!text.includes(secret));}finally{methods.forEach((k,i)=>console[k]=old[i]);}});
