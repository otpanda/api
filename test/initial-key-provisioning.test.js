import test from 'node:test';
import assert from 'node:assert/strict';
import {provisionInitialKey} from '../scripts/provision-initial-key.mjs';
function fixture({present=[],reserved=false,count=0,failAt=0,partial=false}={}) {
  let calls=0,generated=0,uploads=0,marker=reserved,seen=new Set(present),bytes;
  const fetchImpl=async(url,options={})=>{
    calls++;
    if(calls===failAt)throw new Error('sentinel-provider-secret-must-not-escape');
    if(url==='https://fixed.test/health')return {ok:true,json:async()=>({service:'otpanda-api',authentication:'disabled'})};
    if(url.endsWith('/secrets')&&!options.body)return ok([...seen].map(name=>({name,type:'secret_text',text:'sentinel-provider-secret-must-not-escape'})));
    const body=JSON.parse(options.body);
    if(url.endsWith('/secrets-bulk')) {
      uploads++;
      assert.equal(options.method,'PATCH');
      assert.equal(options.headers['Content-Type'],'application/merge-patch+json');
      const keys=JSON.parse(body.secrets.ENCRYPTION_KEYRING.text);
      assert.equal(keys.length,1);assert.equal(Buffer.from(keys[0].key,'base64url').length,32);
      seen.add('ENCRYPTION_KEYRING');if(!partial)seen.add('ACTIVE_KEY_ID');
      return ok({text:'sentinel-provider-secret-must-not-escape'});
    }
    if(body.sql==='SELECT singleton FROM initial_key_provisioning')return db(marker?[{singleton:1}]:[]);
    if(body.sql.startsWith('SELECT (SELECT count'))return db([{dependencies:count}]);
    if(body.sql.startsWith('INSERT INTO')){assert.equal(marker,false);marker=true;return db([{singleton:1}]);}
    if(body.sql.startsWith('UPDATE'))return db([{singleton:1}]);
    throw new Error('unexpected request');
  };
  function ok(result){return {ok:true,json:async()=>({success:true,errors:[],result})};}
  function db(results){return ok([{success:true,results}]);}
  return {options:{token:'fixture-token',runId:'123',fetchImpl,generate:()=>{generated++;bytes=new Uint8Array(32).fill(42);return bytes;},now:()=>1234,healthUrl:'https://fixed.test/health'},state:()=>({generated,uploads,marker,bytes})};
}
test('initial provisioning creates a single immutable keyring through bulk and zeroes bytes',async()=>{
  const f=fixture({present:['GOOGLE_CLIENT_SECRET']});
  assert.deepEqual(await provisionInitialKey(f.options),{keyId:'initial-v1',status:'bindings_created_not_activated'});
  assert.equal(f.state().uploads,1);assert.equal(f.state().generated,1);assert.ok(f.state().bytes.every(x=>x===0));
});
for(const present of [['ENCRYPTION_KEYRING'],['ACTIVE_KEY_ID'],['ENCRYPTION_KEYRING','ACTIVE_KEY_ID']])test('existing key binding refuses generation '+present.join(','),async()=>{const f=fixture({present});await assert.rejects(()=>provisionInitialKey(f.options));assert.equal(f.state().generated,0);});
test('durable prior attempt prevents regeneration even when bindings missing',async()=>{const f=fixture({reserved:true});await assert.rejects(()=>provisionInitialKey(f.options));assert.equal(f.state().generated,0);});
test('ciphertext dependency prevents generation',async()=>{const f=fixture({count:1});await assert.rejects(()=>provisionInitialKey(f.options));assert.equal(f.state().generated,0);});
for(let failAt=1;failAt<=8;failAt++)test('failure at request '+failAt+' is sanitized and never retries',async()=>{const f=fixture({failAt});await assert.rejects(()=>provisionInitialKey(f.options),e=>!e.message.includes('sentinel'));assert.ok(f.state().uploads<=1);if(f.state().bytes)assert.ok(f.state().bytes.every(x=>x===0));});
test('partial binding metadata preserves reservation and fails',async()=>{const f=fixture({partial:true});await assert.rejects(()=>provisionInitialKey(f.options),/binding_metadata_unverified/);assert.equal(f.state().marker,true);assert.equal(f.state().uploads,1);});
import {database} from './sqlite-helper.js';
import {spawnSync} from 'node:child_process';
test('reservation SQL executes against actual migrated SQLite and refuses repeated reservation',async()=>{
 const db=database();let requests=0;
 try{
  const f=fixture();const original=f.options.fetchImpl;
  f.options.fetchImpl=async(url,options={})=>{
   if(!url.endsWith('/query'))return original(url,options);
   requests++;const body=JSON.parse(options.body),rows=db.sqlite.prepare(body.sql).all(...body.params);
   return{ok:true,json:async()=>({success:true,errors:[],result:[{success:true,results:rows}]})};
  };
  await provisionInitialKey(f.options);assert.equal(db.sqlite.prepare('SELECT state FROM initial_key_provisioning').get().state,'bindings_written');
  const rerun=fixture();rerun.options.fetchImpl=f.options.fetchImpl;
  await assert.rejects(()=>provisionInitialKey(rerun.options));assert.equal(rerun.state().generated,0);assert.ok(requests>=4);
 }finally{db.sqlite.close();}
});
test('accepted upload followed by timeout is sanitized, keeps marker and never retries',async()=>{
 const f=fixture(),original=f.options.fetchImpl;let accepted=0;
 f.options.fetchImpl=async(url,options)=>{const result=await original(url,options);if(url.endsWith('/secrets-bulk')){accepted++;throw new Error('sentinel-secret-accept-then-timeout');}return result;};
 let thrown;try{await provisionInitialKey(f.options);}catch(error){thrown=error;}
 assert.equal(accepted,1);assert.equal(f.state().marker,true);assert.equal(f.state().generated,1);assert.ok(f.state().bytes.every(x=>x===0));
 assert.ok(!String(thrown.stack).includes('sentinel'));assert.ok(!JSON.stringify(thrown).includes('sentinel'));assert.equal(thrown.cause,undefined);
});
test('CLI boundary refusal never leaks sentinel token to captured process output',()=>{
 const result=spawnSync(process.execPath,['scripts/provision-initial-key.mjs'],{cwd:new URL('..',import.meta.url),env:{PATH:process.env.PATH,CLOUDFLARE_API_TOKEN:'sentinel-never-log-token'},encoding:'utf8'});
 assert.equal(result.status,1);assert.ok(!JSON.stringify(result).includes('sentinel-never-log-token'));assert.match(result.stderr,/execution boundary/);
});
import {verifyBootstrapReadiness} from '../scripts/provision-initial-key.mjs';
test('read-only readiness reconciliation verifies key format and disabled routes',async()=>{let count=0;await verifyBootstrapReadiness({fetchImpl:async url=>{count++;return url.endsWith('/ready')?{ok:true,json:async()=>({service:'otpanda-api',database:'available',keyring:'valid-format',application:'setup-required'})}:{status:503,json:async()=>({error:'setup_required'})};}});assert.equal(count,3);});
test('readiness reconciliation never accepts activated auth or missing keys',async()=>{await assert.rejects(()=>verifyBootstrapReadiness({fetchImpl:async()=>({ok:true,status:200,json:async()=>({})})}),/readiness_or_auth_gate_unverified/);});
test('partial accepted upload then timeout preserves attempt and keeps console output empty',async()=>{
 const f=fixture({partial:true}),original=f.options.fetchImpl;const captured=[];
 const saved={log:console.log,error:console.error,warn:console.warn};
 for(const name of Object.keys(saved))console[name]=(...args)=>captured.push(args);
 try{
  f.options.fetchImpl=async(url,options)=>{const response=await original(url,options);if(url.endsWith('/secrets-bulk'))throw new Error('sentinel-partial-accepted-secret');return response;};
  let failure;try{await provisionInitialKey(f.options);}catch(error){failure=error;}
  assert.ok(failure);assert.equal(f.state().generated,1);assert.equal(f.state().uploads,1);assert.equal(f.state().marker,true);
  assert.ok(f.state().bytes.every(x=>x===0));assert.deepEqual(captured,[]);
  assert.ok(!String(failure.stack).includes('sentinel'));assert.ok(!JSON.stringify(failure).includes('sentinel'));
  // Provider contains only the partial binding. A new run must not generate.
  const again=fixture({present:['ENCRYPTION_KEYRING'],reserved:true});await assert.rejects(()=>provisionInitialKey(again.options));assert.equal(again.state().generated,0);
 }finally{Object.assign(console,saved);}
});
