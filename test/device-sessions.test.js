import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { AccountIdentityService } from '../src/account-identity.js';
import {BrowserExchangeService} from '../src/browser-exchanges.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { authenticator } from './passkey-fixture.js';
const NOW=1_800_000_000_000,DAY=86400000;
async function setup(){const db=database();let now=NOW;const identity=new AccountIdentityService(db,{clock:()=>now}),signup=new PasskeySignupService(db,{clock:()=>now});const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'});const c=await signup.begin({email:'a@example.com',emailToken:token,binding:'binding'}),a=authenticator();const account=await signup.finish({token:c.token,binding:'binding',response:a.registration({expected:c.options.challenge})});const proof={...account,verifiedAt:NOW,purpose:'authenticate'};const service=new DeviceSessionService(db,{clock:()=>now});return {db,service,proof,setNow:v=>now=v};}
test('hash-only persistent refresh and short access bind credential, owner and generation',async()=>{
 const {db,service,proof}=await setup(),s=await service.issue({proof,clientKind:'web'});assert.ok(s);assert.equal((await service.authenticate(s.access)).ownerId,proof.ownerId);assert.equal(await service.authenticate(s.refresh),undefined);
 const rows=JSON.stringify(db.sqlite.prepare('SELECT * FROM device_refresh_handles').all());assert.ok(!rows.includes(s.refresh));assert.equal(await service.authenticate(s.access+'x'),undefined);db.sqlite.close();
});
test('rotation slides inactivity without forced monthly login; old access expires',async()=>{
 const {db,service,proof,setNow}=await setup(),s=await service.issue({proof,clientKind:'web'});setNow(NOW+29*DAY);assert.equal(await service.authenticate(s.access),undefined);const r=await service.rotate(s.refresh);assert.equal(r.status,'rotated');setNow(NOW+45*DAY);assert.equal((await service.rotate(r.refresh)).status,'rotated');db.sqlite.close();
});
test('inactivity expiry and stale/future proofs deny',async()=>{
 const {db,service,proof,setNow}=await setup();assert.equal(await service.issue({proof:{...proof,verifiedAt:NOW+1},clientKind:'web'}),undefined);assert.equal(await service.issue({proof:{...proof,purpose:'step-up'},clientKind:'web'}),undefined);const s=await service.issue({proof,clientKind:'web'});setNow(NOW+30*DAY);assert.equal((await service.rotate(s.refresh)).status,'denied');assert.equal(await service.issue({proof,clientKind:'web'}),undefined);db.sqlite.close();
});
test('concurrent rotation has one winner and bounded grace never returns successor',async()=>{
 const {db,service,proof,setNow}=await setup(),s=await service.issue({proof,clientKind:'web'});const results=await Promise.all([service.rotate(s.refresh),service.rotate(s.refresh)]);assert.equal(results.filter(x=>x.status==='rotated').length,1);assert.equal(results.filter(x=>x.status==='retry').length,1);const r=results.find(x=>x.status==='rotated');assert.ok(await service.authenticate(r.access));assert.deepEqual(await service.rotate(s.refresh),{status:'retry'});setNow(NOW+10001);assert.deepEqual(await service.rotate(s.refresh),{status:'denied'});assert.equal(await service.authenticate(r.access),undefined);assert.equal((await service.rotate(r.refresh)).status,'denied');db.sqlite.close();
});
test('revoke, credential revoke and generation reset invalidate access/refresh immediately',async()=>{
 for(const change of ['device','credential','generation']){const {db,service,proof}=await setup(),s=await service.issue({proof,clientKind:'web'});if(change==='device'){assert.equal(await service.revoke({ownerId:'other',deviceId:s.deviceId}),false);assert.equal(await service.revoke({ownerId:proof.ownerId,deviceId:s.deviceId}),true);}if(change==='credential')db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=?').run(NOW);if(change==='generation')db.sqlite.prepare('UPDATE account_security SET generation=generation+1').run();assert.equal(await service.authenticate(s.access),undefined);assert.equal((await service.rotate(s.refresh)).status,'denied');if(change!=='device')assert.equal(await service.issue({proof,clientKind:'web'}),undefined);db.sqlite.close();}
});
test('session insertion sees credential or generation changes after proof, before effects',async()=>{
 const {db,service,proof}=await setup();db.sqlite.prepare('UPDATE account_security SET generation=generation+1').run();assert.equal(await service.issue({proof,clientKind:'web'}),undefined);assert.equal(db.sqlite.prepare('SELECT count(*) n FROM device_sessions').get().n,0);assert.equal(db.sqlite.prepare('SELECT count(*) n FROM device_refresh_handles').get().n,0);db.sqlite.close();
});
test('forged old refresh never revokes a valid device and cleanup is bounded',async()=>{
 const {db,service,proof,setNow}=await setup(),s=await service.issue({proof,clientKind:'web'});const changed=s.refresh.slice(0,-2)+(s.refresh.at(-2)==='A'?'B':'A')+s.refresh.at(-1);assert.equal((await service.rotate(changed)).status,'denied');assert.ok(await service.authenticate(s.access));setNow(NOW+5*60000);assert.equal((await service.cleanup({limit:1}))[0],1);assert.equal(db.sqlite.prepare('SELECT count(*) n FROM device_sessions').get().n,1);setNow(NOW+30*DAY);await service.cleanup({limit:1});assert.equal(db.sqlite.prepare('SELECT count(*) n FROM device_sessions').get().n,0);assert.equal(db.sqlite.prepare('SELECT count(*) n FROM device_refresh_handles').get().n,0);await assert.rejects(service.cleanup({limit:0}));db.sqlite.close();
});
test('revoking all owner devices prevents every outstanding access and refresh',async()=>{
 const {db,service,proof}=await setup(),a=await service.issue({proof,clientKind:'web'}),b=await service.issue({proof,clientKind:'android'});assert.equal(await service.revokeAll('other'),0);assert.equal(await service.revokeAll(proof.ownerId),2);for(const s of [a,b]){assert.equal(await service.authenticate(s.access),undefined);assert.equal((await service.rotate(s.refresh)).status,'denied');}db.sqlite.close();
});
test('rotation checks security generation inside final transaction, not just preflight',async()=>{
 const {db,service,proof}=await setup(),s=await service.issue({proof,clientKind:'web'}),batch=db.batch;db.batch=async statements=>{db.sqlite.prepare('UPDATE account_security SET generation=generation+1').run();return batch(statements);};assert.equal((await service.rotate(s.refresh)).status,'retry');assert.equal(db.sqlite.prepare('SELECT count(*) n FROM device_refresh_handles').get().n,1);assert.equal(await service.authenticate(s.access),undefined);db.sqlite.close();
});
test('session proof freshness is rechecked after asynchronous token generation',async()=>{
 const {db,proof}=await setup();let calls=0;const service=new DeviceSessionService(db,{clock:()=>++calls===1?NOW:NOW+120000});assert.equal(await service.issue({proof,clientKind:'web'}),undefined);assert.equal(db.sqlite.prepare('SELECT count(*) n FROM device_sessions').get().n,0);db.sqlite.close();
});
test('cleanup retains recent spent-handle replay detection while deleting old history',async()=>{
 const {db,service,proof,setNow}=await setup(),s=await service.issue({proof,clientKind:'web'});setNow(NOW+DAY);const r=await service.rotate(s.refresh);setNow(NOW+29*DAY);const later=await service.rotate(r.refresh);setNow(NOW+32*DAY);await service.cleanup({limit:500});assert.equal((await service.rotate(s.refresh)).status,'denied');assert.ok(await service.authenticate((await service.rotate(later.refresh)).access));assert.equal((await service.rotate(r.refresh)).status,'denied');assert.equal((await service.rotate(later.refresh)).status,'denied');db.sqlite.close();
});

test('active device ceiling is atomic; revocation frees room',async()=>{
 const {db,service,proof}=await setup();try {
 const results=await Promise.all(Array.from({length:55},()=>service.issue({proof,clientKind:'web'})));
 assert.equal(results.filter(Boolean).length,50);assert.equal(db.sqlite.prepare('SELECT count(*) n FROM device_sessions').get().n,50);
 await service.revoke({ownerId:proof.ownerId,deviceId:results.find(Boolean).deviceId});assert.ok(await service.issue({proof,clientKind:'web'}));
 }finally{db.sqlite.close();}
});
test('active access ceiling denies rotation without spending refresh and expiry frees room',async()=>{
 const {db,service,proof,setNow}=await setup();try {
 const s=await service.issue({proof,clientKind:'web'});let refresh=s.refresh;
 for(let i=0;i<63;i++){const r=await service.rotate(refresh);assert.equal(r.status,'rotated');refresh=r.refresh;}
 assert.equal((await service.rotate(refresh)).status,'retry');assert.equal(db.sqlite.prepare('SELECT used_at FROM device_refresh_handles ORDER BY created_at DESC,rowid DESC LIMIT 1').get().used_at,null);
 setNow(NOW+300001);assert.equal((await service.rotate(refresh)).status,'rotated');
 }finally{db.sqlite.close();}
});

test('refresh history ceiling fails closed without consuming current handle',async()=>{
 const {db,service,proof}=await setup();try {
 const d=await service.issue({proof,clientKind:'web'}),insert=db.sqlite.prepare('INSERT INTO device_refresh_handles(handle_id,secret_digest,device_id,created_at,used_at) VALUES (?,?,?,?,?)');
 for(let i=0;i<9999;i++)insert.run('synthetic-'+i,'a'.repeat(64),d.deviceId,NOW,NOW);
 assert.equal((await service.rotate(d.refresh)).status,'retry');assert.equal(db.sqlite.prepare('SELECT count(*) n FROM device_refresh_handles').get().n,10000);
 }finally{db.sqlite.close();}
});

const LOGIN_REDIRECT='https://otpanda.github.io/app/',BIND='f'.repeat(64),CHALLENGE='a'.repeat(43);
function loginArgs(x,priorRefresh,patch={}){return{proof:x.proof,browserBindingDigest:BIND,priorRefresh,challenge:CHALLENGE,redirectUri:LOGIN_REDIRECT,deadline:NOW+60000,...patch};}
test('browser login atomically retires exact prior and old access/refresh/exchange while new session works',async()=>{
 const x=await setup(),old=await x.service.issue({proof:x.proof,clientKind:'web'}),other=await x.service.issue({proof:x.proof,clientKind:'web'});
 const exchanges=new BrowserExchangeService(x.db,{clock:()=>NOW,redirectUri:LOGIN_REDIRECT});
 const pending=await exchanges.mint({deviceId:old.deviceId,challenge:CHALLENGE,redirectUri:LOGIN_REDIRECT});
 const current=await x.service.issueBrowserLogin(loginArgs(x,old.refresh));assert.ok(current);
 assert.equal(await x.service.authenticate(old.access),undefined);assert.equal((await x.service.rotate(old.refresh)).status,'denied');
 assert.ok(await x.service.authenticate(other.access));assert.equal((await x.service.rotate(current.refresh)).status,'rotated');
 assert.equal(x.db.sqlite.prepare('SELECT revoked_at FROM device_sessions WHERE device_id=?').get(old.deviceId).revoked_at,NOW);
 assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM browser_exchanges WHERE device_id=?').get(current.deviceId).n,1);x.db.sqlite.close();
});
test('invalid,oversize,forged,used and native prior are ignored read-only without retirement',async()=>{
 for(const kind of ['missing','malformed','oversize','forged','used','android']){
  const x=await setup(),old=await x.service.issue({proof:x.proof,clientKind:kind==='android'?'android':'web'});let prior=old.refresh;
  if(kind==='missing')prior=undefined;if(kind==='malformed')prior='bad';if(kind==='oversize')prior='x'.repeat(10000);
  if(kind==='forged')prior=old.refresh.slice(0,40)+(old.refresh[40]==='A'?'B':'A')+old.refresh.slice(41);
  if(kind==='used'){await x.service.rotate(old.refresh);x.setNow(NOW+10001);}
  const result=await x.service.issueBrowserLogin(loginArgs(x,prior));assert.ok(result,kind);
  assert.equal(x.db.sqlite.prepare('SELECT revoked_at FROM device_sessions WHERE device_id=?').get(old.deviceId).revoked_at,null,kind);
  x.db.sqlite.close();
 }
});
test('crossowner prior is ignored for an independently valid other owner proof',async()=>{
 const x=await setup(),old=await x.service.issue({proof:x.proof,clientKind:'web'});
 const identity=new AccountIdentityService(x.db,{clock:()=>NOW}),signup=new PasskeySignupService(x.db,{clock:()=>NOW}),a=authenticator();
 const {token}=await identity.issueEmailChallenge({purpose:'signup-email',email:'other@example.test'}),c=await signup.begin({email:'other@example.test',emailToken:token,binding:'other'});
 const account=await signup.finish({token:c.token,binding:'other',response:a.registration({expected:c.options.challenge})});
 const result=await x.service.issueBrowserLogin(loginArgs(x,old.refresh,{proof:{...account,verifiedAt:NOW,purpose:'authenticate'}}));assert.ok(result);
 assert.ok(await x.service.authenticate(old.access));assert.equal(x.db.sqlite.prepare('SELECT owner_id FROM device_sessions WHERE device_id=?').get(result.deviceId).owner_id,account.ownerId);x.db.sqlite.close();
});
test('50-device cap discounts only eligible prior; fallback without prior cannot exceed it',async()=>{
 const x=await setup(),devices=[];for(let i=0;i<50;i++)devices.push(await x.service.issue({proof:x.proof,clientKind:'web'}));
 assert.equal(await x.service.issueBrowserLogin(loginArgs(x,'bad')),undefined);
 const result=await x.service.issueBrowserLogin(loginArgs(x,devices[0].refresh));assert.ok(result);
 assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions WHERE revoked_at IS NULL').get().n,50);
 assert.ok(await x.service.issueBrowserLogin(loginArgs(x,devices[1].refresh)));
 assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions WHERE revoked_at IS NULL').get().n,50);x.db.sqlite.close();
});
test('rotation or prior logout before atomic commit falls back without touching prior successor',async()=>{
 for(const action of ['rotate','logout']){
  const x=await setup(),old=await x.service.issue({proof:x.proof,clientKind:'web'}),batch=x.db.batch.bind(x.db);let once=false,rotated;
  x.db.batch=async statements=>{if(!once){once=true;if(action==='rotate')rotated=await x.service.rotate(old.refresh);else await x.service.logoutBrowser(old.refresh);}return batch(statements);};
  assert.ok(await x.service.issueBrowserLogin(loginArgs(x,old.refresh)),action);
  if(rotated)assert.ok(await x.service.authenticate(rotated.access));
  x.db.sqlite.close();
 }
});
test('new binding logout, credential revoke and generation change deny all replacement effects',async()=>{
 for(const action of ['binding','credential','generation']){
  const x=await setup(),old=await x.service.issue({proof:x.proof,clientKind:'web'}),batch=x.db.batch.bind(x.db);let once=false;
  x.db.batch=async statements=>{if(!once){once=true;if(action==='binding')await x.service.logoutBrowser(undefined,BIND);if(action==='credential')x.db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=?').run(NOW);if(action==='generation')x.db.sqlite.prepare('UPDATE account_security SET generation=generation+1').run();}return batch(statements);};
  assert.equal(await x.service.issueBrowserLogin(loginArgs(x,old.refresh)),undefined,action);
  assert.equal(x.db.sqlite.prepare('SELECT revoked_at FROM device_sessions WHERE device_id=?').get(old.deviceId).revoked_at,null);
  assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions').get().n,1);x.db.sqlite.close();
 }
});
test('exchange insert failure atomically rolls back replacement and child no-op preserves prior',async()=>{
 for(const mode of ['abort','ignore']){
  const x=await setup(),old=await x.service.issue({proof:x.proof,clientKind:'web'});
  x.db.sqlite.exec(`CREATE TRIGGER stop_exchange BEFORE INSERT ON browser_exchanges BEGIN SELECT RAISE(${mode==='abort'?"ABORT,'synthetic failure'":'IGNORE'}); END`);
  const run=()=>x.service.issueBrowserLogin(loginArgs(x,old.refresh));
  if(mode==='abort')await assert.rejects(run,/synthetic failure/);else assert.equal(await run(),undefined);
  assert.ok(await x.service.authenticate(old.access));assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions WHERE revoked_at IS NULL').get().n,1);x.db.sqlite.close();
 }
});

test('fresh repeated logins replace prior without accumulating devices, cap fallback races stay bounded',async()=>{
 const x=await setup();let prior=await x.service.issue({proof:x.proof,clientKind:'web'});
 for(let i=0;i<55;i++){const result=await x.service.issueBrowserLogin(loginArgs(x,prior.refresh));assert.ok(result);prior=result;}
 assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions WHERE revoked_at IS NULL').get().n,1);
 x.db.sqlite.close();
});
test('cap and retirement share exact predicate for rotate-at-cap and revoked credential prior',async()=>{
 const x=await setup(),devices=[];for(let i=0;i<50;i++)devices.push(await x.service.issue({proof:x.proof,clientKind:'web'}));
 const batch=x.db.batch.bind(x.db);let injected=false;
 x.db.batch=async statements=>{if(!injected){injected=true;await x.service.rotate(devices[0].refresh);}return batch(statements);};
 assert.equal(await x.service.issueBrowserLogin(loginArgs(x,devices[0].refresh)),undefined);
 assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions WHERE revoked_at IS NULL').get().n,50);x.db.sqlite.close();
});

test('concurrent verified replacements never exceed cap, with same or distinct prior',async()=>{
 for(const same of [true,false]){
  const x=await setup(),devices=[];for(let i=0;i<50;i++)devices.push(await x.service.issue({proof:x.proof,clientKind:'web'}));
  const results=await Promise.all([x.service.issueBrowserLogin(loginArgs(x,devices[0].refresh)),x.service.issueBrowserLogin(loginArgs(x,devices[same?0:1].refresh))]);
  assert.equal(results.filter(Boolean).length,same?1:2);
  assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions WHERE revoked_at IS NULL').get().n,50);x.db.sqlite.close();
 }
});
test('unexpected refresh/access child no-op never retires prior or leaves usable replacement',async()=>{
 for(const table of ['device_refresh_handles','device_access_handles']){
  const x=await setup(),old=await x.service.issue({proof:x.proof,clientKind:'web'});
  x.db.sqlite.exec(`CREATE TRIGGER stop_child BEFORE INSERT ON ${table} BEGIN SELECT RAISE(IGNORE); END`);
  assert.equal(await x.service.issueBrowserLogin(loginArgs(x,old.refresh)),undefined);
  assert.ok(await x.service.authenticate(old.access));
  assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM device_sessions WHERE revoked_at IS NULL').get().n,1);
  x.db.sqlite.close();
 }
});

test('revokeAll returns direct device count despite realtime trigger writes and stays idempotent',async()=>{
 const {db,service,proof}=await setup();try{
  const a=await service.issue({proof,clientKind:'web'}),b=await service.issue({proof,clientKind:'android'});
  db.sqlite.exec('DELETE FROM realtime_outbox');
  assert.equal(await service.revokeAll('other'),0);
  assert.equal(await service.revokeAll(proof.ownerId),2);
  assert.ok(db.sqlite.prepare('SELECT count(*) n FROM realtime_outbox').get().n>0);
  assert.equal(await service.revokeAll(proof.ownerId),0);
  for(const s of [a,b])assert.equal(await service.authenticate(s.access),undefined);
 }finally{db.sqlite.close();}
});
