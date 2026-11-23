import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { AccountIdentityService } from '../src/account-identity.js';
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
