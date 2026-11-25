import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { PasskeyVerifier } from '../src/passkey-verifier.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { RecoveryControls } from '../src/recovery-controls.js';
import { createPasskeyLabelHttp } from '../src/passkey-label-http.js';
import { providerName,normalAaguid,normalLabel,storeAaguid } from '../src/passkey-providers.js';
import { authenticator } from './passkey-fixture.js';
const NOW=1_800_000_000_000,API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',BW='d548826e-79b4-db40-a3d8-11116f7e8349',ZERO='00000000-0000-0000-0000-000000000000';
test('provider map: verified ids only, case-insensitive, zero/unknown/garbage give null',()=>{
 assert.equal(providerName(BW),'Bitwarden');assert.equal(providerName(BW.toUpperCase()),'Bitwarden');assert.equal(providerName('ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4'),'Google Password Manager');
 for(const id of ['08987058-cadc-4b81-b6e1-30de50dcbe96','9ddd1817-af5a-4672-a2b9-3e3dd95000a9','6028b017-b1d4-4c02-b4b3-afcdafc96bb2'])assert.equal(providerName(id),'Windows Hello');
 for(const v of [ZERO,'11111111-1111-1111-1111-111111111111','',undefined,null,5,'not-a-uuid',BW+'x'])assert.equal(providerName(v),null);
 assert.equal(normalAaguid(ZERO),null);assert.equal(normalAaguid(BW.toUpperCase()),BW);
});
test('label rules: NFC trim 1..40, no control/format/separator chars, null or empty clears',()=>{
 assert.equal(normalLabel('  My phone '),'My phone');assert.equal(normalLabel(null),null);assert.equal(normalLabel(''),null);
 assert.equal(normalLabel('e\u0301'),'\u00e9');
 for(const v of ['   ','a'.repeat(41),'a\nb','a\u0000b','a\u202eb','a\u2028b',5,{},[]])assert.equal(normalLabel(v),undefined,JSON.stringify(v));
 assert.equal(normalLabel('a'.repeat(40)),'a'.repeat(40));
});
async function fixture(aaguid){
 const db=database(),clock=()=>NOW,identity=new AccountIdentityService(db,{clock}),base=new PasskeyVerifier(),verifier={registrationOptions:(...a)=>base.registrationOptions(...a),verifyRegistration:async(...a)=>{const i=await base.verifyRegistration(...a);return i&&{...i,aaguid}}};
 const signup=new PasskeySignupService(db,{clock,verifier}),a=authenticator(),{token}=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'});
 const c=await signup.begin({email:'a@example.com',emailToken:token,binding:'b'}),account=await signup.finish({token:c.token,binding:'b',response:a.registration({expected:c.options.challenge})});
 const sessions=new DeviceSessionService(db,{clock}),d=await sessions.issue({proof:{...account,verifiedAt:NOW,purpose:'authenticate'},clientKind:'web'}),access=(await sessions.rotate(d.refresh,{clientKind:'web'})).access;
 const http=createPasskeyLabelHttp({db,sessions,clock}),rc=new RecoveryControls(db,{clock}),user={ownerId:account.ownerId,deviceId:d.deviceId,generation:0};
 const rename=(body,{token=access,origin=APP,method='POST',ct='application/json'}={})=>http.fetch(new Request(API+'/v1/manage/passkey/rename',{method,headers:{...(origin?{Origin:origin}:{}),...(token?{Authorization:'Bearer '+token}:{}),'Content-Type':ct},...(method==='GET'?{}:{body:typeof body==='string'?body:JSON.stringify(body)})}));
 const list=async()=>(await rc.status(user)).passkeys;
 return{db,account,credentialId:account.credentialId,rename,list,access,sessions,d};
}
test('registration stores the AAGUID silently; status shows provider and label; unknown and zero show null',async()=>{
 const f=await fixture(BW);let p=(await f.list())[0];
 assert.equal(p.provider,'Bitwarden');assert.equal(p.label,null);assert.deepEqual(Object.keys(p).sort(),['createdAt','id','label','lastUsedAt','provider']);assert.equal('aaguid' in p,false,'raw aaguid is never returned');
 f.db.sqlite.close();
 for(const v of [ZERO,'11111111-1111-1111-1111-111111111111',undefined]){const g=await fixture(v);assert.equal((await g.list())[0].provider,null);
  assert.equal(g.db.sqlite.prepare('SELECT count(*) n FROM passkey_metadata WHERE aaguid IS NOT NULL AND aaguid=?').get(ZERO).n,0);g.db.sqlite.close();}
});
test('rename: owner-scoped, session-only, validates, clears, revoked/unknown 404, wrong Origin/web kind refused, keeps AAGUID',async()=>{
 const f=await fixture(BW),id=f.credentialId;
 assert.equal((await f.rename({credentialId:id,label:'  Work laptop '})).status,200);let p=(await f.list())[0];assert.equal(p.label,'Work laptop');assert.equal(p.provider,'Bitwarden');
 assert.equal((await f.rename({credentialId:id,label:null})).status,200);assert.equal((await f.list())[0].label,null);assert.equal((await f.list())[0].provider,'Bitwarden');
 for(const b of [{credentialId:id},{credentialId:id,label:'x',extra:1},{credentialId:id,label:'a'.repeat(41)},{credentialId:id,label:5},{credentialId:5,label:'x'},'{bad',[]])assert.equal((await f.rename(b)).status,400,JSON.stringify(b));
 assert.equal((await f.rename({credentialId:'A'.repeat(43),label:'x'})).status,404,'unknown credential');
 assert.equal((await f.rename({credentialId:id,label:'x'},{token:null})).status,401);assert.equal((await f.rename({credentialId:id,label:'x'},{origin:'https://evil.example'})).status,403);
 assert.equal((await f.rename({credentialId:id,label:'x'},{origin:null})).status,403,'no Origin (native) refused');
 assert.equal((await f.rename({credentialId:id,label:'x'},{ct:'text/plain'})).status,400);assert.equal((await f.rename({credentialId:id,label:'x'},{method:'GET'})).status,405);
 // a credential owned by another account cannot be renamed by this session
 f.db.sqlite.exec('PRAGMA foreign_keys=OFF');f.db.sqlite.prepare("INSERT INTO accounts VALUES ('o2',0)").run();f.db.sqlite.prepare('UPDATE passkey_credentials SET owner_id=\'o2\' WHERE credential_id=?').run(id);
 assert.ok([401,404].includes((await f.rename({credentialId:id,label:'hijack'})).status));assert.equal((await f.list()).length>=0,true);f.db.sqlite.prepare('UPDATE passkey_credentials SET owner_id=? WHERE credential_id=?').run(f.account.ownerId,id);
 // revoked credential and revoked session both refuse
 f.db.sqlite.prepare('UPDATE device_sessions SET revoked_at=? WHERE device_id=?').run(NOW,f.d.deviceId);assert.equal((await f.rename({credentialId:id,label:'late'})).status,401);
 f.db.sqlite.close();
});
test('rename never touches a revoked credential; storeAaguid never overwrites and never throws',async()=>{
 const f=await fixture(BW);f.db.sqlite.prepare('UPDATE passkey_credentials SET revoked_at=? WHERE credential_id=?').run(NOW,f.credentialId);
 assert.ok([401,404].includes((await f.rename({credentialId:f.credentialId,label:'x'})).status));
 await storeAaguid(f.db,{credentialId:f.credentialId,ownerId:f.account.ownerId,aaguid:'ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4'});
 assert.equal(f.db.sqlite.prepare('SELECT aaguid FROM passkey_metadata WHERE credential_id=?').get(f.credentialId).aaguid,BW,'first AAGUID wins');
 await storeAaguid({prepare(){throw Error('boom');}},{credentialId:'x',ownerId:'y',aaguid:BW});
 f.db.sqlite.close();
});
test('rename is routed through the edge host with a web Origin and refused for native no-Origin even when native is on',async()=>{
 const {createIdentityEdgeHost}=await import('../src/identity-edge-host.js'),{createIdentityRuntime}=await import('../src/identity-runtime.js');
 const f=await fixture(BW),yes={limit:async()=>({success:true})};
 const host=createIdentityEdgeHost({nativeApi:true,resolveTrustedIngress:()=>'192.0.2.1',edgeAddress:yes,edgeAuthGlobal:yes,edgeReadGlobal:yes,initialize:async()=>createIdentityRuntime({db:f.db,keys:new Map(),activeKeyId:'x',trustedRequestKey:()=>'192.0.2.1',clock:()=>NOW,native:{enabled:true}})});
 const call=(origin)=>host.fetch(new Request(API+'/v1/manage/passkey/rename',{method:'POST',headers:{...(origin?{Origin:origin}:{}),Authorization:'Bearer '+f.access,'Content-Type':'application/json'},body:JSON.stringify({credentialId:f.credentialId,label:'Phone'})}));
 assert.equal((await call(APP)).status,200);assert.equal((await f.list())[0].label,'Phone');assert.equal((await call(null)).status,403);
 const pre=await host.fetch(new Request(API+'/v1/manage/passkey/rename',{method:'OPTIONS',headers:{Origin:APP,'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'authorization, content-type'}}));assert.equal(pre.status,204);
 f.db.sqlite.close();
});
