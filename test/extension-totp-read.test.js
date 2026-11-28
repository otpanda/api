import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { database } from './sqlite-helper.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { authenticator } from './passkey-fixture.js';
import { CodeCipher } from '../src/code-cipher.js';
import { SourceEntryStore } from '../src/source-entries.js';
import { EntryAccess } from '../src/entry-access.js';
import { SeedCipher } from '../src/seed-cipher.js';
import { TotpSeedStore, EntryTotpGenerator } from '../src/totp-seeds.js';
import { createTotpReadHttp } from '../src/totp-read-http.js';
import { NativeSessionService, extensionProfile } from '../src/native-sessions.js';
import { pkceChallenge } from '../src/browser-exchanges.js';
import { base64urlEncode } from '../src/tokens.js';
const NOW=1_800_000_000_000,API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',R1='https://abcdefghijklmnopabcdefghijklmnop.chromiumapp.org/',EXTO='chrome-extension://abcdefghijklmnopabcdefghijklmnop',verifier='v'.repeat(43);
const PATHQ='/v1/manage/totp-code?entry=';
async function fx(extensionOrigins=[EXTO],{now=59000}={}){
 let t=now;const clock=()=>t,db=database(),a=authenticator(),identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock});
 const e=await identity.issueEmailChallenge({purpose:'signup-email',email:'x@example.test'}),c=await signup.begin({email:'x@example.test',emailToken:e.token,binding:'b'});
 const account=await signup.finish({token:c.token,binding:'b',response:a.registration({expected:c.options.challenge})}),sessions=new DeviceSessionService(db,{clock});
 const proof={...account,purpose:'authenticate',verifiedAt:t},web=await sessions.issue({proof,clientKind:'web'}),android=await sessions.issue({proof,clientKind:'android'});
 const ext=new NativeSessionService(db,{clock,profile:extensionProfile([R1])}),kp=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign']);
 const m=await ext.mint({sourceDeviceId:web.deviceId,challenge:await pkceChallenge(verifier),redirectUri:R1}),extDev=await ext.exchange({code:m.code,verifier,redirectUri:R1,renewalKey:base64urlEncode(new Uint8Array(await crypto.subtle.exportKey('raw',kp.publicKey)))});
 await db.prepare('INSERT INTO accounts VALUES (?,?)').bind('stranger',0).run();
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),keys=new Map([['k',key]]),sources=new SourceEntryStore(db,new CodeCipher({keys,activeKeyId:'k'})),access=new EntryAccess(db,sources),seeds=new TotpSeedStore(db,new SeedCipher({keys,activeKeyId:'k'})),generator=new EntryTotpGenerator(db,seeds,access);
 const entry=await sources.createEntry(account.ownerId,'test','Test',0);await seeds.putSeed(account.ownerId,entry,{secret:new TextEncoder().encode('12345678901234567890'),algorithm:'SHA-1',digits:8,period:30},0);
 const http=createTotpReadHttp({db,sessions,generator,clock,native:true,extensionOrigins});
 const get=(token,{origin,method='GET',entryId=entry,suffix}={})=>http.fetch(new Request(API+(suffix??PATHQ+entryId),{method,headers:{...(origin?{origin}:{}),authorization:'Bearer '+token}}),{clientAddress:'1.1.1.1'});
 return{db,web,android,ext:extDev,account,entry,get,setNow:v=>{t=v;},generator,access,sessions,seeds};
}
test('extension session gets exactly the generated code with no CORS headers, with no Origin or the pinned Origin',async()=>{
 const f=await fx();
 for(const origin of [undefined,EXTO]){const r=await f.get(f.ext.access,{origin});assert.equal(r.status,200,String(origin));assert.equal(r.headers.get('access-control-allow-origin'),null);assert.equal(r.headers.get('cache-control'),'no-store');
  assert.deepEqual(await r.json(),{entryId:f.entry,code:'94287082',period:30,validFrom:30,validUntil:60,serverNow:59000});}
 f.db.sqlite.close();
});
test('only the extension kind: web, android and wrong or foreign origins are refused; web still works unchanged',async()=>{
 const f=await fx();
 assert.equal((await f.get(f.web.access)).status,401,'web token without Origin'); assert.equal((await f.get(f.ext.access,{origin:APP})).status,401,'extension token with the APP origin is not web');
 for(const o of ['https://evil.example','chrome-extension://zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz','null'])assert.equal((await f.get(f.ext.access,{origin:o})).status,403,o);
 assert.equal((await f.get(f.web.access,{origin:APP})).status,200);assert.equal((await f.get(f.android.access)).status,200,'android unchanged');assert.equal((await f.get(f.android.access,{origin:EXTO})).status,401,'android token never reads through the extension origin');
 f.db.sqlite.close();
});
test('no preflight, no other method, strict single-entry query for the extension',async()=>{
 const f=await fx();
 for(const origin of [undefined,EXTO])assert.equal((await f.get(f.ext.access,{origin,method:'OPTIONS'})).status,403,'no preflight '+origin);
 for(const m of ['POST','PUT','DELETE','PATCH'])assert.notEqual((await f.get(f.ext.access,{method:m})).status,200,m);
 for(const q of ['','?entry=','?entry=a&entry=b','?entry='+f.entry+'&owner=x','?entry='+f.entry+'&now=1','?entry='+'x'.repeat(257)])assert.equal((await f.get(f.ext.access,{suffix:'/v1/manage/totp-code'+q})).status,400,q);
 f.db.sqlite.close();
});
test('only entries the viewer can read: unknown and unshared look identical; sharing, revocation, seed removal and ownership are enforced',async()=>{
 const f=await fx();
 await f.db.prepare('INSERT INTO accounts VALUES (?,?)').bind('recipient',0).run();
 const rows=await f.db.prepare("SELECT entry_id FROM entries WHERE entry_id=?").bind(f.entry).first();assert.ok(rows);
 // another owner's entry: the extension of account A cannot read B's entry, and cannot tell it from a missing one
 const {SourceEntryStore:S}=await import('../src/source-entries.js'),{CodeCipher:C}=await import('../src/code-cipher.js');
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),sources=new S(f.db,new C({keys:new Map([['k',key]]),activeKeyId:'k'}));
 const other=await sources.createEntry('stranger','test','Other',0);
 await f.seeds.putSeed('stranger',other,{secret:new TextEncoder().encode('12345678901234567890'),algorithm:'SHA-1',digits:8,period:30},0);
 const miss=await f.get(f.ext.access,{entryId:'missing'}),foreign=await f.get(f.ext.access,{entryId:other});
 assert.equal(miss.status,404);assert.equal(foreign.status,404);assert.deepEqual(await foreign.json(),await miss.json());
 // share to the extension's owner, then revoke
 await f.access.share('stranger',other,f.account.ownerId,{},0);
 const shared=await f.get(f.ext.access,{entryId:other});assert.equal(shared.status,200);assert.equal((await shared.json()).code,'94287082');
 await f.access.revoke('stranger',other,f.account.ownerId,59000);
 assert.equal((await f.get(f.ext.access,{entryId:other})).status,404,'revoked share');
 // share again, then the owner removes the seed during decrypt: no stale code
 await f.access.share('stranger',other,f.account.ownerId,{},0);assert.equal((await f.get(f.ext.access,{entryId:other})).status,200);
 const dec=f.seeds.cipher.decrypt.bind(f.seeds.cipher);f.seeds.cipher.decrypt=async(...a)=>{const t=await dec(...a);await f.seeds.removeSeed('stranger',other);return t;};
 const gone=await f.get(f.ext.access,{entryId:other});assert.equal(gone.status,404);assert.equal((await gone.text()).includes('94287082'),false);
 f.seeds.cipher.decrypt=dec;
 // a revoke in the middle of a share read also suppresses the code
 await f.seeds.putSeed('stranger',other,{secret:new TextEncoder().encode('12345678901234567890'),algorithm:'SHA-1',digits:8,period:30},0);
 await f.access.share('stranger',other,f.account.ownerId,{},0);
 f.seeds.cipher.decrypt=async(...a)=>{const t=await dec(...a);await f.access.revoke('stranger',other,f.account.ownerId,59000);return t;};
 assert.equal((await f.get(f.ext.access,{entryId:other})).status,404);
 f.db.sqlite.close();
});
test('no seed or envelope field can leave, and a malformed generation is refused',async()=>{
 const f=await fx();const good=f.generator.generateForActor.bind(f.generator);
 f.generator.generateForActor=async(...a)=>({...await good(...a),secret:'synthetic',envelope:'synthetic',algorithm:'SHA-1'});
 const r=await f.get(f.ext.access);assert.deepEqual(Object.keys(await r.json()).sort(),['code','entryId','period','serverNow','validFrom','validUntil']);
 f.generator.generateForActor=async(...a)=>({...await good(...a),code:'secret'});assert.equal((await f.get(f.ext.access)).status,503);
 f.db.sqlite.close();
});
test('revoking the extension device, bumping the generation, or a revoke during generation ends access with no code',async()=>{
 const f=await fx();assert.equal((await f.get(f.ext.access)).status,200);
 const good=f.generator.generateForActor.bind(f.generator);
 f.generator.generateForActor=async(...a)=>{const v=await good(...a);f.db.sqlite.prepare('UPDATE account_security SET generation=generation+1 WHERE owner_id=?').run(f.account.ownerId);return v;};
 const r=await f.get(f.ext.access);assert.equal(r.status,401);assert.equal((await r.text()).includes('94287082'),false);
 f.generator.generateForActor=good;assert.equal((await f.get(f.ext.access)).status,401);
 f.db.sqlite.close();
});
test('extension budget: 20 per owner per minute with Retry-After, before any further generation; web budget is separate',async()=>{
 const f=await fx();let calls=0;const good=f.generator.generateForActor.bind(f.generator);f.generator.generateForActor=async(...a)=>{calls++;return good(...a);};
 for(let i=0;i<20;i++)assert.equal((await f.get(f.ext.access)).status,200,String(i));
 const r=await f.get(f.ext.access);assert.equal(r.status,429);assert.ok(Number(r.headers.get('retry-after'))>0);assert.equal(calls,20);assert.equal(r.headers.get('access-control-allow-origin'),null);
 assert.equal((await f.get(f.web.access,{origin:APP})).status,200,'the web budget is not spent by the extension');
 f.setNow(120000);assert.equal((await f.get(f.ext.access)).status,200,'a new minute resets');
 f.db.sqlite.close();
});
test('without the extensionOrigins option nothing changes: the extension token is refused here',async()=>{
 const f=await fx(null);
 for(const origin of [undefined,EXTO])assert.notEqual((await f.get(f.ext.access,{origin})).status,200,String(origin));
 assert.equal((await f.get(f.web.access,{origin:APP})).status,200);f.db.sqlite.close();
});
test('default-deny guard: the extension kind and totp-code stay inside the audited modules and the edge allowlist names totp-code explicitly',()=>{
 const rd=n=>readFileSync(new URL('../src/'+n,import.meta.url),'utf8');
 assert.match(rd('totp-read-http.js'),/createDeviceSessionAuth\(\{sessions,extension:true,extensionOrigins\}\)/);
 assert.match(rd('device-read-http.js'),/EXT_PATHS=new Set\(\['\/v1\/manage\/entries','\/v1\/manage\/active-codes'\]\)/,'the device read allowlist is not widened');
 assert.match(rd('identity-edge-host.js'),/\['\/v1\/manage\/entries','\/v1\/manage\/active-codes','\/v1\/manage\/entry\/domains','\/v1\/manage\/totp-code'\]\.includes\(p\)/);
 for(const p of ['/v1/manage/totp','/v1/manage/totp/begin','/v1/manage/session','/v1/manage/unassigned'])assert.equal(rd('identity-edge-host.js').includes("'"+p+"'].includes(p)&&origin!==APP"),false);
});
test('edge host: the extension reaches totp-code only with extensionApi, GET, no APP origin, on the read budget; nothing else under /v1/manage/totp',async()=>{
 const {createIdentityEdgeHost}=await import('../src/identity-edge-host.js');
 const run=async(extensionApi,path,{method='GET',origin}={})=>{const seen=[];let init=0;const yes={limit:async({key})=>{seen.push(key);return{success:true};}};
  const host=createIdentityEdgeHost({resolveTrustedIngress:()=> '203.0.113.9',edgeAddress:yes,edgeAuthGlobal:yes,edgeReadGlobal:yes,extensionApi,extensionOrigins:[EXTO],initialize:async()=>{init++;return{fetch:async()=>new Response('{}')};}});
  const r=await host.fetch(new Request(API+path,{method,headers:origin?{origin}:{}}));return{status:r.status,seen,init};};
 const ok=await run(true,'/v1/manage/totp-code?entry=x');assert.equal(ok.status,200);assert.equal(ok.init,1);assert.ok(ok.seen.length>=2);
 for(const o of [EXTO])assert.equal((await run(true,'/v1/manage/totp-code?entry=x',{origin:o})).init,1,o);
 assert.equal((await run(true,'/v1/manage/totp-code?entry=x',{origin:'https://evil.example'})).init,0,'foreign origin never reaches D1');
 assert.equal((await run(true,'/v1/manage/totp-code?entry=x',{method:'POST'})).init,0);
 for(const p of ['/v1/manage/totp','/v1/manage/totp/begin','/v1/manage/session','/v1/manage/sources','/v1/manage/unassigned','/v1/manage/unassigned-context'])assert.equal((await run(true,p)).init,0,p);
});
