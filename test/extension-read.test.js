import test from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { database } from './sqlite-helper.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { authenticator } from './passkey-fixture.js';
import { CodeCipher } from '../src/code-cipher.js';
import { SourceEntryStore } from '../src/source-entries.js';
import { EntryAccess } from '../src/entry-access.js';
import { createDeviceReadHttp } from '../src/device-read-http.js';
import { createEntryDomainsHttp } from '../src/entry-domains-http.js';
import { NativeSessionService, extensionProfile } from '../src/native-sessions.js';
import { pkceChallenge } from '../src/browser-exchanges.js';
import { base64urlEncode } from '../src/tokens.js';
const NOW=1_800_000_000_000,API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',R1='https://abcdefghijklmnopabcdefghijklmnop.chromiumapp.org/',EXTO='chrome-extension://abcdefghijklmnopabcdefghijklmnop',verifier='v'.repeat(43);
async function fx(extensionOrigins=[EXTO]){
 const db=database(),clock=()=>NOW,a=authenticator(),identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock});
 const e=await identity.issueEmailChallenge({purpose:'signup-email',email:'x@example.test'}),c=await signup.begin({email:'x@example.test',emailToken:e.token,binding:'b'});
 const account=await signup.finish({token:c.token,binding:'b',response:a.registration({expected:c.options.challenge})}),sessions=new DeviceSessionService(db,{clock});
 const proof={...account,purpose:'authenticate',verifiedAt:NOW},web=await sessions.issue({proof,clientKind:'web'}),android=await sessions.issue({proof,clientKind:'android'});
 const ext=new NativeSessionService(db,{clock,profile:extensionProfile([R1])}),kp=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign']);
 const m=await ext.mint({sourceDeviceId:web.deviceId,challenge:await pkceChallenge(verifier),redirectUri:R1}),extDev=await ext.exchange({code:m.code,verifier,redirectUri:R1,renewalKey:base64urlEncode(new Uint8Array(await crypto.subtle.exportKey('raw',kp.publicKey)))});
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']),cipher=new CodeCipher({keys:new Map([['k',key]]),activeKeyId:'k'}),sources=new SourceEntryStore(db,cipher),access=new EntryAccess(db,sources);
 const source=await sources.createSource(account.ownerId,'sms','Phone',NOW),entry=await sources.createEntry(account.ownerId,'test','Test',NOW);
 await sources.receive(account.ownerId,{sourceId:source,eventId:'one',code:'123456',receivedAt:NOW,expiresAt:NOW+60000});await sources.confirm(account.ownerId,source,'one',entry,NOW);
 const reads=createDeviceReadHttp({db,sessions,sources,access,clock,native:true,extensionOrigins}),domains=createEntryDomainsHttp({db,sessions,clock,native:true,extensionOrigins});
 const read=(path,{token,origin,method='GET',search=''}={})=>reads.fetch(new Request(API+'/v1/manage/'+path+search,{method,headers:{...(origin?{origin}:{}),authorization:'Bearer '+token}}),{clientAddress:'1.1.1.1'});
 const dom=(method,{token,origin,body}={})=>domains.fetch(new Request(API+'/v1/manage/entry/domains',{method,headers:{...(origin?{origin}:{}),authorization:'Bearer '+token,'content-type':'application/json'},...(body?{body:JSON.stringify(body)}:{})}),{clientAddress:'1.1.1.1'});
 return{db,web,android,ext:extDev,account,entry,sessions,read,dom,sources};
}
test('extension session GETs entries and active-codes (no Origin or pinned Origin), without CORS headers for the extension origin',async()=>{
 const f=await fx();
 for(const origin of [undefined,EXTO])for(const p of ['entries','active-codes']){const r=await f.read(p,{token:f.ext.access,origin});assert.equal(r.status,200,p+String(origin));}
 const rec=(await (await f.read('active-codes',{token:f.ext.access})).json()).records;assert.equal(rec[0].code,'123456');assert.deepEqual(Object.keys(rec[0]).sort().includes('entryId'),true);
 f.db.sqlite.close();
});
test('extension session cannot read anything else, nor use any other method, nor wrong origin',async()=>{
 const f=await fx();
 for(const p of ['session','unassigned','sources'])assert.equal((await f.read(p,{token:f.ext.access})).status,401,p);
 for(const m of ['POST','PUT','DELETE','PATCH'])assert.notEqual((await f.read('entries',{token:f.ext.access,method:m})).status,200);
 for(const o of [APP,'https://evil.example','chrome-extension://zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz','null'])assert.notEqual((await f.read('entries',{token:f.ext.access,origin:o})).status,200,o);
 assert.equal((await f.read('entries',{token:f.ext.access,search:'?x=1'})).status,400);
 assert.equal((await f.read('entries',{token:f.ext.access,method:'OPTIONS',origin:EXTO})).status,403,'no preflight for extensions');
 f.db.sqlite.close();
});
test('without the extensionOrigins option nothing changes: extension tokens are refused everywhere, web and android unchanged',async()=>{
 const f=await fx(null);
 assert.equal((await f.read('entries',{token:f.ext.access})).status,401);assert.equal((await f.dom('GET',{token:f.ext.access})).status,401);
 assert.equal((await f.read('entries',{token:f.web.access,origin:APP})).status,200);assert.equal((await f.read('entries',{token:f.android.access})).status,200);
 f.db.sqlite.close();
});
test('associations: extension GET only, own associations; POST refused for the extension in every origin shape',async()=>{
 const f=await fx();
 assert.equal((await f.dom('POST',{token:f.android.access,body:{entryId:f.entry,domains:['example.com']}})).status,200);
 const g=await f.dom('GET',{token:f.ext.access});assert.equal(g.status,200);assert.deepEqual(await g.json(),{associations:[{entryId:f.entry,domains:['example.com']}]});assert.equal(g.headers.get('access-control-allow-origin'),null);
 assert.equal((await f.dom('GET',{token:f.ext.access,origin:EXTO})).status,200);
 for(const origin of [undefined,EXTO,APP])assert.notEqual((await f.dom('POST',{token:f.ext.access,origin,body:{entryId:f.entry,domains:['evil.test']}})).status,200,String(origin));
 assert.deepEqual((await (await f.dom('GET',{token:f.android.access})).json()).associations[0].domains,['example.com'],'extension POST changed nothing');
 assert.equal((await f.dom('GET',{token:f.ext.access,origin:'https://evil.example'})).status,403);
 assert.equal((await f.dom('GET',{token:f.web.access})).status,401,'web token without Origin');
 f.db.sqlite.close();
});
test('revoking the extension device or bumping the generation ends read access at once',async()=>{
 const f=await fx();assert.equal((await f.read('entries',{token:f.ext.access})).status,200);
 f.db.sqlite.prepare('UPDATE account_security SET generation=generation+1 WHERE owner_id=?').run(f.account.ownerId);
 assert.equal((await f.read('entries',{token:f.ext.access})).status,401);assert.equal((await f.dom('GET',{token:f.ext.access})).status,401);f.db.sqlite.close();
});
test('default-deny guard: extension mode may be enabled only in the three audited modules',()=>{
 const allowed=new Set(['device-read-http.js','entry-domains-http.js','extension-http.js','device-session-auth.js']);
 for(const f of readdirSync(new URL('../src/',import.meta.url)).filter(f=>f.endsWith('.js'))){
  const s=readFileSync(new URL('../src/'+f,import.meta.url),'utf8');
  if(/extension\s*:\s*true/.test(s))assert.ok(allowed.has(f),f+' enables extension kind and is not audited');
 }
 // the audited read modules restrict it to GET and (device-read) two paths
 assert.match(readFileSync(new URL('../src/device-read-http.js',import.meta.url),'utf8'),/EXT_PATHS=new Set\(\['\/v1\/manage\/entries','\/v1\/manage\/active-codes'\]\)/);
});
