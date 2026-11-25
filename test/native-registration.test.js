import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { PasskeySignupService } from '../src/passkey-signup.js';
import { AccountIdentityService } from '../src/account-identity.js';
import { DeviceSessionService } from '../src/device-sessions.js';
import { PasskeyService } from '../src/passkey-service.js';
import { PasskeyVerifier } from '../src/passkey-verifier.js';
import { FirstPasskeyEnrollment } from '../src/first-passkey-enrollment.js';
import { NativeSessionService } from '../src/native-sessions.js';
import { androidOriginsFromFingerprints } from '../src/native-http.js';
import { createAddPasskeyHttp } from '../src/additional-passkey-http.js';
import { createFirstPasskeyHttp } from '../src/first-passkey-http.js';
import { base64urlEncode } from '../src/tokens.js';
import { authenticator } from './passkey-fixture.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',NOW=1_800_000_000_000,ORIGIN=androidOriginsFromFingerprints([Array(32).fill('AB').join(':')])[0];
const enc=u=>base64urlEncode(new Uint8Array(u));
async function newKey(){const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},false,['sign']);return enc(await crypto.subtle.exportKey('raw',k.publicKey));}
const mixed=(db,clock)=>new PasskeyService(db,{clock,verifier:new PasskeyVerifier({androidOrigins:[ORIGIN]})});
const call=(http,path,value={},{grant,origin=null,auth,method='POST',ct='application/json'}={})=>http.fetch(new Request(API+path,{method,headers:{...(origin?{Origin:origin}:{}),'Content-Type':ct,...(auth?{Authorization:'Bearer '+auth}:{}),...(grant?{'X-OTPanda-Enrollment':grant}:{})},body:JSON.stringify(value)}),{clientAddress:'9.9.9.9'});
async function addFixture({native=true,passkeys}={}){
 const db=database(),clock=()=>NOW,identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock}),e=await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.com'}),c=await signup.begin({email:'a@example.com',emailToken:e.token,binding:'binding'}),a=authenticator(),account=await signup.finish({token:c.token,binding:'binding',response:a.registration({expected:c.options.challenge})});
 const sessions=new DeviceSessionService(db,{clock}),proof={ownerId:account.ownerId,credentialId:a.credential.id,generation:account.generation,purpose:'authenticate',verifiedAt:NOW};
 const android=await sessions.issue({proof,clientKind:'android'}),web=await sessions.issue({proof,clientKind:'web'});
 return{db,a,android,web,http:createAddPasskeyHttp({db,sessions,clock,native,passkeys:passkeys??mixed(db,clock)})};
}
const P='/v1/manage/passkey/add/';
test('native add-passkey: android bearer without Origin completes step-up then registers a second passkey with the android origin',async()=>{
 const f=await addFixture(),n=authenticator();
 const vb=await (await call(f.http,P+'verify-begin',{},{auth:f.android.access})).json();
 const vf=await call(f.http,P+'verify-finish',{token:vb.token,response:f.a.assertion({origin:ORIGIN,expected:vb.options.challenge})},{auth:f.android.access});assert.equal(vf.status,200);
 const grant=(await vf.json()).token,rb=await (await call(f.http,P+'register-begin',{},{auth:f.android.access,grant})).json();
 const r=await call(f.http,P+'register-finish',{token:rb.token,response:n.registration({origin:ORIGIN,expected:rb.options.challenge})},{auth:f.android.access,grant});
 assert.equal(r.status,200);assert.equal(r.headers.get('access-control-allow-origin'),null,'no CORS on native');
 assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM passkey_credentials WHERE revoked_at IS NULL').get().n,2);
});
test('native add-passkey boundary: kinds never cross, foreign Origin refused, native flag off refuses no-Origin, web unchanged',async()=>{
 const f=await addFixture();
 assert.equal((await call(f.http,P+'verify-begin',{},{auth:f.web.access})).status,401,'web token without Origin');
 assert.equal((await call(f.http,P+'verify-begin',{},{auth:f.android.access,origin:APP})).status,401,'android token with web Origin');
 assert.equal((await call(f.http,P+'verify-begin',{},{auth:f.android.access,origin:'https://evil.test'})).status,403);
 assert.equal((await call(f.http,P+'verify-begin',{},{})).status,401);
 assert.equal((await call(f.http,P+'verify-begin',{},{auth:f.web.access,origin:APP})).status,200);
 const off=await addFixture({native:false});assert.equal((await call(off.http,P+'verify-begin',{},{auth:off.android.access})).status,403);
});
test('native add-passkey: android-origin assertion refused when the service only knows the web origin',async()=>{
 const g=await addFixture(),web=new PasskeyService(g.db,{clock:()=>NOW}),h=createAddPasskeyHttp({db:g.db,sessions:new DeviceSessionService(g.db,{clock:()=>NOW}),clock:()=>NOW,native:true,passkeys:web});
 const b=await (await call(h,P+'verify-begin',{},{auth:g.android.access})).json();
 assert.equal((await call(h,P+'verify-finish',{token:b.token,response:g.a.assertion({origin:ORIGIN,expected:b.options.challenge})},{auth:g.android.access})).status,403);
});
async function firstFixture(native=true){
 const db=database(),clock=()=>NOW;
 db.sqlite.exec("INSERT INTO accounts(owner_id,created_at) VALUES('o1',0);INSERT INTO account_emails(owner_id,email,verified_at,updated_at) VALUES('o1','g@gmail.com',0,0);INSERT INTO account_security(owner_id) VALUES('o1');INSERT INTO provider_identities(identity_id,owner_id,provider,issuer,subject,email,created_at) VALUES('i1','o1','google','https://accounts.google.com','g-sub-1','g@gmail.com',0)");
 const sessions=new DeviceSessionService(db,{clock}),nat=new NativeSessionService(db,{clock}),dev=await nat.issueProvider({ownerId:'o1',generation:0,issuer:'https://accounts.google.com',subject:'g-sub-1',renewalKey:await newKey()});
 const enrollment=new FirstPasskeyEnrollment(db,{clock,passkeys:mixed(db,clock)}),grant=await enrollment.issue({ownerId:'o1',deviceId:dev.deviceId,generation:0,issuer:'https://accounts.google.com',subject:'g-sub-1',verifiedAt:NOW});
 return{db,dev,grant:grant.token,http:createFirstPasskeyHttp({db,sessions,clock,native,enrollment})};
}
const F='/v1/manage/first-passkey/';
test('native first-passkey: Google-only android device with its grant registers the first passkey via the OS (android origin), once',async()=>{
 const f=await firstFixture(),a=authenticator();
 assert.equal((await call(f.http,F+'begin',{},{auth:f.dev.access})).status,403,'no grant');
 const b=await call(f.http,F+'begin',{},{auth:f.dev.access,grant:f.grant});assert.equal(b.status,200);const c=await b.json();
 assert.equal((await call(f.http,F+'finish',{token:c.token,response:a.registration({origin:'https://evil.test',expected:c.options.challenge})},{auth:f.dev.access,grant:f.grant})).status,403,'wrong origin consumes the grant');
 assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM passkey_credentials').get().n,0);
 assert.equal((await call(f.http,F+'begin',{},{auth:f.dev.access,grant:f.grant})).status,403,'grant is single use');
});
test('native first-passkey happy path and boundary',async()=>{
 const f=await firstFixture(),a=authenticator(),c=await (await call(f.http,F+'begin',{},{auth:f.dev.access,grant:f.grant})).json(),resp=a.registration({origin:ORIGIN,expected:c.options.challenge});
 assert.equal((await call(f.http,F+'finish',{token:c.token,response:resp},{auth:f.dev.access,grant:f.grant,origin:APP})).status,401,'android token with web Origin');
 assert.equal((await call(f.http,F+'finish',{token:c.token,response:resp},{auth:f.dev.access,grant:f.grant,origin:'https://evil.test'})).status,403);
 const r=await call(f.http,F+'finish',{token:c.token,response:resp},{auth:f.dev.access,grant:f.grant});assert.equal(r.status,200);assert.deepEqual(await r.json(),{status:'registered'});
 assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM passkey_credentials WHERE revoked_at IS NULL').get().n,1);
 assert.equal((await call(f.http,F+'finish',{token:c.token,response:resp},{auth:f.dev.access,grant:f.grant})).status,403,'replay');
 const off=await firstFixture(false);assert.equal((await call(off.http,F+'begin',{},{auth:off.dev.access,grant:off.grant})).status,403,'native flag off');
});
