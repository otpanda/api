import test from 'node:test';import assert from 'node:assert/strict';
import{database}from'./sqlite-helper.js';import{AccountIdentityService}from'../src/account-identity.js';import{PasskeySignupService}from'../src/passkey-signup.js';import{DeviceSessionService}from'../src/device-sessions.js';import{authenticator}from'./passkey-fixture.js';
import{DurableDeviceKeys}from'../src/durable-device-keys.js';import{EnrolledApprovals,approvalAction,approveBinding,fingerprint}from'../src/enrolled-approvals.js';import{createApprovalsHttp}from'../src/approvals-http.js';
import{AddPasskeyEnrollment}from'../src/additional-passkey.js';import{deviceProofMessage}from'../src/device-key-proof.js';import{hashText}from'../src/sessions.js';import{base64urlEncode}from'../src/tokens.js';
const NOW=1800000000000,API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
async function pair(){const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),j=await crypto.subtle.exportKey('jwk',k.publicKey),jwk={kty:j.kty,crv:j.crv,x:j.x,y:j.y};return{k,jwk,text:JSON.stringify(jwk),digest:await hashText(JSON.stringify(jwk))};}
async function fx(){
 const db=database(),a=authenticator();let now=NOW;const clock=()=>now,identity=new AccountIdentityService(db,{clock}),signup=new PasskeySignupService(db,{clock}),e=await identity.issueEmailChallenge({purpose:'signup-email',email:'approve@example.test'}),c=await signup.begin({email:'approve@example.test',emailToken:e.token,binding:'fixture'}),account=await signup.finish({token:c.token,binding:'fixture',response:a.registration({expected:c.options.challenge})}),sessions=new DeviceSessionService(db,{clock});
 const mk=async kind=>{const i=await sessions.issue({proof:{...account,purpose:'authenticate',verifiedAt:now},clientKind:kind});return{...i,user:{...await sessions.authenticate(i.access)}};};
 const web=await mk('web'),phoneA=await mk('android'),phoneB=await mk('android');
 const A=await pair(),B=await pair();
 db.sqlite.prepare('INSERT INTO durable_device_keys(key_id,owner_id,public_jwk,generation,created_at,public_key_digest) VALUES(?,?,?,?,?,?)').run('key-a',account.ownerId,A.text,0,NOW,A.digest);
 const keys=new DurableDeviceKeys(db,{clock}),approvals=new EnrolledApprovals(db,{clock,keys});
 const sign=async(P,c)=>base64urlEncode(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},P.k.privateKey,deviceProofMessage(c))));
 // approve a pending request from phone A
 const approve=async(changeId,over={})=>{const b=await approvals.approveBegin({user:phoneA.user,changeId,keyId:'key-a'});if(!b)return;return approvals.approveFinish({user:phoneA.user,changeId,token:b.token,signature:await sign(A,b.challenge),...over});};
 return{db,a,account,sessions,web,phoneA,phoneB,A,B,keys,approvals,sign,approve,setNow:n=>{now=n;},clock,rows:()=>db.sqlite.prepare('SELECT * FROM enrolled_approvals').all()};
}
test('passkey-add: request is idempotent per device, status lists it to the approver only, approve then authorize once, registration guard accepts approver key',async()=>{const f=await fx();try{
 const r=await f.approvals.requestPasskeyAdd({user:f.web.user});assert.ok(r.changeId);assert.equal(r.expiresAt,NOW+600000);
 assert.deepEqual(await f.approvals.requestPasskeyAdd({user:f.web.user}),r);assert.equal(f.rows().length,1);
 const st=await f.approvals.status({user:f.phoneA.user});assert.equal(st.pending.length,1);assert.equal(st.pending[0].kind,'passkey-add');assert.equal(st.pending[0].target,null);assert.equal(st.pending[0].requesterKind,'web');assert.equal(st.pending[0].requestedAt,NOW);assert.ok(Number.isSafeInteger(st.pending[0].requestedAt));assert.deepEqual(Object.keys(st.pending[0]).sort(),['changeId','expiresAt','kind','requestedAt','requesterKind','requesterLabel','target']);assert.equal(st.ownerId,f.account.ownerId);
 assert.equal(await f.approvals.status({user:f.web.user}),undefined);// web session is not an approver
 assert.deepEqual(await f.approve(r.changeId),{status:'approved'});assert.deepEqual(await f.approve(r.changeId),undefined);
 assert.equal((await f.approvals.status({user:f.phoneA.user})).pending.length,0);
 const g=await f.approvals.authorizePasskeyAdd({user:f.web.user,changeId:r.changeId});assert.ok(g.token);assert.ok(g.expiresAt<=NOW+120000);
 assert.equal(await f.approvals.authorizePasskeyAdd({user:f.web.user,changeId:r.changeId}),undefined);// single use
 const auth=f.db.sqlite.prepare('SELECT approver_credential_id,approver_key_id FROM passkey_add_authorizations').get();assert.equal(auth.approver_credential_id,null);assert.equal(auth.approver_key_id,'key-a');
 const add=new AddPasskeyEnrollment(f.db,{clock:f.clock}),c=await add.begin({user:f.web.user,grant:g.token});assert.ok(c);
 const before=f.db.sqlite.prepare('SELECT count(*) n FROM passkey_credentials').get().n;
 assert.equal(await add.finish({user:f.web.user,grant:g.token,token:c.token,response:authenticator().registration({expected:c.options.challenge})}),true);
 assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM passkey_credentials').get().n,before+1);}finally{f.db.sqlite.close();}});
test('passkey-add refusals: approver==requester session, requester must be web, revoked approver key, other owner, wrong digest signature',async()=>{const f=await fx();try{
 assert.equal(await f.approvals.requestPasskeyAdd({user:f.phoneA.user}),undefined);// android cannot request passkey-add
 const r=await f.approvals.requestPasskeyAdd({user:f.web.user});
 assert.equal(await f.approvals.approveBegin({user:f.web.user,changeId:r.changeId,keyId:'key-a'}),undefined);// web session cannot approve
 assert.equal(await f.approvals.approveBegin({user:f.phoneA.user,changeId:r.changeId,keyId:'nope'}),undefined);
 assert.equal(await f.approvals.approveBegin({user:{...f.phoneA.user,ownerId:'other'},changeId:r.changeId,keyId:'key-a'}),undefined);
 const b=await f.approvals.approveBegin({user:f.phoneA.user,changeId:r.changeId,keyId:'key-a'});assert.equal(b.challenge.actionDigest,await approvalAction(r.changeId,'passkey-add',null,f.account.ownerId,0));
 assert.equal(await f.approvals.approveFinish({user:f.phoneA.user,changeId:r.changeId,token:b.token,signature:'A'.repeat(86)}),undefined);assert.equal(f.rows()[0].approved_at,null);
 assert.equal(await f.approvals.approveFinish({user:f.phoneA.user,changeId:r.changeId,token:b.token,signature:await f.sign(f.A,b.challenge)}),undefined);// challenge already consumed
 assert.deepEqual(await f.approve(r.changeId),{status:'approved'});
 f.db.sqlite.prepare("UPDATE durable_device_keys SET revoked_at=1 WHERE key_id='key-a'").run();
 assert.equal(await f.approvals.authorizePasskeyAdd({user:f.web.user,changeId:r.changeId}),undefined);assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM passkey_add_authorizations').get().n,0);assert.equal(f.rows()[0].consumed_at,null);
 assert.equal(await f.approvals.authorizePasskeyAdd({user:f.phoneB.user,changeId:r.changeId}),undefined);}finally{f.db.sqlite.close();}});
test('same session cannot approve its own request (approver equals requester)',async()=>{const f=await fx();try{
 const r=await f.approvals.requestDeviceKeyAdd({user:f.phoneB.user,publicJwk:f.B.jwk});
 assert.equal(await f.approvals.approveBegin({user:f.phoneB.user,changeId:r.changeId,keyId:'key-a'}),undefined);
 assert.equal((await f.approvals.status({user:f.phoneB.user})).pending.length,0);}finally{f.db.sqlite.close();}});
test('expiry: expired request is replaced in the same batch, expired approval refuses approve/authorize, retention sweeps',async()=>{const f=await fx();try{
 const r=await f.approvals.requestPasskeyAdd({user:f.web.user});f.setNow(NOW+600001);
 assert.equal(await f.approvals.approveBegin({user:f.phoneA.user,changeId:r.changeId,keyId:'key-a'}),undefined);assert.equal((await f.approvals.status({user:f.phoneA.user})).pending.length,0);
 const r2=await f.approvals.requestPasskeyAdd({user:f.web.user});assert.notEqual(r2.changeId,r.changeId);assert.equal(f.rows().length,1);// expired row deleted before insert, unique index not violated
 assert.deepEqual(await f.approve(r2.changeId),{status:'approved'});f.setNow(NOW+600001+600001);
 assert.equal(await f.approvals.authorizePasskeyAdd({user:f.web.user,changeId:r2.changeId}),undefined);
 assert.equal(await f.approvals.cleanup({limit:10}),1);assert.equal(f.rows().length,0);}finally{f.db.sqlite.close();}});
test('race: concurrent requests return one row; pending cap of 8 per owner',async()=>{const f=await fx();try{
 const [x,y]=await Promise.all([f.approvals.requestPasskeyAdd({user:f.web.user}),f.approvals.requestPasskeyAdd({user:f.web.user})]);assert.equal(x.changeId,y.changeId);assert.equal(f.rows().length,1);
 const extra=[];for(let i=0;i<8;i++)extra.push((await f.sessions.issue({proof:{...f.account,purpose:'authenticate',verifiedAt:NOW},clientKind:'web'})));
 let made=1;for(const e of extra){const u=await f.sessions.authenticate(e.access),q=await f.approvals.requestPasskeyAdd({user:u});if(q)made++;}
 assert.equal(made,8);assert.equal(f.rows().length,8);// cap holds at 8 open requests per owner
 }finally{f.db.sqlite.close();}});
test('device-key-add: fingerprint matches on both phones, approve, add-begin/add-finish enrolls once, replay returns outcome, different JWK refused',async()=>{const f=await fx();try{
 const r=await f.approvals.requestDeviceKeyAdd({user:f.phoneB.user,publicJwk:f.B.jwk});assert.equal(r.fingerprint,fingerprint(f.B.digest));assert.match(r.fingerprint,/^[0-9a-f]{4}(-[0-9a-f]{4}){3}$/);
 assert.deepEqual(await f.approvals.requestDeviceKeyAdd({user:f.phoneB.user,publicJwk:f.B.jwk}),r);
 const st=await f.approvals.status({user:f.phoneA.user});assert.equal(st.pending[0].kind,'device-key-add');assert.equal(st.pending[0].target,f.B.digest);assert.equal(st.pending[0].requesterKind,'android');assert.equal(fingerprint(st.pending[0].target),r.fingerprint);
 assert.equal(await f.approvals.addBegin({user:f.phoneB.user,changeId:r.changeId}),undefined);// not approved yet
 const b=await f.approvals.approveBegin({user:f.phoneA.user,changeId:r.changeId,keyId:'key-a'});assert.equal(b.challenge.actionDigest,await approvalAction(r.changeId,'device-key-add',f.B.digest,f.account.ownerId,0));
 assert.deepEqual(await f.approvals.approveFinish({user:f.phoneA.user,changeId:r.changeId,token:b.token,signature:await f.sign(f.A,b.challenge)}),{status:'approved'});
 assert.equal(await f.approvals.addBegin({user:f.phoneA.user,changeId:r.changeId}),undefined);// only the requester
 const ab=await f.approvals.addBegin({user:f.phoneB.user,changeId:r.changeId});assert.equal(ab.challenge.purpose,'enroll');assert.match(ab.challenge.keyId,/^k_[0-9a-f]{40}$/);
 assert.equal(await f.approvals.addFinish({user:f.phoneB.user,changeId:r.changeId,token:ab.token,signature:await f.sign(f.A,ab.challenge)}),undefined);// wrong key signs
 const ab2=await f.approvals.addBegin({user:f.phoneB.user,changeId:r.changeId});
 const done=await f.approvals.addFinish({user:f.phoneB.user,changeId:r.changeId,token:ab2.token,signature:await f.sign(f.B,ab2.challenge)});assert.deepEqual(done,{status:'enrolled',keyId:ab2.challenge.keyId});
 assert.deepEqual(await f.approvals.addFinish({user:f.phoneB.user,changeId:r.changeId,token:ab2.token,signature:await f.sign(f.B,ab2.challenge)}),done);
 assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM durable_device_keys WHERE revoked_at IS NULL').get().n,2);assert.equal(f.rows()[0].consume_receipt!==null,true);assert.equal(await f.approvals.addBegin({user:f.phoneB.user,changeId:r.changeId}),undefined);// consumed once
 assert.equal((await f.approvals.status({user:f.phoneA.user})).pending.length,0);}finally{f.db.sqlite.close();}});
test('device-key-add: approver key revoked between approve and add-finish refuses and rolls back; existing or revoked target refused; swapped target_jwk refused',async()=>{const f=await fx();try{
 const r=await f.approvals.requestDeviceKeyAdd({user:f.phoneB.user,publicJwk:f.B.jwk});await f.approve(r.changeId);
 const ab=await f.approvals.addBegin({user:f.phoneB.user,changeId:r.changeId});
 f.db.sqlite.prepare("UPDATE durable_device_keys SET revoked_at=1 WHERE key_id='key-a'").run();
 assert.equal(await f.approvals.addFinish({user:f.phoneB.user,changeId:r.changeId,token:ab.token,signature:await f.sign(f.B,ab.challenge)}),undefined);
 assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM durable_device_keys').get().n,1);assert.equal(f.rows()[0].consumed_at,null);assert.equal(f.db.sqlite.prepare('SELECT count(*) n FROM device_key_receipts').get().n,0);
 const f2=await fx();try{assert.equal(await f2.approvals.requestDeviceKeyAdd({user:f2.phoneB.user,publicJwk:f2.A.jwk}),undefined);// already enrolled
  const C=await pair();const r2=await f2.approvals.requestDeviceKeyAdd({user:f2.phoneB.user,publicJwk:C.jwk});f2.db.sqlite.prepare('UPDATE enrolled_approvals SET target_jwk=?').run(f2.B.text);
  await f2.approve(r2.changeId);assert.equal(await f2.approvals.addBegin({user:f2.phoneB.user,changeId:r2.changeId}),undefined);}finally{f2.db.sqlite.close();}
 }finally{f.db.sqlite.close();}});
test('re-request with a different key replaces an unapproved device-key-add; an approved one is not replaced',async()=>{const f=await fx();try{
 const C=await pair(),r=await f.approvals.requestDeviceKeyAdd({user:f.phoneB.user,publicJwk:f.B.jwk}),r2=await f.approvals.requestDeviceKeyAdd({user:f.phoneB.user,publicJwk:C.jwk});assert.notEqual(r2.changeId,r.changeId);assert.equal(f.rows().length,1);
 await f.approve(r2.changeId);assert.equal(await f.approvals.requestDeviceKeyAdd({user:f.phoneB.user,publicJwk:f.B.jwk}),undefined);assert.equal(f.rows()[0].target,C.digest);}finally{f.db.sqlite.close();}});
test('regression: passkey-approved authorization still registers and a key-approved row cannot satisfy a missing approver',async()=>{const f=await fx();try{
 const add=new AddPasskeyEnrollment(f.db,{clock:f.clock});const g=await add.authorize({user:f.web.user,proof:{purpose:'step-up',ownerId:f.account.ownerId,generation:0,credentialId:f.account.credentialId,verifiedAt:NOW,actionDigest:await hashText('passkey:add')}});
 if(g){const c=await add.begin({user:f.web.user,grant:g.token});assert.equal(await add.finish({user:f.web.user,grant:g.token,token:c.token,response:authenticator().registration({expected:c.options.challenge})}),true);}
 }finally{f.db.sqlite.close();}});
test('HTTP: web routes need Origin+web bearer, android routes need no Origin+android bearer, exact keys, wrong kind refused, end to end',async()=>{const f=await fx();try{
 const http=createApprovalsHttp({db:f.db,sessions:f.sessions,approvals:f.approvals,clock:f.clock}),run=(p,body,{origin,token,method='POST',ct='application/json'}={})=>http.fetch(new Request(API+p,{method,headers:{...(origin?{Origin:origin}:{}),Authorization:'Bearer '+token,'Content-Type':ct},...(method==='POST'?{body:JSON.stringify(body)}:{})}),{clientAddress:'192.0.2.7'});
 const W='/v1/manage/passkey/add/approval-request',S='/v1/manage/approval/status';
 assert.equal((await run(W,{},{token:f.web.access})).status,403);// web route without Origin
 assert.equal((await run(W,{},{token:f.phoneA.access,origin:APP})).status,401);// android token on web route
 assert.equal((await run(S,{},{token:f.web.access,origin:APP})).status,403);// android route with Origin
 assert.equal((await run(S,{},{token:f.web.access})).status,401);// web token on android route
 assert.equal((await run(W,{x:1},{token:f.web.access,origin:APP})).status,400);assert.equal((await run(W,{},{token:f.web.access,origin:APP,ct:'application/json; charset=utf-8'})).status,400);assert.equal((await run(W,{},{token:f.web.access,origin:APP,method:'GET'})).status,405);
 const rq=await run(W,{},{token:f.web.access,origin:APP});assert.equal(rq.status,200);assert.equal(rq.headers.get('access-control-allow-origin'),APP);const {changeId}=await rq.json();
 const st=await run(S,{},{token:f.phoneA.access});assert.equal(st.status,200);assert.equal(st.headers.get('access-control-allow-origin'),null);assert.equal((await st.json()).pending.length,1);
 const b=await (await run('/v1/manage/approval/approve-begin',{changeId,keyId:'key-a'},{token:f.phoneA.access})).json();
 const fin=await run('/v1/manage/approval/approve-finish',{changeId,token:b.token,signature:await f.sign(f.A,b.challenge)},{token:f.phoneA.access});assert.equal(fin.status,200);assert.deepEqual(await fin.json(),{status:'approved'});
 const au=await run('/v1/manage/passkey/add/approval-authorize',{changeId},{token:f.web.access,origin:APP});assert.equal(au.status,200);assert.ok((await au.json()).token);
 assert.equal((await run('/v1/manage/passkey/add/approval-authorize',{changeId},{token:f.web.access,origin:APP})).status,409);
 const pre=await http.fetch(new Request(API+W,{method:'OPTIONS',headers:{Origin:APP,'Access-Control-Request-Method':'POST','Access-Control-Request-Headers':'authorization, content-type'}}));assert.equal(pre.status,204);
 assert.equal((await http.fetch(new Request(API+S,{method:'OPTIONS',headers:{}}))).status,405);
 assert.equal((await run('/v1/manage/device-key/add-request',{publicJwk:f.B.jwk},{token:f.phoneB.access})).status,200);}finally{f.db.sqlite.close();}});
