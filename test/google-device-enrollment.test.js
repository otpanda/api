import test from 'node:test';import assert from 'node:assert/strict';
import {DeviceSessionService} from '../src/device-sessions.js';
import {database} from './sqlite-helper.js';
import {FirstPasskeyEnrollment} from '../src/first-passkey-enrollment.js';
import {GoogleDeviceEnrollment} from '../src/google-device-enrollment.js';
import {DurableDeviceKeys} from '../src/durable-device-keys.js';
import {deviceProofMessage} from '../src/device-key-proof.js';
import {authenticator} from './passkey-fixture.js';
import {cleanupIdentity} from '../src/identity-cleanup.js';
import {hashText} from '../src/sessions.js';
import {base64urlEncode,generateAccessToken,parseAccessToken,digestSecret,digestToHex} from '../src/tokens.js';
const NOW=1800000000000;let t=NOW;const clock=()=>t;
async function newKey(){const k=await crypto.subtle.generateKey({name:'ECDSA',namedCurve:'P-256'},true,['sign','verify']),j=await crypto.subtle.exportKey('jwk',k.publicKey);return{k,jwk:{kty:j.kty,crv:j.crv,x:j.x,y:j.y}};}
const sign=async(k,c)=>base64urlEncode(new Uint8Array(await crypto.subtle.sign({name:'ECDSA',hash:'SHA-256'},k.k.privateKey,deviceProofMessage(c))));
async function fx(){t=NOW;const db=database();
 db.sqlite.prepare('INSERT INTO accounts(owner_id,created_at) VALUES(?,?)').run('owner',NOW);db.sqlite.prepare('INSERT INTO account_emails VALUES(?,?,?,?)').run('owner','a@gmail.com',NOW,NOW);db.sqlite.prepare('INSERT INTO account_security(owner_id) VALUES(?)').run('owner');
 db.sqlite.prepare("INSERT INTO provider_identities(identity_id,owner_id,provider,issuer,subject,email,created_at) VALUES('one','owner','google','https://accounts.google.com','one','a@gmail.com',?)").run(NOW);
 const sessions=new DeviceSessionService(db,{clock}),proof={authMethod:'google',issuer:'https://accounts.google.com',subject:'one',ownerId:'owner',generation:0,purpose:'authenticate',verifiedAt:NOW};
 const device=await sessions.issue({proof,clientKind:'android'}),user={ownerId:'owner',deviceId:device.deviceId,generation:0};
 const first=new FirstPasskeyEnrollment(db,{clock}),grant=(await first.issue({...proof,...user})).token,svc=new GoogleDeviceEnrollment(db,{clock}),keys=new DurableDeviceKeys(db,{clock}),key=await newKey();
 const count=q=>db.sqlite.prepare(q).get().n;
 return{db,user,grant,svc,keys,key,first,count,proof,sessions};}
test('enroll once: begin, possession proof, status, adopt, identical replay',async()=>{const f=await fx(),b=await f.svc.begin({user:f.user,publicJwk:f.key.jwk,grant:f.grant});assert.ok(b.token&&b.challenge.purpose==='enroll');
 const sig=await sign(f.key,b.challenge),r=await f.svc.finish({user:f.user,grant:f.grant,token:b.token,signature:sig});assert.equal(r.status,'enrolled');assert.equal(r.keyId,b.challenge.keyId);
 assert.deepEqual(await f.svc.finish({user:f.user,grant:f.grant,token:b.token,signature:sig}),r);
 const digest=await hashText(JSON.stringify(f.key.jwk));assert.deepEqual(await f.svc.status({user:f.user,digest}),{status:'enrolled',keyId:r.keyId});assert.deepEqual(await f.svc.status({user:f.user,digest:'0'.repeat(64)}),{status:'absent'});
 assert.equal(f.count('SELECT count(*) n FROM google_enrollment_grants WHERE consumed_at IS NOT NULL'),1);assert.equal(f.count('SELECT count(*) n FROM durable_device_keys'),1);
 assert.equal(await f.first.begin({user:f.user,grant:f.grant}),undefined);
 const a=await f.svc.adoptBegin({user:f.user,digest,keys:f.keys});assert.ok(a);const ar=await f.svc.adoptFinish({user:f.user,digest,token:a.token,signature:await sign(f.key,a.challenge),keys:f.keys});assert.deepEqual(ar,r);});
test('bad signature consumes nothing; retry with right signature works',async()=>{const f=await fx(),other=await newKey(),b=await f.svc.begin({user:f.user,publicJwk:f.key.jwk,grant:f.grant});
 assert.equal(await f.svc.finish({user:f.user,grant:f.grant,token:b.token,signature:await sign(other,b.challenge)}),undefined);assert.equal(f.count('SELECT count(*) n FROM google_enrollment_grants WHERE consumed_at IS NOT NULL'),0);assert.equal(f.count('SELECT count(*) n FROM durable_device_challenges WHERE consumed_at IS NOT NULL'),0);
 assert.equal((await f.svc.finish({user:f.user,grant:f.grant,token:b.token,signature:await sign(f.key,b.challenge)})).status,'enrolled');});
test('replay and finish are bound to the same android session',async()=>{const f=await fx(),b=await f.svc.begin({user:f.user,publicJwk:f.key.jwk,grant:f.grant}),sig=await sign(f.key,b.challenge);await f.svc.finish({user:f.user,grant:f.grant,token:b.token,signature:sig});
 assert.equal(await f.svc.finish({user:{...f.user,deviceId:'other'},grant:f.grant,token:b.token,signature:sig}),undefined);assert.equal(await f.svc.begin({user:{...f.user,deviceId:'other'},publicJwk:f.key.jwk,grant:f.grant}),undefined);});
test('method_exists only at begin: existing passkey or different key',async()=>{const f=await fx(),g2=await f.first.issue({...f.proof,...f.user}),b=await f.svc.begin({user:f.user,publicJwk:f.key.jwk,grant:f.grant});assert.ok(g2);await f.svc.finish({user:f.user,grant:f.grant,token:b.token,signature:await sign(f.key,b.challenge)});const k2=await newKey();assert.deepEqual(await f.svc.begin({user:f.user,publicJwk:k2.jwk,grant:g2.token}),{error:'method_exists'});
 const f2=await fx();f2.db.sqlite.prepare('INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES(?,?,?,?,?,?,?,?)').run('c','owner',new Uint8Array(4),0,'[]','singleDevice',0,NOW);
 assert.deepEqual(await f2.svc.begin({user:f2.user,publicJwk:f2.key.jwk,grant:f2.grant}),{error:'method_exists'});});
test('two keys begun on one grant: only one wins, grant claimed once',async()=>{const f=await fx(),k2=await newKey(),b1=await f.svc.begin({user:f.user,publicJwk:f.key.jwk,grant:f.grant}),b2=await f.svc.begin({user:f.user,publicJwk:k2.jwk,grant:f.grant});assert.ok(b1&&b2);
 const rs=await Promise.all([f.svc.finish({user:f.user,grant:f.grant,token:b1.token,signature:await sign(f.key,b1.challenge)}),f.svc.finish({user:f.user,grant:f.grant,token:b2.token,signature:await sign(k2,b2.challenge)})]);assert.equal(rs.filter(Boolean).length,1);assert.equal(f.count('SELECT count(*) n FROM durable_device_keys'),1);assert.equal(f.count('SELECT count(*) n FROM device_key_receipts'),1);});
test('revoked link or generation change between begin and finish rolls the whole batch back',async()=>{for(const a of ['link','generation','session','passkey']){const f=await fx(),b=await f.svc.begin({user:f.user,publicJwk:f.key.jwk,grant:f.grant}),sig=await sign(f.key,b.challenge);
 f.db.sqlite.prepare({link:'UPDATE provider_identities SET revoked_at=1',generation:'UPDATE account_security SET generation=1',session:'UPDATE device_sessions SET revoked_at=1',passkey:"INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES('c','owner',x'00',0,'[]','singleDevice',0,1)"}[a]).run();
 assert.equal(await f.svc.finish({user:f.user,grant:f.grant,token:b.token,signature:sig}),undefined,a);assert.equal(f.count('SELECT count(*) n FROM google_enrollment_grants WHERE consumed_at IS NOT NULL'),0,a);assert.equal(f.count('SELECT count(*) n FROM durable_device_keys'),0,a);assert.equal(f.count('SELECT count(*) n FROM durable_device_challenges WHERE consumed_at IS NOT NULL'),0,a);assert.equal(f.count('SELECT count(*) n FROM device_key_receipts'),0,a);}});
test('expired grant or challenge, revoked tombstone digest and malformed keys are refused',async()=>{const f=await fx(),b=await f.svc.begin({user:f.user,publicJwk:f.key.jwk,grant:f.grant});t=NOW+121000;assert.equal(await f.svc.finish({user:f.user,grant:f.grant,token:b.token,signature:await sign(f.key,b.challenge)}),undefined);assert.equal(await f.svc.begin({user:f.user,publicJwk:f.key.jwk,grant:f.grant}),undefined);
 const g=await fx();g.db.sqlite.prepare('INSERT INTO durable_device_keys(key_id,owner_id,public_jwk,generation,created_at,public_key_digest,revoked_at) VALUES(?,?,?,?,?,?,?)').run('k','owner',JSON.stringify(g.key.jwk),0,NOW,await hashText(JSON.stringify(g.key.jwk)),NOW);assert.equal(await g.svc.begin({user:g.user,publicJwk:g.key.jwk,grant:g.grant}),undefined);
 assert.equal(await g.svc.begin({user:g.user,publicJwk:{...g.key.jwk,d:'x'},grant:g.grant}),undefined);assert.equal(await g.svc.begin({user:g.user,publicJwk:g.key.jwk,grant:'bad'}),undefined);});
test('web session cannot use the android enrollment',async()=>{const f=await fx();f.db.sqlite.prepare("UPDATE device_sessions SET client_kind='web'").run();assert.equal(await f.svc.begin({user:f.user,publicJwk:f.key.jwk,grant:f.grant}),undefined);});
test('receipts survive their 10 minute window past challenge expiry and are then swept; consumed approvals sweep too',async()=>{const f=await fx(),b=await f.svc.begin({user:f.user,publicJwk:f.key.jwk,grant:f.grant});await f.svc.finish({user:f.user,grant:f.grant,token:b.token,signature:await sign(f.key,b.challenge)});
 t=NOW+300000;await cleanupIdentity({db:f.db,clock});assert.equal(f.count('SELECT count(*) n FROM device_key_receipts'),1);t=NOW+601000;await cleanupIdentity({db:f.db,clock});assert.equal(f.count('SELECT count(*) n FROM device_key_receipts'),0);});
test('new migration preserves old passkey_add_authorizations rows and CHECKs reject both-or-neither approver',async()=>{const f=await fx();const ins=(a,k)=>f.db.sqlite.prepare("INSERT INTO passkey_add_authorizations(auth_id,secret_digest,owner_id,device_id,generation,approver_credential_id,approver_key_id,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)").run(String(Math.random()),'a'.repeat(64),'owner',f.user.deviceId,0,a,k,1,2);
 assert.throws(()=>ins('c','k'));assert.throws(()=>ins(null,null));ins('c',null);});
test('mutual guard: after a device key, a fresh Google grant cannot start or finish the first passkey',async()=>{const f=await fx(),b=await f.svc.begin({user:f.user,publicJwk:f.key.jwk,grant:f.grant});await f.svc.finish({user:f.user,grant:f.grant,token:b.token,signature:await sign(f.key,b.challenge)});
 assert.equal(await f.first.issue({...f.proof,...f.user}),undefined);
 const g=await fx(),pk=await g.first.begin({user:g.user,grant:g.grant});assert.ok(pk);
 g.db.sqlite.prepare('INSERT INTO durable_device_keys(key_id,owner_id,public_jwk,generation,created_at,public_key_digest) VALUES(?,?,?,?,?,?)').run('kk','owner','{}',0,NOW,'d'.repeat(64));
 assert.equal(await g.first.finish({user:g.user,grant:g.grant,token:pk.token,response:authenticator().registration({expected:pk.options.challenge})}),false);assert.equal(g.count('SELECT count(*) n FROM passkey_credentials'),0);});
test('same JWK begun twice returns the same keyId; finish A then B yields one key and a truthful receipt each',async()=>{const f=await fx(),b1=await f.svc.begin({user:f.user,publicJwk:f.key.jwk,grant:f.grant}),b2=await f.svc.begin({user:f.user,publicJwk:f.key.jwk,grant:f.grant});assert.equal(b1.challenge.keyId,b2.challenge.keyId);
 const r1=await f.svc.finish({user:f.user,grant:f.grant,token:b1.token,signature:await sign(f.key,b1.challenge)});assert.equal(r1.status,'enrolled');
 const r2=await f.svc.finish({user:f.user,grant:f.grant,token:b2.token,signature:await sign(f.key,b2.challenge)});assert.equal(r2,undefined);// grant already consumed: opaque
 assert.equal(f.count('SELECT count(*) n FROM durable_device_keys'),1);assert.equal(f.db.sqlite.prepare('SELECT key_id k FROM durable_device_keys').get().k,r1.keyId);assert.equal(f.count('SELECT count(*) n FROM device_key_receipts'),1);});
test('legacy stored key id is reused and returned; conflict update cannot return a different id',async()=>{const f=await fx();
 f.db.sqlite.prepare('INSERT INTO durable_device_keys(key_id,owner_id,public_jwk,generation,created_at,public_key_digest) VALUES(?,?,?,?,?,?)').run('legacy-id','owner',JSON.stringify(f.key.jwk),0,NOW,await hashText(JSON.stringify(f.key.jwk)));
 const b=await f.svc.begin({user:f.user,publicJwk:f.key.jwk,grant:f.grant});assert.equal(b.challenge.keyId,'legacy-id');
 f.db.sqlite.prepare("UPDATE durable_device_challenges SET key_id='forged-id'").run();
 assert.equal(await f.svc.finish({user:f.user,grant:f.grant,token:b.token,signature:await sign(f.key,{...b.challenge,keyId:'forged-id'})}),undefined);assert.equal(f.count('SELECT count(*) n FROM device_key_receipts'),0);assert.equal(f.count('SELECT count(*) n FROM google_enrollment_grants WHERE consumed_at IS NOT NULL'),0);});
test('receipt replay needs the same grant binding and an unchanged owner session; status and adopt need a live android session',async()=>{const f=await fx(),b=await f.svc.begin({user:f.user,publicJwk:f.key.jwk,grant:f.grant}),sig=await sign(f.key,b.challenge),r=await f.svc.finish({user:f.user,grant:f.grant,token:b.token,signature:sig});
 const g2=(await f.first.issue({...f.proof,...f.user}));assert.equal(g2,undefined);
 const digest=await hashText(JSON.stringify(f.key.jwk));
 assert.equal(await f.svc.finish({user:f.user,grant:'otpda_'+'A'.repeat(55),token:b.token,signature:sig}),undefined);
 f.db.sqlite.prepare('UPDATE device_sessions SET revoked_at=1').run();assert.equal(await f.svc.status({user:f.user,digest}),undefined);assert.equal(await f.svc.adoptBegin({user:f.user,digest,keys:f.keys}),undefined);assert.deepEqual(await f.svc.finish({user:f.user,grant:f.grant,token:b.token,signature:sig}),r);});

test('status and adopt work for a passkey-method android session of the owner; web, revoked, other generation and other owner stay refused; enroll stays Google-only',async()=>{const f=await fx();
 const b=await f.svc.begin({user:f.user,publicJwk:f.key.jwk,grant:f.grant}),r=await f.svc.finish({user:f.user,grant:f.grant,token:b.token,signature:await sign(f.key,b.challenge)});assert.equal(r.status,'enrolled');
 f.db.sqlite.prepare("INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES('pk1','owner',x'01',0,'[]','singleDevice',0,?)").run(NOW);
 const pk=await f.sessions.issue({proof:{ownerId:'owner',generation:0,purpose:'authenticate',verifiedAt:NOW,credentialId:'pk1'},clientKind:'android'}),pu={ownerId:'owner',deviceId:pk.deviceId,generation:0};
 const digest=await hashText(JSON.stringify(f.key.jwk));
 assert.deepEqual(await f.svc.status({user:pu,digest}),{status:'enrolled',keyId:r.keyId});assert.deepEqual(await f.svc.status({user:pu,digest:'a'.repeat(64)}),{status:'absent'});
 const ab=await f.svc.adoptBegin({user:pu,digest,keys:f.keys});assert.ok(ab);
 assert.deepEqual(await f.svc.adoptFinish({user:pu,digest,token:ab.token,signature:await sign(f.key,ab.challenge),keys:f.keys}),{status:'enrolled',keyId:r.keyId});
 const ab2=await f.svc.adoptBegin({user:pu,digest,keys:f.keys});assert.equal(await f.svc.adoptFinish({user:pu,digest,token:ab2.token,signature:'A'.repeat(86),keys:f.keys}),undefined);// no key possession, no adopt
 assert.equal(await f.svc.status({user:{...pu,ownerId:'other'},digest}),undefined);assert.equal(await f.svc.status({user:{...pu,generation:1},digest}),undefined);
 f.db.sqlite.prepare("UPDATE device_sessions SET client_kind='web' WHERE device_id=?").run(pk.deviceId);assert.equal(await f.svc.status({user:pu,digest}),undefined);assert.equal(await f.svc.adoptBegin({user:pu,digest,keys:f.keys}),undefined);
 f.db.sqlite.prepare("UPDATE device_sessions SET client_kind='android',revoked_at=1 WHERE device_id=?").run(pk.deviceId);assert.equal(await f.svc.status({user:pu,digest}),undefined);
 f.db.sqlite.prepare("UPDATE device_sessions SET revoked_at=NULL WHERE device_id=?").run(pk.deviceId);f.db.sqlite.prepare("UPDATE passkey_credentials SET revoked_at=1").run();assert.equal(await f.svc.status({user:pu,digest}),undefined);// method revoked ends the session
 assert.equal(await f.svc.begin({user:pu,publicJwk:(await newKey()).jwk,grant:f.grant}),undefined);// a passkey-method session cannot enroll with the Google grant
});
test('grant bound to a passkey-method android session still cannot begin enrollment (Google SESSION guard, not grant mismatch); expired session and generation bump refuse status',async()=>{const f=await fx();
 f.db.sqlite.prepare("INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES('pk2','owner',x'01',0,'[]','singleDevice',0,?)").run(NOW);
 const pk=await f.sessions.issue({proof:{ownerId:'owner',generation:0,purpose:'authenticate',verifiedAt:NOW,credentialId:'pk2'},clientKind:'android'}),pu={ownerId:'owner',deviceId:pk.deviceId,generation:0};
 // The normal issuer refuses a passkey-method session, so plant a grant row bound to it to isolate the Google SESSION guard from grant mismatch.
 const t=generateAccessToken(),pt=parseAccessToken(t.token);f.db.sqlite.prepare('INSERT INTO google_enrollment_grants(grant_id,secret_digest,owner_id,device_id,generation,issuer,subject,created_at,expires_at) VALUES(?,?,?,?,?,?,?,?,?)').run(pt.tokenId,digestToHex(await digestSecret(pt.secret)),'owner',pk.deviceId,0,'https://accounts.google.com','one',NOW,NOW+120000);
 assert.equal(await f.first.issue({...f.proof,...pu}),undefined);
 assert.equal(await f.svc.begin({user:pu,publicJwk:f.key.jwk,grant:t.token}),undefined);
 assert.ok(await f.svc.begin({user:f.user,publicJwk:f.key.jwk,grant:f.grant}));// control: the Google session with its own grant still begins
 const digest='b'.repeat(64);assert.deepEqual(await f.svc.status({user:pu,digest}),{status:'absent'});
 f.db.sqlite.prepare('UPDATE account_security SET generation=1').run();assert.equal(await f.svc.status({user:pu,digest}),undefined);f.db.sqlite.prepare('UPDATE account_security SET generation=0').run();
 f.db.sqlite.prepare('UPDATE device_sessions SET expires_at=1 WHERE device_id=?').run(pk.deviceId);assert.equal(await f.svc.status({user:pu,digest}),undefined);
});
