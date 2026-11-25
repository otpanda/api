import test from 'node:test';import assert from 'node:assert/strict';
import {database} from './sqlite-helper.js';import {authenticator} from './passkey-fixture.js';
import {DeviceSessionService} from '../src/device-sessions.js';import {createDeviceReadHttp} from '../src/device-read-http.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io';
async function setup(){const db=database(),now=Date.now(),clock=()=>now;
 for(const o of ['a','b']){db.sqlite.prepare('INSERT INTO accounts(owner_id,created_at) VALUES(?,?)').run(o,now);db.sqlite.prepare('INSERT INTO account_security(owner_id) VALUES(?)').run(o);}
 const creds={};for(const o of ['a','b']){const a=authenticator();creds[o]=a.credential.id;db.sqlite.prepare('INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES(?,?,?,?,?,?,?,?)').run(a.credential.id,o,a.credential.publicKey,0,'[]','singleDevice',0,now);}
 const sessions=new DeviceSessionService(db,{clock}),issue=o=>sessions.issue({proof:{authMethod:'passkey',credentialId:creds[o],ownerId:o,generation:0,purpose:'authenticate',verifiedAt:now},clientKind:'web'});
 const http=createDeviceReadHttp({db,sessions,sources:{},access:{},clock});
 const read=async (access,q='?view=cache-v1')=>{const r=await http.fetch(new Request(API+'/v1/manage/session'+q,{headers:{Origin:APP,Authorization:'Bearer '+access}}),{clientAddress:'192.0.2.'+Math.floor(Math.random()*200)});return{status:r.status,body:await r.json()};};
 return{db,sessions,issue,read};}
test('session endpoint returns an opaque per-sign-in sessionId: stable across rotation, new per fresh login and per account',async()=>{
 const x=await setup(),s1=await x.issue('a'),r1=await x.read(s1.access);assert.equal(r1.status,200);assert.deepEqual(Object.keys(r1.body).sort(),['expiresAt','ownerId','sessionId']);
 assert.match(r1.body.sessionId,/^[a-f0-9]{64}$/);assert.ok(!r1.body.sessionId.includes(s1.deviceId),'not the device id');
 const rot=await x.sessions.rotate(s1.refresh,{clientKind:'web'});assert.equal(rot.status,'rotated');const r2=await x.read(rot.access);assert.equal(r2.body.sessionId,r1.body.sessionId,'renew/restore keeps the same session namespace');
 const s2=await x.issue('a'),r3=await x.read(s2.access);assert.notEqual(r3.body.sessionId,r1.body.sessionId,'fresh login, same account, is a new namespace');
 const s3=await x.issue('b'),r4=await x.read(s3.access);assert.notEqual(r4.body.sessionId,r1.body.sessionId);assert.notEqual(r4.body.sessionId,r3.body.sessionId);
 assert.equal((await x.read('nope')).status,401);
 const legacy=await x.read(s1.access,'');assert.equal(legacy.status,200);assert.deepEqual(Object.keys(legacy.body).sort(),['expiresAt','ownerId'],'legacy shape unchanged');
 for(const q of ['?view=other','?view=cache-v1&x=1','?x=1','?view=cache-v1&view=cache-v1'])assert.equal((await x.read(s1.access,q)).status,400,q);
});
