import test from 'node:test';import assert from 'node:assert/strict';import {database} from './sqlite-helper.js';import {disconnectGmailGuarded} from '../src/gmail-source-http.js';
const NOW=1800000000000;
test('guarded source disconnect is atomic with token wipe and denies revoked device/method/reset/expiry/wrongowner',async()=>{for(const change of ['none','device','method','generation','expiry','access','owner']){const db=database();try{db.sqlite.exec(`INSERT INTO accounts(owner_id,created_at)VALUES('owner',0); INSERT INTO account_security(owner_id,generation)VALUES('owner',0); INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at)VALUES('cred','owner',X'00',0,'[]','singleDevice',0,0); INSERT INTO device_sessions(device_id,owner_id,credential_id,generation,client_kind,created_at,last_used_at,expires_at)VALUES('dev','owner','cred',0,'web',0,0,${NOW+10000}); INSERT INTO sources(source_id,owner_id,kind,label,created_at)VALUES('source','owner','gmail','Test',0); INSERT INTO gmail_connections(source_id,owner_id,mailbox,refresh_envelope,history_id,watch_expires_at,created_at,updated_at)VALUES('source','owner','a@example.test','encrypted-envelope','123',${NOW+10000},0,0);`);if(change==='device')db.sqlite.exec('UPDATE device_sessions SET revoked_at=1');if(change==='method')db.sqlite.exec('UPDATE passkey_credentials SET revoked_at=1');if(change==='generation')db.sqlite.exec('UPDATE account_security SET generation=1');if(change==='expiry')db.sqlite.exec('UPDATE device_sessions SET expires_at=1');const user={ownerId:change==='owner'?'wrong':'owner',deviceId:'dev',generation:0,expiresAt:change==='access'?NOW:NOW+10000},r=await disconnectGmailGuarded(db,user,'source',NOW);assert.equal(r.disconnected,change==='none');const c=db.sqlite.prepare('SELECT status,refresh_envelope FROM gmail_connections').get();assert.equal(c.status,change==='none'?'disconnected':'active');assert.equal(c.refresh_envelope,change==='none'?'':'encrypted-envelope');}finally{db.sqlite.close();}}});
const sessionDb=(change)=>{const db=database();db.sqlite.exec(`INSERT INTO accounts(owner_id,created_at)VALUES('owner',0); INSERT INTO account_security(owner_id,generation)VALUES('owner',0); INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at)VALUES('cred','owner',X'00',0,'[]','singleDevice',0,0); INSERT INTO device_sessions(device_id,owner_id,credential_id,generation,client_kind,created_at,last_used_at,expires_at)VALUES('dev','owner','cred',0,'web',0,0,${NOW+10000}); INSERT INTO sources(source_id,owner_id,kind,label,created_at)VALUES('source','owner','gmail','Test',0); INSERT INTO gmail_connections(source_id,owner_id,mailbox,refresh_envelope,history_id,watch_expires_at,created_at,updated_at,label_id,filter_id)VALUES('source','owner','a@example.test','encrypted-envelope','123',${NOW+10000},0,0,'Label_1','Filter_1');`);if(change==='device')db.sqlite.exec('UPDATE device_sessions SET revoked_at=1');if(change==='generation')db.sqlite.exec('UPDATE account_security SET generation=1');return db;};
test('mounted guarded disconnect reaches sync cleanup with the SAME session-guarded revoke; a failed guard performs no Google cleanup',async()=>{
 for(const change of ['none','device','generation']){const db=sessionDb(change);try{
  let called=0,revokeRan;const sync={async disconnect(owner,source,{revoke}){called++;assert.deepEqual([owner,source],['owner','source']);revokeRan=await revoke();return revokeRan?{disconnected:true,remoteRevoked:true,artifactsRemoved:true}:{disconnected:false};}};
  const r=await disconnectGmailGuarded(db,{ownerId:'owner',deviceId:'dev',generation:0,expiresAt:NOW+10000},'source',NOW,{sync});
  assert.equal(called,1);assert.equal(revokeRan,change==='none');
  assert.deepEqual(r,change==='none'?{disconnected:true,remoteRevoked:false,googlePermissionRemains:true,artifactsRemoved:true}:{disconnected:false,remoteRevoked:false,googlePermissionRemains:true});
  const c=db.sqlite.prepare('SELECT status,refresh_envelope e FROM gmail_connections').get();assert.equal(c.status,change==='none'?'disconnected':'active');assert.equal(c.e,change==='none'?'':'encrypted-envelope');
 }finally{db.sqlite.close();}}
 // an expired access token never reaches sync
 const db=sessionDb('none');try{let called=0;const r=await disconnectGmailGuarded(db,{ownerId:'owner',deviceId:'dev',generation:0,expiresAt:NOW},'source',NOW,{sync:{async disconnect(){called++;return {disconnected:true};}}});assert.deepEqual([r.disconnected,called],[false,0]);}finally{db.sqlite.close();}
});

test('disconnect rules choice: keep (and legacy no choice) pauses saved rules, delete removes them; a failed session guard changes neither',async()=>{
 for(const [rules,change] of [[undefined,'none'],['keep','none'],['delete','none'],['delete','device'],['keep','device']]){
  const db=sessionDb(change);try{
   db.sqlite.exec("INSERT INTO services(service_id,name)VALUES('svc','svc'); INSERT INTO entries(entry_id,owner_id,service_id,label,created_at)VALUES('en','owner','svc','E',0); INSERT INTO service_routes(route_id,owner_id,service_id,source_id,origin_kind,origin_value,entry_id,created_at)VALUES('r1','owner','svc','source','email_address','a@b.test','en',0);");
   const user={ownerId:'owner',deviceId:'dev',generation:0,expiresAt:NOW+10000};
   await disconnectGmailGuarded(db,user,'source',NOW,{rules});
   const n=db.sqlite.prepare('SELECT count(*) c FROM service_routes').get().c,p=db.sqlite.prepare('SELECT paused_at FROM service_routes').get()?.paused_at??null;
   const label=String(rules)+'/'+change;
   if(change==='device'){assert.equal(n,1,label);assert.equal(p,null,label);assert.equal(db.sqlite.prepare('SELECT revoked_at FROM sources').get().revoked_at,null,label);}
   else if(rules==='delete')assert.equal(n,0,label);
   else{assert.equal(n,1,label);assert.notEqual(p,null,label);}
  }finally{db.sqlite.close();}
 }
});
