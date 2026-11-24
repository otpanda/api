import test from 'node:test';
import assert from 'node:assert/strict';
import {database} from './sqlite-helper.js';
import {PersonalOrganizationStore} from '../src/personal-organization.js';
const NOW=1800000000000;
function setup(){const db=database();for(const id of ['owner','viewer','other'])db.sqlite.prepare('INSERT INTO accounts VALUES (?,?)').run(id,NOW);db.sqlite.prepare("INSERT INTO entries(entry_id,owner_id,service_id,label,created_at) VALUES ('entry','owner','service','Label',?)").run(NOW);return {db,store:new PersonalOrganizationStore(db,{clock:()=>NOW})};}
const doc={tags:[{id:'tag',label:'Personal'}],entries:[{entryId:'entry',pinned:true,tagIds:['tag']}]};
test('cloud tags/pins are private to authenticated viewer and revision checked',async()=>{
 const {db,store}=setup();
 assert.deepEqual(await store.read('owner'),{revision:0,tags:[],entries:[]});
 assert.deepEqual(await store.replace('owner',0,doc),{ok:true,revision:1});
 assert.deepEqual(await store.replace('owner',0,{tags:[],entries:[]}),{ok:false});
 assert.deepEqual(await store.read('owner'),{revision:1,...doc});
 assert.deepEqual(await store.read('other'),{revision:0,tags:[],entries:[]});
 assert.deepEqual(await store.replace('other',0,doc),{ok:false});db.sqlite.close();
});
test('unknown and inaccessible entries never enter state, invalid fields fail closed',async()=>{
 const {db,store}=setup();
 for(const bad of [{...doc,copyCount:3},{...doc,tags:[...doc.tags,...doc.tags]},{...doc,entries:[{...doc.entries[0],copyCount:2}]},{...doc,entries:[{...doc.entries[0],tagIds:['missing']}]},{...doc,tags:[{id:'x',label:'Bad\nlabel'}]}])await assert.rejects(store.replace('owner',0,bad),TypeError);
 assert.deepEqual(await store.replace('owner',0,{tags:[],entries:[{entryId:'missing',pinned:false,tagIds:[]}]}),{ok:false});
 assert.equal((await store.read('owner')).revision,0);db.sqlite.close();
});
test('concurrent devices cannot silently overwrite cloud preference revisions',async()=>{
 const {db,store}=setup();const results=[await store.replace('owner',0,doc),await store.replace('owner',0,{tags:[],entries:[]})];assert.equal(results.filter(r=>r.ok).length,1);assert.equal((await store.read('owner')).revision,1);db.sqlite.close();
});
test('recipient tags and pins are not visible to owner; revocation blocks reads/writes',async()=>{
 const {db,store}=setup();db.sqlite.prepare("INSERT INTO entry_shares VALUES ('entry','viewer',0,?,NULL)").run(NOW);
 assert.equal((await store.replace('viewer',0,doc)).ok,true);
 assert.equal((await store.read('owner')).entries.length,0);
 db.sqlite.prepare("UPDATE entry_shares SET revoked_at=? WHERE recipient_id='viewer'").run(NOW);
 assert.equal((await store.read('viewer')).entries.length,0);
 assert.equal((await store.replace('viewer',1,doc)).ok,false);db.sqlite.close();
});
test('successful-copy receipt deduplication, private ranking and aging',async()=>{
 const {db}=setup();let now=NOW;const store=new PersonalOrganizationStore(db,{clock:()=>now});
 const receipt={entryId:'entry',receiptId:'a'.repeat(22),createdAt:now};
 assert.equal((await store.recordSuccessfulCopy('owner',receipt)).accepted,true);
 assert.equal((await store.recordSuccessfulCopy('owner',receipt)).accepted,false);
 assert.deepEqual(await store.ranking('owner'),[{entryId:'entry',score:1}]);
 assert.deepEqual(await store.ranking('other'),[]);
 assert.equal((await store.recordSuccessfulCopy('other',receipt)).accepted,false);
 now+=7*86400000;
 assert.equal((await store.ranking('owner'))[0].score,0.5);
 await assert.rejects(store.recordSuccessfulCopy('owner',receipt),TypeError);
 assert.equal((await store.recordSuccessfulCopy('owner',{...receipt,receiptId:'b'.repeat(22),createdAt:now})).accepted,true);
 assert.equal((await store.ranking('owner'))[0].score,1.5);
 now+=90*86400000;assert.deepEqual(await store.ranking('owner'),[]);db.sqlite.close();
});
test('shared recipient successful copies never alter owner rank and revoked access blocks receipts',async()=>{
 const {db,store}=setup();db.sqlite.prepare("INSERT INTO entry_shares VALUES ('entry','viewer',0,?,NULL)").run(NOW);
 const receipt={entryId:'entry',receiptId:'z'.repeat(22),createdAt:NOW};
 assert.equal((await store.recordSuccessfulCopy('viewer',receipt)).accepted,true);
 assert.deepEqual(await store.ranking('owner'),[]);
 db.sqlite.prepare("UPDATE entry_shares SET revoked_at=? WHERE recipient_id='viewer'").run(NOW);
 assert.deepEqual(await store.ranking('viewer'),[]);
 assert.equal((await store.recordSuccessfulCopy('viewer',{...receipt,receiptId:'y'.repeat(22)})).accepted,false);db.sqlite.close();
});
test('receipt and per-day caps bound storage, replay remains rejected after receipt pruning',async()=>{
 const {db}=setup();let now=NOW;const store=new PersonalOrganizationStore(db,{clock:()=>now});
 const insert=db.sqlite.prepare('INSERT INTO personal_copy_receipts VALUES (?,?,?)');for(let i=0;i<1000;i++)insert.run('owner','r'+i,now);
 const receipt={entryId:'entry',receiptId:'n'.repeat(22),createdAt:now};assert.equal((await store.recordSuccessfulCopy('owner',receipt)).accepted,false);
 now+=600001;assert.equal((await store.recordSuccessfulCopy('owner',{...receipt,createdAt:now})).accepted,true);
 assert.equal(db.sqlite.prepare("SELECT count(*) AS n FROM personal_copy_receipts WHERE viewer_id='owner'").get().n,1);
 db.sqlite.prepare("UPDATE personal_copy_days SET copies=1000 WHERE viewer_id='owner'").run();
 assert.equal((await store.recordSuccessfulCopy('owner',{...receipt,receiptId:'m'.repeat(22),createdAt:now})).accepted,true);
 assert.equal((await store.ranking('owner'))[0].score,1000);
 await assert.rejects(store.recordSuccessfulCopy('owner',receipt),TypeError);db.sqlite.close();
});
test('transaction-level device and generation guard denies revocation immediately before batch',async()=>{
 const {db}=setup();db.sqlite.prepare("INSERT INTO account_security VALUES ('owner',0,0)").run();db.sqlite.prepare("INSERT INTO passkey_credentials VALUES ('p','owner',X'01',0,0,'[]','singleDevice',0,?,NULL,NULL,NULL)").run(NOW);db.sqlite.prepare("INSERT INTO device_sessions(device_id,owner_id,credential_id,generation,client_kind,created_at,last_used_at,expires_at) VALUES ('d','owner','p',0,'web',?,?,?)").run(NOW,NOW,NOW+30000);
 let revoke=true;const wrapped={prepare:db.prepare,batch:async statements=>{if(revoke){db.sqlite.prepare("UPDATE device_sessions SET revoked_at=? WHERE device_id='d'").run(NOW);revoke=false;}return db.batch(statements);}};
 const store=new PersonalOrganizationStore(wrapped,{clock:()=>NOW}),guard={ownerId:'owner',deviceId:'d',generation:0,expiresAt:NOW+30000};
 assert.equal((await store.replace('owner',0,doc,guard)).ok,false);assert.equal(db.sqlite.prepare('SELECT count(*) AS n FROM personal_organization').get().n,0);
 assert.equal((await store.recordSuccessfulCopy('owner',{entryId:'entry',receiptId:'w'.repeat(22),createdAt:NOW},guard)).accepted,false);
 db.sqlite.prepare("UPDATE device_sessions SET revoked_at=NULL WHERE device_id='d'").run();db.sqlite.prepare("UPDATE account_security SET generation=1 WHERE owner_id='owner'").run();assert.equal((await store.replace('owner',0,doc,guard)).ok,false);db.sqlite.close();
});
test('copy storage stays bounded to one thousand recent identities',async()=>{const {db,store}=setup();const entry=db.sqlite.prepare('INSERT INTO entries(entry_id,owner_id,service_id,label,created_at) VALUES (?,?,?,?,?)');const day=db.sqlite.prepare('INSERT INTO personal_copy_days VALUES (?,?,?,?)');for(let i=0;i<1000;i++){const id='old'+i;entry.run(id,'owner','service','Label',NOW);day.run('owner',id,Math.floor(NOW/86400000),1);}assert.equal((await store.recordSuccessfulCopy('owner',{entryId:'entry',receiptId:'x'.repeat(22),createdAt:NOW})).accepted,false);assert.equal((await store.recordSuccessfulCopy('owner',{entryId:'old1',receiptId:'v'.repeat(22),createdAt:NOW})).accepted,true);assert.equal((await store.ranking('owner')).length,1000);assert.equal(db.sqlite.prepare('SELECT count(DISTINCT entry_id) AS n FROM personal_copy_days').get().n,1000);db.sqlite.close();});
test('expired, revoked-credential, and non-web session guards cannot mutate cloud state',async()=>{const {db,store}=setup();db.sqlite.prepare("INSERT INTO account_security VALUES ('owner',0,0)").run();db.sqlite.prepare("INSERT INTO passkey_credentials VALUES ('p','owner',X'01',0,0,'[]','singleDevice',0,?,NULL,NULL,NULL)").run(NOW);db.sqlite.prepare("INSERT INTO device_sessions(device_id,owner_id,credential_id,generation,client_kind,created_at,last_used_at,expires_at) VALUES ('d','owner','p',0,'web',?,?,?)").run(NOW,NOW,NOW+30000);const guard={ownerId:'owner',deviceId:'d',generation:0,expiresAt:NOW+30000};for(const change of ["UPDATE device_sessions SET expires_at="+NOW+" WHERE device_id='d'","UPDATE device_sessions SET expires_at="+(NOW+30000)+",client_kind='android' WHERE device_id='d'","UPDATE device_sessions SET client_kind='web' WHERE device_id='d'; UPDATE passkey_credentials SET revoked_at="+NOW+" WHERE credential_id='p'"]){db.sqlite.exec(change);assert.equal((await store.replace('owner',0,doc,guard)).ok,false);assert.equal((await store.recordSuccessfulCopy('owner',{entryId:'entry',receiptId:'u'.repeat(22),createdAt:NOW},guard)).accepted,false);}assert.equal(db.sqlite.prepare('SELECT count(*) AS n FROM personal_organization').get().n,0);assert.equal(db.sqlite.prepare('SELECT count(*) AS n FROM personal_copy_receipts').get().n,0);db.sqlite.close();});
