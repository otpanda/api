import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { SourceEntryStore } from '../src/source-entries.js';
import { EntryAccess } from '../src/entry-access.js';
import { CodeCipher } from '../src/code-cipher.js';
const NOW=1800000000000;
async function setup(){
 const db=database();for(const owner of ['a','b','c'])await db.prepare('INSERT INTO accounts VALUES (?,?)').bind(owner,NOW).run();
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
 const store=new SourceEntryStore(db,new CodeCipher({keys:new Map([['test',key]]),activeKeyId:'test'}));
 const source=await store.createSource('a','sms','Private phone',NOW);
 const shared=await store.createEntry('a','google','Shared Google',NOW);
 const personal=await store.createEntry('a','google','Private Google',NOW);
 for(const [entryId,eventId,code] of [[shared,'shared','123456'],[personal,'private','999999']]){
  await store.receive('a',{sourceId:source,eventId,code,receivedAt:NOW,expiresAt:NOW+1000});
  await store.confirm('a',source,eventId,entryId,NOW);
 }
 return {db,store,access:new EntryAccess(db,store),source,shared,personal};
}
test('selected entry read-only sharing never shares sources or other entries',async()=>{
 const {db,store,access,shared,personal}=await setup();
 assert.equal(await access.share('a',shared,'b',{},NOW),true);
 assert.equal((await access.latest('b',shared,NOW)).code,'123456');
 assert.equal(await access.latest('b',personal,NOW),undefined);
 assert.equal(await access.latest('c',shared,NOW),undefined);
 assert.deepEqual(await store.sourcesForOwner('b'),[]);
 assert.equal(await access.updateEntry('b',shared,'Changed'),false);
 assert.equal(await access.deleteEntry('b',shared),false);
 assert.equal(await access.share('b',shared,'c',{},NOW),false);
 assert.equal(await access.revoke('b',shared,'a',NOW),false);
 db.sqlite.close();
});
test('recipient automation requires separate owner permission checked on every read',async()=>{
 const {db,access,shared}=await setup();
 await access.share('a',shared,'b',{},NOW);
 assert.equal(await access.latest('b',shared,NOW,{automation:true}),undefined);
 assert.equal(await access.share('b',shared,'b',{allowAutomation:true},NOW).catch(()=>false),false);
 await access.share('a',shared,'b',{allowAutomation:true},NOW);
 assert.equal((await access.latest('b',shared,NOW,{automation:true})).code,'123456');
 await access.share('a',shared,'b',{allowAutomation:false},NOW);
 assert.equal(await access.latest('b',shared,NOW,{automation:true}),undefined);
 assert.equal((await access.latest('b',shared,NOW)).code,'123456');
 await access.revoke('a',shared,'b',NOW);
 assert.equal(await access.latest('b',shared,NOW),undefined);
 assert.equal(await access.latest('b',shared,NOW,{automation:true}),undefined);
 db.sqlite.close();
});
test('revocation during async code read is rechecked before returning plaintext',async()=>{
 const {db,access,store,shared}=await setup();
 await access.share('a',shared,'b',{},NOW);
 const wrapper={async latestOwned(...args){const value=await store.latestOwned(...args);await access.revoke('a',shared,'b',NOW);return value;}};
 assert.equal(await new EntryAccess(db,wrapper).latest('b',shared,NOW),undefined);
 db.sqlite.close();
});
test('database entry assignment tamper fails authenticated decryption',async()=>{
 const {db,store,shared,personal}=await setup();
 db.sqlite.prepare('UPDATE incoming_codes SET entry_id = ? WHERE event_id = ?').run(personal,'shared');
 await assert.rejects(store.latestOwned('a',personal,NOW));
 db.sqlite.close();
});
