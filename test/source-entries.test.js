import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { SourceEntryStore } from '../src/source-entries.js';
import { CodeCipher } from '../src/code-cipher.js';
const NOW=1800000000000;
async function setup(){
 const db=database();
 for(const owner of ['a','b'])await db.prepare('INSERT INTO accounts VALUES (?,?)').bind(owner,NOW).run();
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
 const store=new SourceEntryStore(db,new CodeCipher({keys:new Map([['test',key]]),activeKeyId:'test'}));
 const phone=await store.createSource('a','sms','Personal phone',NOW);
 const workPhone=await store.createSource('a','sms','Work phone',NOW);
 const mailbox=await store.createSource('a','gmail','Personal Gmail',NOW);
 const secondMailbox=await store.createSource('a','gmail','Work Gmail',NOW);
 const personal=await store.createEntry('a','google','Personal Google',NOW);
 const work=await store.createEntry('a','google','Work Google',NOW);
 const foreign=await store.createEntry('b','google','Other owner',NOW);
 const incoming={sourceId:phone,eventId:'event-1',code:'123456',receivedAt:NOW,expiresAt:NOW+1000,sender:'sender',accountHint:'personal'};
 return {db,store,phone,workPhone,mailbox,secondMailbox,personal,work,foreign,incoming};
}
test('several mailboxes, phones and same-service entries coexist without merging',async()=>{
 const {db,store,personal,work}=await setup();
 assert.equal((await store.sourcesForOwner('a')).length,4);
 assert.equal((await store.entriesForOwner('a')).length,2);
 assert.notEqual(personal,work);
 assert.equal((await store.sourcesForOwner('b')).length,0);
 db.sqlite.close();
});
test('only explicit unique owner rule assigns; ambiguous or unidentified events stay unassigned',async()=>{
 const {db,store,phone,personal,work,incoming}=await setup();
 assert.equal((await store.receive('a',incoming)).entryId,null);
 assert.equal(await store.latestOwned('a',personal,NOW),undefined);
 await store.addRule('a',{sourceId:phone,entryId:personal,sender:'sender',accountHint:'personal'},NOW);
 assert.equal((await store.receive('a',{...incoming,eventId:'event-2'})).entryId,personal);
 assert.equal((await store.latestOwned('a',personal,NOW)).code,'123456');
 await store.addRule('a',{sourceId:phone,entryId:work,sender:'sender',accountHint:'personal'},NOW);
 assert.equal((await store.receive('a',{...incoming,eventId:'event-3',receivedAt:NOW+1})).entryId,null);
 assert.equal((await store.receive('a',{...incoming,eventId:'event-4',accountHint:undefined})).entryId,null);
 assert.equal(db.sqlite.prepare("SELECT count(*) AS n FROM incoming_codes WHERE assignment='unassigned'").get().n,3);
 db.sqlite.close();
});
test('cross-owner source, rules, confirmation and code reads fail closed',async()=>{
 const {db,store,phone,personal,foreign,incoming}=await setup();
 await assert.rejects(store.receive('b',incoming));
 await assert.rejects(store.addRule('a',{sourceId:phone,entryId:foreign,sender:'sender',accountHint:'personal'},NOW));
 await store.receive('a',incoming);
 assert.equal(await store.confirm('b',phone,incoming.eventId,foreign),false);
 assert.equal(await store.confirm('a',phone,incoming.eventId,foreign),false);
 assert.equal(await store.confirm('a',phone,incoming.eventId,personal),true);
 assert.equal(await store.confirm('a',phone,incoming.eventId,personal),false);
 assert.equal(await store.latestOwned('b',personal,NOW),undefined);
 assert.equal((await store.latestOwned('a',personal,NOW)).code,'123456');
 db.sqlite.close();
});
test('provider-event replay cannot overwrite or reassign a code; revocation blocks new ingestion',async()=>{
 const {db,store,phone,personal,incoming}=await setup();
 await store.receive('a',incoming);
 assert.equal(await store.confirm('a',phone,incoming.eventId,personal),true);
 assert.equal((await store.receive('a',{...incoming,code:'999999'})).inserted,false);
 assert.equal((await store.latestOwned('a',personal,NOW)).code,'123456');
 assert.equal(await store.latestOwned('a',personal,NOW+1000),undefined);
 assert.ok(!JSON.stringify(db.sqlite.prepare('SELECT * FROM incoming_codes').all()).includes('123456'));
 db.sqlite.prepare('UPDATE sources SET revoked_at = ? WHERE source_id = ?').run(NOW,phone);
 await assert.rejects(store.receive('a',{...incoming,eventId:'later'}));
 db.sqlite.close();
});
