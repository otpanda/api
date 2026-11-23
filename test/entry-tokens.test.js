import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { EntryAccess } from '../src/entry-access.js';
import { EntryTokenStore,createEntryReadHandler } from '../src/entry-tokens.js';
const NOW=1800000000000;
async function setup(){
 const db=database();for(const id of ['a','b','c'])await db.prepare('INSERT INTO accounts VALUES (?,?)').bind(id,NOW).run();
 for(const [entry,owner] of [['shared','a'],['private','a'],['other','c']])await db.prepare('INSERT INTO entries (entry_id,owner_id,service_id,label,created_at) VALUES (?,?,?,?,?)').bind(entry,owner,'google',entry,NOW).run();
 const access=new EntryAccess(db,{async latestOwned(ownerId,entryId){return {entryId,code:'123456',receivedAt:NOW,expiresAt:NOW+1000};}});
 const tokens=new EntryTokenStore(db,access);
 return {db,access,tokens};
}
test('entry tokens name one entry, require live automation permission, and never store raw credentials',async()=>{
 const {db,access,tokens}=await setup();
 assert.equal(await tokens.mint('b','shared','agent',1000,NOW),undefined);
 await access.share('a','shared','b',{},NOW);
 assert.equal(await tokens.mint('b','shared','agent',1000,NOW),undefined);
 await access.share('a','shared','b',{allowAutomation:true},NOW);
 const minted=await tokens.mint('b','shared','agent',1000,NOW);
 assert.equal((await tokens.verify(minted.token,NOW)).actorId,'b');
 assert.ok(!JSON.stringify(db.sqlite.prepare('SELECT * FROM entry_tokens').all()).includes(minted.token));
 const handler=createEntryReadHandler({tokens,access,clock:()=>NOW});
 const request=entry=>new Request('https://test.invalid/v1/entries/code?entry='+entry,{headers:{authorization:'Bearer '+minted.token}});
 assert.equal((await handler.fetch(request('private'))).status,403);
 assert.equal((await handler.fetch(request('shared'))).status,200);
 await access.revoke('a','shared','b',NOW);
 assert.equal(await tokens.verify(minted.token,NOW),undefined);
 assert.equal((await handler.fetch(request('shared'))).status,401);
 db.sqlite.close();
});
test('owner token expiry/revocation and token-actor isolation',async()=>{
 const {db,tokens}=await setup();
 const minted=await tokens.mint('a','private','agent',1000,NOW);
 assert.equal(await tokens.verify(minted.token,NOW+1000),undefined);
 await tokens.revoke('b',minted.tokenId,NOW);
 assert.ok(await tokens.verify(minted.token,NOW));
 await tokens.revoke('a',minted.tokenId,NOW);
 assert.equal(await tokens.verify(minted.token,NOW),undefined);
 assert.deepEqual(await tokens.list('b'),[]);
 db.sqlite.close();
});
test('removing recipient automation permission invalidates old grants immediately',async()=>{
 const {db,access,tokens}=await setup();
 await access.share('a','shared','b',{allowAutomation:true},NOW);
 const minted=await tokens.mint('b','shared','agent',1000,NOW);
 await access.share('a','shared','b',{allowAutomation:false},NOW);
 assert.equal(await tokens.verify(minted.token,NOW),undefined);
 assert.equal(await access.canRead('b','shared'),true);
 await access.share('a','shared','b',{allowAutomation:true},NOW);
 assert.equal(await tokens.verify(minted.token,NOW),undefined);
 db.sqlite.close();
});
