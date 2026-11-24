import test from 'node:test';
import assert from 'node:assert/strict';
import {database} from './sqlite-helper.js';
import {SessionService,SESSION_COOKIE} from '../src/sessions.js';
import {SourceEntryStore} from '../src/source-entries.js';
import {ServiceMetadata} from '../src/service-metadata.js';
import {EntryAccess} from '../src/entry-access.js';
import {EntryTokenStore} from '../src/entry-tokens.js';
import {createEntryApplication} from '../src/entry-application.js';
const NOW=1800000000000;
async function setup(){
 const db=database();for(const owner of ['a','b'])await db.prepare('INSERT INTO accounts VALUES (?,?)').bind(owner,NOW).run();
 const sessions=new SessionService(db,{origin:'https://app.test',clock:()=>NOW});
 const sources=new SourceEntryStore(db,{}),metadata=new ServiceMetadata(db),access=new EntryAccess(db,sources),tokens=new EntryTokenStore(db,access);
 const app=createEntryApplication({db,sessions,sources,metadata,access,tokens,trustedRequestKey:()=> 'management',clock:()=>NOW});
 const issued={a:await sessions.issue('a'),b:await sessions.issue('b')};
 const req=(actor,path,method='GET',body,extra={})=>new Request('https://app.test/v1/manage/'+path,{method,headers:{cookie:SESSION_COOKIE+'='+issued[actor].session,origin:'https://app.test','x-otpanda-csrf':issued[actor].csrf,'content-type':'application/json',...extra},body:body===undefined?undefined:JSON.stringify(body)});
 return {db,sessions,sources,metadata,access,tokens,app,req};
}
test('browser management creates entries, optional account names, mints/revokes entry tokens and deletes',async()=>{
 const {db,app,req,tokens}=await setup();
 const created=await app.fetch(req('a','entries','POST',{serviceId:'new.test',label:'New',accountName:'work'}));assert.equal(created.status,201);
 const {entryId}=await created.json();
 assert.equal((await(await app.fetch(req('a','entries'))).json()).entries[0].account_name,'work');
 const minted=await app.fetch(req('a','tokens','POST',{entryId,clientId:'cli',ttlMs:1000}));assert.equal(minted.status,201);
 const token=await minted.json();assert.ok(await tokens.verify(token.token,NOW));
 assert.equal((await app.fetch(req('a','tokens/'+token.tokenId,'DELETE'))).status,200);assert.equal(await tokens.verify(token.token,NOW),undefined);
 assert.equal((await app.fetch(req('a','entries','PATCH',{entryId,label:'Renamed'}))).status,200);
 assert.equal((await app.fetch(req('a','entry-account','PATCH',{entryId,accountName:null}))).status,200);
 assert.equal((await app.fetch(req('a','entries','DELETE',{entryId}))).status,200);
 assert.equal((await(await app.fetch(req('a','entries'))).json()).entries.length,0);db.sqlite.close();
});
test('shared recipients cannot mutate entry metadata or create tokens without separate automation permission',async()=>{
 const {db,sources,access,app,req}=await setup();const entryId=await sources.createEntry('a','shared.test','Shared',NOW);await access.share('a',entryId,'b',{},NOW);
 for(const [path,method,body] of [['entries','PATCH',{entryId,label:'Hijacked'}],['entry-account','PATCH',{entryId,accountName:'Hijacked'}],['entries','DELETE',{entryId}]])assert.equal((await app.fetch(req('b',path,method,body))).status,404);
 assert.equal((await app.fetch(req('b','tokens','POST',{entryId,clientId:'cli',ttlMs:1000}))).status,403);
 await access.share('a',entryId,'b',{allowAutomation:true},NOW);assert.equal((await app.fetch(req('b','tokens','POST',{entryId,clientId:'cli',ttlMs:1000}))).status,201);db.sqlite.close();
});
test('management rejects oversized/unknown fields, invalid media type and bearer-only credentials',async()=>{
 const {db,app,req}=await setup();
 assert.equal((await app.fetch(req('a','entries','POST',{serviceId:'new.test',label:'New',ownerId:'b'}))).status,400);
 assert.equal((await app.fetch(req('a','entries','POST',{serviceId:'new.test',label:'x'.repeat(5000)}))).status,413);
 assert.equal((await app.fetch(req('a','entries','POST',{serviceId:'new.test',label:'New'},{'content-type':'text/plain'}))).status,400);
 assert.equal((await app.fetch(new Request('https://app.test/v1/manage/entries',{method:'POST',headers:{authorization:'Bearer test','content-type':'application/json'},body:'{}'}))).status,401);
 assert.equal(db.sqlite.prepare('SELECT count(*) AS n FROM entries').get().n,0);db.sqlite.close();
});
