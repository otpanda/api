import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { ServiceMetadata,normalizeDomain,normalizeEmail,normalizePhone } from '../src/service-metadata.js';
const NOW=1800000000000;
async function setup(){
 const db=database();for(const owner of ['a','b'])await db.prepare('INSERT INTO accounts VALUES (?,?)').bind(owner,NOW).run();
 await db.prepare('INSERT INTO sources (source_id,owner_id,kind,label,created_at) VALUES (?,?,?,?,?)').bind('mail','a','gmail','Mail',NOW).run();
 await db.prepare('INSERT INTO sources (source_id,owner_id,kind,label,created_at) VALUES (?,?,?,?,?)').bind('phone','a','sms','Phone',NOW).run();
 for(const entry of ['personal','work'])await db.prepare('INSERT INTO entries (entry_id,owner_id,service_id,label,created_at) VALUES (?,?,?,?,?)').bind(entry,'a','google',entry,NOW).run();
 const metadata=new ServiceMetadata(db);await metadata.putService('google',{name:'Google',websiteHost:'google.com'});
 await metadata.setReceiver('a','mail','Me@example.com');await metadata.setReceiver('a','phone','+12025550199');
 return {db,metadata};
}
test('service metadata and optional account name are separate; local icon keys only',async()=>{
 const {db,metadata}=await setup();
 assert.equal(await metadata.setEntryAccount('a','personal','Personal'),true);
 assert.equal(await metadata.setEntryAccount('b','personal','Hacked'),false);
 assert.equal(await metadata.setEntryAccount('a','work',null),true);
 await assert.rejects(metadata.putService('bad',{name:'Bad',iconKey:'https://track.invalid/logo'}));
 assert.equal(normalizeEmail('Me@EXAMPLE.com'),'Me@example.com');
 assert.equal(normalizeEmail('me+tag@example.com'),'me+tag@example.com');
 assert.throws(()=>normalizeDomain('google.com.evil/'));
 assert.throws(()=>normalizePhone('00447397842936'));
 db.sqlite.close();
});
test('receiving source plus exact email/domain origin routes without suffix confusion',async()=>{
 const {db,metadata}=await setup();
 await metadata.addRoute('a',{serviceId:'google',sourceId:'mail',originKind:'email_domain',originValue:'accounts.google.com',entryId:'personal'});
 const event={sourceId:'mail',receiver:'Me@example.com',sender:'noreply@accounts.google.com'};
 assert.equal((await metadata.match('a',event)).entryId,'personal');
 assert.equal((await metadata.match('a',{...event,sender:'noreply@accounts.google.com.evil'})).entryId,null);
 assert.equal((await metadata.match('a',{...event,receiver:'other@example.com'})).entryId,null);
 assert.equal((await metadata.match('b',event)).entryId,null);
 await assert.rejects(metadata.addRoute('b',{serviceId:'google',sourceId:'mail',originKind:'email_domain',originValue:'accounts.google.com',entryId:'personal'}));
 db.sqlite.close();
});
test('conflicting entries remain ambiguous; account discriminators can narrow explicit routes',async()=>{
 const {db,metadata}=await setup();
 for(const [entryId,accountHint] of [['personal','personal'],['work','work']])await metadata.addRoute('a',{serviceId:'google',sourceId:'mail',originKind:'email_address',originValue:'noreply@google.com',entryId,accountHint});
 const event={sourceId:'mail',receiver:'Me@example.com',sender:'noreply@google.com'};
 assert.equal((await metadata.match('a',event)).entryId,null);
 assert.equal((await metadata.match('a',{...event,accountHint:'personal'})).entryId,'personal');
 await metadata.addRoute('a',{serviceId:'google',sourceId:'mail',originKind:'email_domain',originValue:'google.com',entryId:'work'});
 assert.equal((await metadata.match('a',{...event,accountHint:'personal'})).reason,'ambiguous');
 db.sqlite.close();
});
test('phone routes require exact E.164 receiver and origin, never substring matches',async()=>{
 const {db,metadata}=await setup();
 await metadata.addRoute('a',{serviceId:'google',sourceId:'phone',originKind:'sms_number',originValue:'+12025550123',entryId:'personal'});
 const event={sourceId:'phone',receiver:'+12025550199',sender:'+12025550123'};
 assert.equal((await metadata.match('a',event)).entryId,'personal');
 assert.equal((await metadata.match('a',{...event,sender:'+12025550124'})).entryId,null);
 await assert.rejects(metadata.addRoute('a',{serviceId:'google',sourceId:'mail',originKind:'sms_number',originValue:'+12025550123',entryId:'personal'}));
 db.sqlite.close();
});
