import test from 'node:test';
import assert from 'node:assert/strict';
import { database } from './sqlite-helper.js';
import { SourceEntryStore } from '../src/source-entries.js';
import { CodeCipher } from '../src/code-cipher.js';
import { extractEmailCode, extractExpiry } from '../src/email-code-extractor.js';
import { ingestEmail } from '../src/email-ingest.js';
import { normalizeOutlookMessage } from '../src/email-message-normalizers.js';
const NOW=1800000000000;
test('extractor picks the code, not years, phones, amounts or order numbers',()=>{
 assert.equal(extractEmailCode('Your verification code is 482913. It expires in 10 minutes.'),'482913');
 assert.equal(extractEmailCode('Security code: 123-456'),'123456');
 assert.equal(extractEmailCode('Order 99887766 total $1234. Call +1 555 0100. Copyright 2026.'),null);
 assert.equal(extractEmailCode('Sent 2026. Your one-time passcode is 7731'),'7731');
 assert.equal(extractEmailCode('Welcome to our newsletter 4821'),null);
 assert.equal(extractEmailCode(null),null);
 assert.equal(extractExpiry('code expires in 5 minutes',NOW),NOW+300000);
 assert.equal(extractExpiry('valid for 99 hours',NOW),NOW+86400000);
 assert.equal(extractExpiry('no hint',NOW),NOW+600000);
});
async function setup(){
 const db=database();await db.prepare('INSERT INTO accounts VALUES (?,?)').bind('a',NOW).run();
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
 const store=new SourceEntryStore(db,new CodeCipher({keys:new Map([['t',key]]),activeKeyId:'t'}));
 const source=await store.createSource('a','gmail','Gmail',NOW);const entry=await store.createEntry('a','example','Example',NOW);
 await store.addRule('a',{sourceId:source,entryId:entry,sender:'noreply@example.test',accountHint:'me@example.test'},NOW);
 return {db,store,source,entry};
}
const msg={id:'m1',from:'noreply@example.test',to:'me@example.test',subject:'Your code',text:'Your verification code is 482913',receivedAt:NOW,provider:'gmail'};
test('ingest assigns by rule, is replay-safe, and skips code-less mail and any provider other than gmail',async()=>{
 const {db,store,source,entry}=await setup();
 const r=await ingestEmail(store,'a',source,msg);
 assert.deepEqual([r.ingested,r.entryId],[true,entry]);
 assert.equal((await store.latestOwned('a',entry,NOW+1)).code,'482913');
 assert.equal((await ingestEmail(store,'a',source,msg)).reason,'duplicate');
 assert.equal((await ingestEmail(store,'a',source,{...msg,id:'m3',provider:undefined})).reason,'provider_disabled');
 assert.equal((await ingestEmail(store,'a',source,{...msg,id:'m4',text:'hello'})).reason,'no-code');
 assert.equal((await ingestEmail(store,'a',source,{...msg,id:'m5',from:'evil@other.test'})).entryId,null);
 assert.equal((await ingestEmail(store,'b',source,{...msg,id:'m6'}).catch(()=>({ingested:'threw'}))).ingested,'threw');
 const row=db.sqlite.prepare('SELECT envelope FROM incoming_codes WHERE event_id=?').get('m1');
 assert.ok(!JSON.stringify(row).includes('482913'));
 db.sqlite.close();
});
test('outlook stays disabled: normalizer output is rejected by ingest',async()=>{
 const o=normalizeOutlookMessage({id:'o1',receivedDateTime:new Date(NOW).toISOString(),subject:'x',from:{emailAddress:{address:'a@example.test'}},toRecipients:[{emailAddress:{address:'me@example.test'}}],body:{contentType:'text',content:'Your login code: 246810'},internetMessageHeaders:[{name:'Authentication-Results',value:'protection.outlook.com; dkim=pass; dmarc=pass header.from=example.test'}]});
 assert.equal(o.provider,'outlook');assert.equal(o.receivedAt,NOW);
 const {db,store,source}=await setup();
 assert.equal((await ingestEmail(store,'a',source,o)).reason,'provider_disabled');
 assert.equal((await ingestEmail(store,'a',source,{...msg,id:'d1',provider:'outlook'})).reason,'provider_disabled');
 db.sqlite.close();
});
