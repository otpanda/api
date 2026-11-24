import test from 'node:test';
import assert from 'node:assert/strict';
import {database} from './sqlite-helper.js';
import {createEntryApplication} from '../src/entry-application.js';
import {SessionService} from '../src/sessions.js';
import {parseAccessToken} from '../src/tokens.js';
import {SourceEntryStore} from '../src/source-entries.js';
import {CodeCipher} from '../src/code-cipher.js';
const NOW=1800000000000;
test('integrated cleanup purges expired encrypted incoming codes in bounded batches',async()=>{
 const db=database();await db.prepare('INSERT INTO accounts VALUES (?,?)').bind('a',0).run();
 const key=await crypto.subtle.generateKey({name:'AES-GCM',length:256},false,['encrypt','decrypt']);
 const cipher=new CodeCipher({keys:new Map([['test',key]]),activeKeyId:'test'});
 const sources=new SourceEntryStore(db,cipher),source=await sources.createSource('a','sms','Demo',0);
 // Duplicate synthetic encrypted envelopes for expiry behavior only. These
 // unassigned rows are not decrypted by this test.
 const expired=JSON.stringify(await cipher.encrypt('123456',{ownerId:'a',recordId:'demo',serviceId:'unassigned',receivedAt:NOW-2000,expiresAt:NOW-1000}));
 const insert=db.sqlite.prepare("INSERT INTO incoming_codes (owner_id,event_id,source_id,entry_id,envelope,received_at,expires_at,assignment) VALUES (?,?,?,NULL,?,?,?,'unassigned')");
 for(let n=0;n<105;n++)insert.run('a','expired-'+n,source,expired,NOW-2000,NOW-1000);
 insert.run('a','current',source,expired,NOW,NOW+1000);
 const sessions=new SessionService(db,{origin:'https://app.test',clock:()=>NOW});
 const current=await sessions.issue('a');await sessions.issue('a');db.sqlite.prepare('UPDATE sessions SET created_at=?,expires_at=? WHERE session_id<>?').run(NOW-2000,NOW-1000,parseAccessToken(current.session).tokenId);
 const app=createEntryApplication({db,sessions,access:{},tokens:{},trustedRequestKey:()=> 'cleanup',clock:()=>NOW});
 await app.cleanup();assert.equal(db.sqlite.prepare('SELECT count(*) AS n FROM incoming_codes').get().n,6);
 assert.equal(db.sqlite.prepare('SELECT count(*) AS n FROM sessions').get().n,1);
 await app.cleanup();assert.equal(db.sqlite.prepare('SELECT count(*) AS n FROM incoming_codes').get().n,1);
 assert.equal(db.sqlite.prepare('SELECT event_id FROM incoming_codes').get().event_id,'current');
 await app.cleanup();assert.equal(db.sqlite.prepare('SELECT count(*) AS n FROM incoming_codes').get().n,1);db.sqlite.close();
});
