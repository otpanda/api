import test from 'node:test';
import assert from 'node:assert/strict';
import {database} from './sqlite-helper.js';
import {cleanupIdentity} from '../src/identity-cleanup.js';
import {AccountIdentityService} from '../src/account-identity.js';
import {PasskeyService} from '../src/passkey-service.js';
const NOW=1800000000000;
test('bounded cleanup removes expired rows, preserves live rows and repeats safely',async()=>{
 const db=database();try {
 let now=NOW;const clock=()=>now,identity=new AccountIdentityService(db,{clock}),passkeys=new PasskeyService(db,{clock});
 for(let i=0;i<5;i++) {await identity.issueEmailChallenge({purpose:'signup-email',email:'a@example.test',ttlMs:1});await passkeys.begin({purpose:'authenticate',binding:'b'.repeat(43)});}
 now+=120001;
 await identity.issueEmailChallenge({purpose:'signup-email',email:'b@example.test'});await passkeys.begin({purpose:'authenticate',binding:'c'.repeat(43)});
 const first=await cleanupIdentity({db,clock,limit:2});assert.equal(first.auth_challenges,2);assert.equal(first.passkey_ceremonies,2);
 assert.equal(db.sqlite.prepare('SELECT count(*) AS n FROM auth_challenges').get().n,4);
 await cleanupIdentity({db,clock,limit:2});await cleanupIdentity({db,clock,limit:2});const last=await cleanupIdentity({db,clock,limit:2});assert.equal(last.auth_challenges,0);assert.equal(last.passkey_ceremonies,0);assert.equal(db.sqlite.prepare('SELECT count(*) AS n FROM auth_challenges').get().n,1);
 }finally{db.sqlite.close();}
});
test('every cleanup statement is fixed-table and explicitly bounded',async()=>{
 const calls=[],db={prepare(sql){assert.match(sql,/DELETE FROM/);assert.match(sql,/LIMIT \?2/);assert.doesNotMatch(sql,/DELETE FROM sessions /);return {bind(...args){assert.equal(args[1],3);calls.push(sql);return {async run(){return {meta:{changes:0}};}};}};}};
 const result=await cleanupIdentity({db,clock:()=>NOW,limit:3});assert.equal(calls.length,39);assert.equal(Object.keys(result).length,38);
 for(const limit of [0,-1,501,1.5])await assert.rejects(cleanupIdentity({db,limit}));
 await assert.rejects(cleanupIdentity({db,clock:()=>NaN}));
});
