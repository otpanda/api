import test from 'node:test';
import assert from 'node:assert/strict';
import { permitsCodeRead } from '../src/grants.js';
const now=1000;
const grant={ ownerId:'owner-a',clientId:'automation-a',serviceId:'example',scopes:['codes:read'],notBefore:900,expiresAt:1100,revokedAt:null };
const request={ownerId:'owner-a',clientId:'automation-a',serviceId:'example'};
test('explicit service-scoped grant allows unattended read',()=>assert.equal(permitsCodeRead(grant,request,now),true));
test('cross-user, cross-client and cross-service reads denied',()=>{
 for(const key of ['ownerId','clientId','serviceId']) assert.equal(permitsCodeRead(grant,{...request,[key]:'other'},now),false);
});
test('revoked, expired, not-yet-valid, missing and malformed grants denied',()=>{
 for(const change of [{revokedAt:950},{revokedAt:undefined},{expiresAt:1000},{expiresAt:999},{notBefore:1001},{scopes:[]},{scopes:'codes:read'},{expiresAt:Infinity},{notBefore:undefined}]) assert.equal(permitsCodeRead({...grant,...change},request,now),false);
 assert.equal(permitsCodeRead(null,request,now),false);
 assert.equal(permitsCodeRead(grant,null,now),false);
 assert.equal(permitsCodeRead(grant,request,NaN),false);
});
