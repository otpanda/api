import test from 'node:test';import assert from 'node:assert/strict';
import {database} from './sqlite-helper.js';import {authenticator} from './passkey-fixture.js';
import {DeviceSessionService} from '../src/device-sessions.js';import {GoogleAccountService} from '../src/google-account.js';
import {googlePictureUrl,googleEmailEvidence} from '../src/account-identity.js';import {createAccountOverviewHttp} from '../src/account-overview-http.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',OK='https://lh3.googleusercontent.com/a/ACg8ocAbC-123=s96-c',ISS='https://accounts.google.com';
const claims=(extra={})=>({iss:ISS,sub:'sub-1',email:'a@gmail.com',email_verified:true,...extra});
test('picture validator accepts only plain https googleusercontent URLs',()=>{
 assert.equal(googlePictureUrl(OK),OK);
 for(const bad of [undefined,null,5,'','http://lh3.googleusercontent.com/a/x','https://evil.test/a.png','https://googleusercontent.com.evil.test/a','https://evil.test/?x=lh3.googleusercontent.com','https://lh3.googleusercontent.com/a/x?s=96','https://lh3.googleusercontent.com/a/x#f','https://u:p@lh3.googleusercontent.com/a/x','https://lh3.googleusercontent.com:8443/a/x','https://LH3.googleusercontent.com/a/x','https://lh3.googleusercontent.com/'+'a'.repeat(600),'javascript:alert(1)','data:image/png;base64,AAAA','//lh3.googleusercontent.com/a/x',' '+OK])assert.equal(googlePictureUrl(bad),undefined,String(bad).slice(0,40));
});
test('evidence carries a valid picture and silently drops an invalid one',()=>{
 assert.equal(googleEmailEvidence(claims({picture:OK})).picture,OK);assert.equal('picture' in googleEmailEvidence(claims({picture:'https://evil.test/x'})),false);assert.equal('picture' in googleEmailEvidence(claims()),false);
});
async function setup(){const db=database(),now=Date.now(),clock=()=>now;
 db.sqlite.prepare('INSERT INTO accounts(owner_id,created_at) VALUES(?,?)').run('owner',now);db.sqlite.prepare('INSERT INTO account_emails VALUES(?,?,?,?)').run('owner','a@gmail.com',now,now);db.sqlite.prepare('INSERT INTO account_security(owner_id) VALUES(?)').run('owner');
 const a=authenticator();db.sqlite.prepare('INSERT INTO passkey_credentials(credential_id,owner_id,public_key,counter,transports,device_type,backed_up,created_at) VALUES(?,?,?,?,?,?,?,?)').run(a.credential.id,'owner',a.credential.publicKey,0,'[]','singleDevice',0,now);
 const sessions=new DeviceSessionService(db,{clock}),pk=await sessions.issue({proof:{authMethod:'passkey',credentialId:a.credential.id,ownerId:'owner',generation:0,purpose:'authenticate',verifiedAt:now},clientKind:'web'});
 const http=createAccountOverviewHttp({db,sessions,clock}),overview=async()=>(await http.fetch(new Request(API+'/v1/manage/account',{headers:{Origin:APP,Authorization:'Bearer '+pk.access}}),{clientAddress:'192.0.2.1'})).json();
 return{db,now,overview,google:new GoogleAccountService(db,{clock}),row:()=>db.sqlite.prepare('SELECT picture FROM provider_identities WHERE revoked_at IS NULL').get()};}
const link=(x,picture)=>x.db.sqlite.prepare("INSERT INTO provider_identities(identity_id,owner_id,provider,issuer,subject,email,created_at,picture) VALUES('one','owner','google',?,'sub-1','a@gmail.com',1,?)").run(ISS,picture);
test('overview returns the picture only for an active Google link with a valid stored URL, and re-validates on read',async()=>{
 const x=await setup();assert.equal('picture' in await x.overview(),false,'no link, no key');
 link(x,null);assert.equal('picture' in await x.overview(),false,'linked without picture, no key');
 x.db.sqlite.prepare('UPDATE provider_identities SET picture=?').run(OK);const o=await x.overview();assert.equal(o.picture,OK);assert.equal(o.google,true);
 x.db.sqlite.prepare('UPDATE provider_identities SET picture=?').run('https://evil.test/x.png');assert.equal('picture' in await x.overview(),false,'a bad stored value is never returned');
 x.db.sqlite.prepare('UPDATE provider_identities SET picture=?').run(OK);x.db.sqlite.prepare('UPDATE provider_identities SET revoked_at=1').run();assert.equal('picture' in await x.overview(),false,'unlinked, no picture');
});
test('a Google sign-in refreshes or clears the stored picture; invalid claims never store',async()=>{
 const x=await setup();link(x,null);const id={issuer:ISS,subject:'sub-1',email:'a@gmail.com',authoritative:true};
 assert.equal((await x.google.resolve({...id,picture:OK})).status,'linked');assert.equal(x.row().picture,OK);
 await x.google.resolve({...id,picture:'https://lh3.googleusercontent.com/a/new=s96-c'});assert.equal(x.row().picture,'https://lh3.googleusercontent.com/a/new=s96-c');
 await x.google.resolve({...id,picture:'https://evil.test/x'});assert.equal(x.row().picture,null,'an invalid claim clears it');
 await x.google.resolve({...id,picture:OK});await x.google.resolve(id);assert.equal(x.row().picture,null,'a missing claim clears it');
 assert.equal(x.db.sqlite.prepare('SELECT count(*) n FROM account_security').get().n,1,'authority state untouched');
});
test('a new Google signup stores the picture on the created identity',async()=>{
 const db=database(),g=new GoogleAccountService(db,{clock:()=>Date.now()});
 const r=await g.resolve({issuer:ISS,subject:'new-sub',email:'n@gmail.com',authoritative:true,picture:OK});assert.equal(r.status,'created');assert.equal(db.sqlite.prepare("SELECT picture FROM provider_identities WHERE subject='new-sub'").get().picture,OK);
 const r2=await g.resolve({issuer:ISS,subject:'new-2',email:'m@gmail.com',authoritative:true,picture:'http://lh3.googleusercontent.com/x'});assert.equal(r2.status,'created');assert.equal(db.sqlite.prepare("SELECT picture FROM provider_identities WHERE subject='new-2'").get().picture,null);
});
