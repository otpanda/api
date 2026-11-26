// Isolated synthetic actual common-horizon runtime. Never imported by production.
import {createIdentityRuntime} from '../src/identity-runtime.js';
import {importBrowserKeyring} from '../src/browser-keyring.js';
import fixture from './fixture.json';
const policy={entryCap:5,budget:100,minPeriod:20,maxPeriod:86400,maxWindow:600,minUsefulWindow:60};
let app,queryCount=0;
function counted(db){
 const statement=s=>new Proxy(s,{get(target,key){if(key==='bind')return(...args)=>statement(target.bind(...args));if(['all','first','run','raw'].includes(key))return(...args)=>{queryCount++;return target[key](...args)};const v=target[key];return typeof v==='function'?v.bind(target):v;}});
 return{prepare:sql=>statement(db.prepare(sql)),batch:statements=>db.batch(statements),exec:sql=>{queryCount++;return db.exec(sql)}};
}
export default {async fetch(request,env){
 const u=new URL(request.url),prefix='/'+env.FIXTURE_PREFIX;
 if(!u.pathname.startsWith(prefix+'/'))return new Response(null,{status:404});
 const path=u.pathname.slice(prefix.length);
 if(!['/v1/manage/totp-codes','/v1/manage/session'].includes(path))return new Response(null,{status:404});
 const requestId=crypto.randomUUID();console.log(JSON.stringify({qualificationRequestId:requestId}));
 queryCount=0;
 app??=createIdentityRuntime({db:counted(env.DB),loadCodeKeys:()=>importBrowserKeyring({ACTIVE_KEY_ID:'synthetic',ENCRYPTION_KEYRING:JSON.stringify([{id:'synthetic',key:'CwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCwsLCws'}])}),trustedRequestKey:()=> '192.0.2.1',clock:()=>fixture.now,batch:{horizonPolicy:policy,ratePerMinute:24,minRemainingMs:1000}});
 const headers=new Headers(request.headers);headers.set('Origin','https://otpanda.github.io');
 const started=performance.now();
 const r=await app.fetch(new Request('https://otpanda-api.abrahammurciano.workers.dev'+path+u.search,{headers}));
 const body=await r.json();
 return Response.json({requestId,status:r.status,queryCount,wallMs:performance.now()-started,body},{status:r.status});
}};
