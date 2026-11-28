// Real source-migration schema and exact inspection SQL, no remote calls.
// Does not return fixture rows as a substitute for executing the SELECT.
import vm from 'node:vm';
import assert from 'node:assert/strict';
import {readFileSync,readdirSync} from 'node:fs';
import {createHash} from 'node:crypto';
import {database} from '../../test/sqlite-helper.js';
const db=database();
db.sqlite.exec('CREATE TABLE d1_migrations(name TEXT)');
for(const name of readdirSync('migrations').filter(n=>n.endsWith('.sql')))db.sqlite.prepare('INSERT INTO d1_migrations VALUES(?)').run(name);
const text=readFileSync(new URL('./sharing-inspect.mjs',import.meta.url),'utf8').replace(/^import .*;$/gm,'');
let executed=[],out=[];const uuid='12345678-1234-1234-1234-123456789abc';
const context={createHash,readFileSync,readdirSync,AbortSignal,process:{env:{CLOUDFLARE_API_TOKEN:'local-not-secret',CLOUDFLARE_ACCOUNT_ID:'a04834f19f0dfd5dc4eb47515d15478d'}},console:{log:s=>out.push(JSON.parse(s))},fetch:async(url,init)=>{
 let result;
 if(init.method==='POST'){const{sql}=JSON.parse(init.body);assert.match(sql,/^SELECT /);executed.push(sql);result=[{results:db.sqlite.prepare(sql).all()}];}
 else if(url.endsWith('/settings'))result={bindings:[{name:'DB',type:'d1',id:'626cd908-0951-49cf-92a2-9a54cbbb40a8'},...['IDENTITY_ADDRESS_LIMIT','IDENTITY_AUTH_GLOBAL_LIMIT','IDENTITY_READ_GLOBAL_LIMIT'].map(name=>({name,type:'ratelimit',simple:{limit:15,period:60}}))]};
 else if(url.endsWith('/versions'))result={items:[{id:uuid}]};
 else if(url.endsWith('/deployments'))result={deployments:[{id:uuid,versions:[{version_id:uuid,percentage:100}]}]};
 else result={uuid:'626cd908-0951-49cf-92a2-9a54cbbb40a8'};
 return{ok:true,status:200,json:async()=>({success:true,result})};
}};
try{
 await vm.runInNewContext('(async()=>{'+text+'})()',context);
 assert.equal(context.process.exitCode,undefined,JSON.stringify(out));
 assert.equal(executed.length,3);
 const columns=out.find(x=>x.check==='columns');assert.equal(columns.status,'matches');
 const view=columns.columns.filter(c=>c.table==='entry_readers');assert.equal(view.length,5);assert.ok(view.every(c=>c.state==='matches'));
 const schema=out.find(x=>x.check==='schema');assert.equal(schema.status,'matches');assert.equal(schema.objects.length,41);
 console.log('real source migrations plus three exact inspection SELECTs pass; 41 scoped objects and 5 entry_readers view columns match');
}finally{db.sqlite.close();}
