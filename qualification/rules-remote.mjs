import {execFileSync} from 'node:child_process';
import {readFileSync,writeFileSync,mkdirSync,copyFileSync,readdirSync,rmSync} from 'node:fs';
import assert from 'node:assert/strict';
const name='otpanda-rules-qual-'+process.env.GITHUB_RUN_ID;
const root='qualification/rules-temp';mkdirSync(root+'/migrations',{recursive:true});
const config=root+'/wrangler.json';
const run=(args)=>execFileSync('npx',['wrangler',...args,'--config',config],{encoding:'utf8',maxBuffer:8e6});
const conf={name,compatibility_date:'2026-11-23',d1_databases:[]};writeFileSync(config,JSON.stringify(conf));
let dbid;
try{
 const created=run(['d1','create',name]);const m=created.match(/"database_id"\s*:\s*"([0-9a-f-]{36})"/);assert.ok(m,'D1 create returned id');dbid=m[1];
 conf.d1_databases=[{binding:'DB',database_name:name,database_id:dbid,migrations_dir:'migrations'}];writeFileSync(config,JSON.stringify(conf));
 for(const file of readdirSync('migrations').sort().filter(f=>f<'0062'))copyFileSync('migrations/'+file,root+'/migrations/'+file);
 run(['d1','migrations','apply',name,'--remote']);
 run(['d1','execute',name,'--remote','--file','qualification/rules-seed.sql']);
 copyFileSync('migrations/0062_rule_pause.sql',root+'/migrations/0062_rule_pause.sql');run(['d1','migrations','apply',name,'--remote']);
 const sql=(query)=>{const data=JSON.parse(run(['d1','execute',name,'--remote','--command',query,'--json']));return data.at(-1).results;};
 const row=id=>sql("SELECT paused_at FROM service_routes WHERE route_id='"+id+"'")[0];
 const previews=()=>sql('SELECT context_id FROM unassigned_context ORDER BY context_id').map(r=>r.context_id);
 assert.equal(row('qual-dead-route').paused_at,100);assert.equal(row('qual-live-route').paused_at,null);assert.deepEqual(previews(),['qual-live-preview']);
 sql("UPDATE sources SET revoked_at=NULL WHERE source_id='qual-dead'");assert.equal(row('qual-dead-route').paused_at,100);
 sql("UPDATE sources SET revoked_at=200 WHERE source_id='qual-live'");assert.equal(row('qual-live-route').paused_at,200);assert.deepEqual(previews(),[]);
 sql("UPDATE sources SET revoked_at=NULL WHERE source_id='qual-live'");assert.equal(row('qual-live-route').paused_at,200);
 // Reconnect must pause even a rule manually made active while revoked.
 sql("UPDATE sources SET revoked_at=300 WHERE source_id='qual-live'");sql("UPDATE service_routes SET paused_at=NULL WHERE route_id='qual-live-route'");sql("UPDATE sources SET revoked_at=NULL WHERE source_id='qual-live'");assert.equal(row('qual-live-route').paused_at,300);
 sql("UPDATE sources SET revoked_at=400 WHERE source_id='qual-live' AND 0");assert.equal(sql("SELECT revoked_at FROM sources WHERE source_id='qual-live'")[0].revoked_at,null);assert.equal(row('qual-live-route').paused_at,300);
 const report={remoteD1:true,syntheticOnly:true,migrationBackfill:true,revokeTrigger:true,unrevokeTrigger:true,neverAutoResume:true,guardNoop:true,previewDeletion:true,productionTouched:false};writeFileSync('qualification/rules-remote-result.json',JSON.stringify(report,null,2));console.log(JSON.stringify(report));
}finally{
 if(dbid){run(['d1','delete',dbid,'--skip-confirmation']);console.log('Synthetic D1 deleted');}
 rmSync(root,{recursive:true,force:true});
}
