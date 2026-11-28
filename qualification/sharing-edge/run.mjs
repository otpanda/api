import{spawnSync,spawn}from'node:child_process';import{readFileSync,writeFileSync,openSync,rmSync}from'node:fs';import{randomBytes}from'node:crypto';
const root='qualification/sharing-edge/',config=root+'wrangler.json',name='otpanda-sharing-edge-'+process.env.GITHUB_RUN_ID,account=process.env.CLOUDFLARE_ACCOUNT_ID;
if(!/^otpanda-sharing-edge-[0-9]+$/.test(name)||account!=='a04834f19f0dfd5dc4eb47515d15478d')throw Error('Scope');
const api='https://api.cloudflare.com/client/v4/accounts/'+account,headers={Authorization:'Bearer '+process.env.CLOUDFLARE_API_TOKEN};let id,workerPossible=false,tail,tailFailed=false,stage='scope';const completed={databaseCreated:false,migrationsApplied:false,workerDeployAttempted:false,workerDeployed:false,tailStarted:false,driverCompleted:false,cpuValidated:false};
function command(args){const r=spawnSync('npx',['wrangler',...args,'--config',config],{encoding:'utf8',timeout:90000,maxBuffer:2e6});if(r.status!==0)throw Error('Wrangler stage failed');return r.stdout;}
async function absent(path){const d=await fetch(api+path,{method:'DELETE',headers});if(!d.ok&&d.status!==404)throw Error('Delete failed');const v=await fetch(api+path,{headers});if(v.status!==404)throw Error('Absence not proven');return true;}
let failure=false;const cleanup={workerAbsent:false,databaseAbsent:false};
try{
 stage='config';const c=JSON.parse(readFileSync(config));c.name=name;c.vars.FIXTURE_PREFIX=randomBytes(24).toString('hex');c.d1_databases[0].database_name=name;writeFileSync(config,JSON.stringify(c));
 // Direct create captures immutable ID before any subsequent action. No raw result in logs.
 stage='database_create';const r=await fetch(api+'/d1/database',{method:'POST',headers:{...headers,'Content-Type':'application/json'},body:JSON.stringify({name})});const b=await r.json();id=b.result?.uuid;if(!r.ok||!b.success||!/^[a-f0-9-]{36}$/.test(id??''))throw Error('Create failed');
 completed.databaseCreated=true;c.d1_databases[0].database_id=id;writeFileSync(config,JSON.stringify(c));
 stage='migrations';command(['d1','migrations','apply',name,'--remote']);completed.migrationsApplied=true;stage='worker_deploy';workerPossible=true;completed.workerDeployAttempted=true;command(['deploy']);completed.workerDeployed=true;
 stage='tail_start';tail=spawn('npx',['wrangler','tail','--config',config,'--format','json'],{stdio:['ignore',openSync(root+'raw-tail.json','w'),openSync(root+'raw-tail-errors.txt','w')]});
 tail.once('error',()=>{tailFailed=true;});
 await new Promise(r=>setTimeout(r,10000));if(tailFailed||tail.exitCode!==null)throw Error('Tail unavailable');
 completed.tailStarted=true;stage='driver';const d=spawnSync(process.execPath,[root+'driver.mjs','https://'+name+'.abrahammurciano.workers.dev/'+c.vars.FIXTURE_PREFIX],{encoding:'utf8',timeout:160000});if(d.status!==0||tailFailed)throw Error('Driver or tail failed');
 completed.driverCompleted=true;stage='tail_collect';await new Promise(r=>setTimeout(r,10000));tail.kill();if(tail.exitCode===null)await new Promise(r=>tail.once('exit',r));tail=null;if(tailFailed)throw Error('Tail failed');
 stage='cpu_validate';const s=spawnSync(process.execPath,[root+'sanitize-tail.mjs',root+'raw-tail.json'],{encoding:'utf8',timeout:10000});if(s.status!==0)throw Error('CPU evidence failed');
completed.cpuValidated=true;stage='complete';
}catch{failure=true;console.log(JSON.stringify({synthetic:true,failureCode:stage,completed}));}finally{
 if(tail)tail.kill();
 if(workerPossible)try{cleanup.workerAbsent=await absent('/workers/scripts/'+name);}catch{failure=true;}else cleanup.workerAbsent=true;
 if(id)try{cleanup.databaseAbsent=await absent('/d1/database/'+id);}catch{failure=true;}
 else cleanup.databaseAbsent=true;
 writeFileSync(root+'cleanup.json',JSON.stringify(cleanup));rmSync(root+'raw-tail.json',{force:true});rmSync(root+'raw-tail-errors.txt',{force:true});
 console.log(JSON.stringify({synthetic:true,pass:!failure,stage,completed,cleanup}));
}
if(failure||!cleanup.workerAbsent||!cleanup.databaseAbsent)process.exit(1);
