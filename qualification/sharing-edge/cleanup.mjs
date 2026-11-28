// Independent recovery, no dependence on workload artifacts or runner memory.
// Only exact one-run names; never touches production or another run.
import{writeFileSync}from'node:fs';
const run=process.env.WORKLOAD_RUN_ID;if(!/^[0-9]{8,20}$/.test(run??''))throw Error('Numeric workload run ID required');
const account=process.env.CLOUDFLARE_ACCOUNT_ID;if(account!=='a04834f19f0dfd5dc4eb47515d15478d')throw Error('Account scope');
const name='otpanda-sharing-edge-'+run,base='https://api.cloudflare.com/client/v4/accounts/'+account,headers={Authorization:'Bearer '+process.env.CLOUDFLARE_API_TOKEN};
async function request(path,method='GET'){return fetch(base+path,{method,headers,signal:AbortSignal.timeout(20000)});}
async function remove(path){const initial=await request(path);if(initial.status===404)return;if(!initial.ok)throw Error('Initial state unavailable');const d=await request(path,'DELETE');if(!d.ok&&d.status!==404)throw Error('Delete unavailable');const v=await request(path);if(v.status!==404)throw Error('Absence unverified');}
// Discover by exact immutable name, bounded inventory, fail if incomplete.
let ids=[],complete=false;
for(let page=1;page<=10;page++){const r=await request('/d1/database?per_page=100&page='+page);const b=await r.json();if(!r.ok||!b.success||!Array.isArray(b.result))throw Error('Inventory unavailable');for(const x of b.result)if(x.name===name){if(!/^[a-f0-9-]{36}$/.test(x.uuid??''))throw Error('Bad ID');ids.push(x.uuid);}if(b.result.length<100){complete=true;break;}}
if(!complete||ids.length>1)throw Error('Ambiguous/incomplete inventory');
await remove('/workers/scripts/'+name);
for(const id of ids){const r=await request('/d1/database/'+id);if(r.status!==404){const b=await r.json();if(!r.ok||b.result?.name!==name)throw Error('Name mismatch');}await remove('/d1/database/'+id);}
// Repeat complete exact-name inventory to prove no database left, including a create race.
for(let page=1;page<=10;page++){const r=await request('/d1/database?per_page=100&page='+page);const b=await r.json();if(!r.ok||!b.success||!Array.isArray(b.result))throw Error('Final inventory unavailable');if(b.result.some(x=>x.name===name))throw Error('Resource still present');if(b.result.length<100){console.log(JSON.stringify({synthetic:true,workerAbsent:true,databaseAbsent:true}));writeFileSync('cleanup-independent.json',JSON.stringify({workerAbsent:true,databaseAbsent:true}));process.exit(0);}}
throw Error('Final inventory incomplete');
