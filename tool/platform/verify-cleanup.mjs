// Read-only verification, token used only for these fixed Cloudflare list calls.
const name=process.env.QUALIFICATION_NAME,account=process.env.CLOUDFLARE_ACCOUNT_ID;
if(!/^otpanda-realtime-qualification-[0-9]+$/.test(name||''))throw Error('isolated name required');
if(account!=='a04834f19f0dfd5dc4eb47515d15478d')throw Error('unexpected account');
async function list(path){const r=await fetch('https://api.cloudflare.com/client/v4/accounts/'+account+'/'+path,{headers:{authorization:'Bearer '+process.env.CLOUDFLARE_API_TOKEN},signal:AbortSignal.timeout(20000)});const j=await r.json();if(!r.ok||!j.success||!Array.isArray(j.result))throw Error('Cleanup list unavailable: '+path);if((j.result_info?.total_pages??1)>1)throw Error('Cleanup list needs pagination: '+path);return j.result;}
const scripts=await list('workers/scripts'),databases=await list('d1/database?per_page=100'),namespaces=await list('workers/durable_objects/namespaces?per_page=1000');
const remaining={worker:scripts.some(x=>x.id===name),database:databases.some(x=>x.name===name),namespace:namespaces.some(x=>x.script===name)};
console.log(JSON.stringify({cleanupVerification:remaining}));if(Object.values(remaining).some(Boolean))throw Error('Temporary resource remains');
