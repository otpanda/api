// Read-only Cloudflare account preflight for OTPanda. Creates, deploys and deletes NOTHING. Requests are GET/list calls plus two read-only POSTs:
// the GraphQL analytics query and the Workers Observability telemetry query (query bodies, no mutation). Fails closed (exit 2) on any missing permission or unreadable meter.
//   probe     token + read permissions (workers, d1, analytics, observability, workers.dev subdomain); lists what is missing
//   plan      stops unless subscriptions are readable and show no non-free Workers/D1 plan (no row = "free inferred", an API inference only)
//   orphans   checks the production database is listed and whether any scratch-named resource exists (coarse result only, deletes nothing)
//   readout   passes only if at least 30% of both daily free D1 limits remain (UTC day); prints no counts
// PRIVACY: this runs in public Actions logs, so output is only pass/fail and missing permission classes: never usage counts, resource names or ids, plan details or account metadata. No artifact is produced.
// Env: CLOUDFLARE_API_TOKEN, CLOUDFLARE_ACCOUNT_ID (pinned). Public docs name the GraphQL dataset d1AnalyticsAdaptiveGroups with sum{rowsRead rowsWritten}; the telemetry body is not verified, so probe may fail.
const A='a04834f19f0dfd5dc4eb47515d15478d',E=process.env,mode=process.argv[2];
const B=(E.CLOUDFLARE_API_TOKEN==='ci-test-fake-token'&&E.CF_API_BASE)||'https://api.cloudflare.com/client/v4/'; // override only with the fixed fake test token
const NAME=/^otpanda-seedsync-cpu-qualification-[0-9]+$/,PROD='626cd908-0951-49cf-92a2-9a54cbbb40a8',FREE={w:100000,r:5000000},FLOOR=0.3;
const fail=(m,c=2)=>{console.error('PREFLIGHT FAIL:',m);process.exit(c);};
if(E.CLOUDFLARE_ACCOUNT_ID!==A)fail('unexpected account');
if(!E.CLOUDFLARE_API_TOKEN)fail('CLOUDFLARE_API_TOKEN missing');
const H={authorization:'Bearer '+E.CLOUDFLARE_API_TOKEN,'content-type':'application/json'};
const call=async(m,p,body)=>{try{const r=await fetch(B+p,{method:m,headers:H,body:body&&JSON.stringify(body),signal:AbortSignal.timeout(20000)});let j={};try{j=await r.json();}catch{}return {ok:r.ok&&j.success!==false,status:r.status,j};}catch{return {ok:false,status:0,j:{}};}};
async function usage(){
 const d=new Date().toISOString().slice(0,10);
 const q={query:'query($a:String!,$d:Date!){viewer{accounts(filter:{accountTag:$a}){d1AnalyticsAdaptiveGroups(limit:1000,filter:{date_geq:$d,date_leq:$d}){sum{rowsRead rowsWritten}}}}}',variables:{a:A,d}};
 let r,j;try{r=await fetch(B+'graphql',{method:'POST',headers:H,body:JSON.stringify(q),signal:AbortSignal.timeout(20000)});j=await r.json();}catch{throw Error('analytics unreachable');}
 const g=j?.data?.viewer?.accounts?.[0]?.d1AnalyticsAdaptiveGroups;if(!r.ok||j.errors||!Array.isArray(g))throw Error('analytics unreadable (status '+r.status+')');
 return {r:g.reduce((a,x)=>a+Number(x.sum?.rowsRead||0),0),w:g.reduce((a,x)=>a+Number(x.sum?.rowsWritten||0),0),day:d};
}
try{
 if(mode==='probe'){
  const missing=[];
  const t=await call('GET','accounts/'+A+'/tokens/verify');const t2=t.ok?t:await call('GET','user/tokens/verify');
  if(!t2.ok||t2.j.result?.status!=='active')missing.push('token not active/verifiable');
  if(!(await call('GET','accounts/'+A+'/workers/scripts')).ok)missing.push('Workers Scripts read');
  if(!(await call('GET','accounts/'+A+'/d1/database?per_page=5')).ok)missing.push('D1 read');
  try{await usage();}catch{missing.push('Account Analytics read');}
  const now=Date.now();if(!(await call('POST','accounts/'+A+'/workers/observability/telemetry/query',{queryId:'preflight',view:'events',limit:1,timeframe:{from:now-60000,to:now},parameters:{filters:[{key:'$workers.scriptName',operation:'eq',type:'string',value:'otpanda-preflight-none'}]}})).ok)missing.push('Observability query');
  if(!(await call('GET','accounts/'+A+'/workers/subdomain')).ok)missing.push('workers.dev subdomain read');
  console.log(JSON.stringify({probe:missing.length?'FAIL':'pass',missingPermissionClasses:missing}));
  if(missing.length)fail('missing permission(s) above. No token is minted or widened.');
 }else if(mode==='plan'){
  const sub=await call('GET','accounts/'+A+'/subscriptions');if(!sub.ok)fail('plan unreadable: subscriptions API not available to this token, free-plan checkpoint cannot be established');
  const w=(sub.j.result??[]).map(x=>String(x.rate_plan?.public_name??'')+' '+String(x.rate_plan?.id??'')).filter(x=>/workers|d1/i.test(x));
  const paid=w.filter(x=>!/free/i.test(x));if(paid.length)fail('a non-free Workers/D1 plan is present: stop');
  console.log(JSON.stringify({plan:'pass'}));
 }else if(mode==='orphans'){
  const s=await call('GET','accounts/'+A+'/workers/scripts'),d=await call('GET','accounts/'+A+'/d1/database?per_page=100');
  if(!s.ok||!d.ok)fail('cannot list resources');
  if(!(d.j.result||[]).some(x=>x.uuid===PROD))fail('expected production database not listed: stop and investigate');
  const other=(s.j.result||[]).some(x=>NAME.test(x.id))||(d.j.result||[]).some(x=>NAME.test(x.name)&&x.uuid!==PROD);
  console.log(JSON.stringify({resources:other?'scratch-named-present':'pass'})); // coarse only: no names, counts or ids
 }else if(mode==='readout'){
  const u=await usage();
  if(FREE.w-u.w<FLOOR*FREE.w||FREE.r-u.r<FLOOR*FREE.r)fail('less than 30% of a daily free limit remains'); // no counts are printed; the meter values stay inside this process
  console.log(JSON.stringify({meter:'pass'}));
 }else fail('mode probe|plan|orphans|readout');
}catch(e){fail(e.message);}
