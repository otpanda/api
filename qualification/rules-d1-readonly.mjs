// STAGED ONLY. Three read operations, no automatic follow-on execution.
import assert from 'node:assert/strict';
import {writeFileSync} from 'node:fs';
const ACCOUNT='a04834f19f0dfd5dc4eb47515d15478d',PROD='626cd908-0951-49cf-92a2-9a54cbbb40a8',ROOT='https://api.cloudflare.com/client/v4';
export const USAGE_QUERY='query($a:String!,$d:Date!){viewer{accounts(filter:{accountTag:$a}){d1AnalyticsAdaptiveGroups(limit:1000,filter:{date_geq:$d,date_leq:$d}){sum{rowsRead rowsWritten}}}}}';
export async function preflight(e,request=fetch,now=Date.now()){
 assert.equal(e.GITHUB_EVENT_NAME,'workflow_dispatch');assert.equal(e.GITHUB_RUN_ATTEMPT,'1');assert.match(e.GITHUB_SHA??'',/^[a-f0-9]{40}$/);assert.equal(e.REVIEWED_SHA,e.GITHUB_SHA);assert.equal(e.CONFIRM,'readonly-d1-permissions');assert.equal(e.CLOUDFLARE_ACCOUNT_ID,ACCOUNT);assert(e.CLOUDFLARE_API_TOKEN);
 const day=new Date(now).toISOString().slice(0,10),result={sha:e.GITHUB_SHA,readonly:true,subscriptions:false,usage:false,inventory:false,productionPresent:false,passed:false};
 const operations=[['subscriptions',ROOT+'/accounts/'+ACCOUNT+'/subscriptions'],['usage',ROOT+'/graphql',{query:USAGE_QUERY,variables:{a:ACCOUNT,d:day}}],['inventory',ROOT+'/accounts/'+ACCOUNT+'/d1/database?per_page=100']];
 for(const [name,url,body]of operations){
  try{const r=await request(url,{method:body?'POST':'GET',headers:{Authorization:'Bearer '+e.CLOUDFLARE_API_TOKEN,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(20000)});const j=await r.json();assert(r.ok);
   if(name==='subscriptions'){assert(j.success&&Array.isArray(j.result));result.subscriptions=true;}
   if(name==='usage'){assert(!j.errors);const a=j.data?.viewer?.accounts;assert(Array.isArray(a)&&a.length===1);const g=a[0]?.d1AnalyticsAdaptiveGroups;assert(Array.isArray(g)&&g.length<1000);for(const x of g){assert(Number.isSafeInteger(x.sum?.rowsRead)&&x.sum.rowsRead>=0);assert(Number.isSafeInteger(x.sum?.rowsWritten)&&x.sum.rowsWritten>=0);}result.usage=true;}
   if(name==='inventory'){assert(j.success&&Array.isArray(j.result)&&j.result_info?.total_count===j.result.length);result.inventory=true;result.productionPresent=j.result.some(x=>x.uuid===PROD);}
  }catch{/* Booleans only. No response bodies, counter values or credential output. */}
 }
 result.passed=result.subscriptions&&result.usage&&result.inventory&&result.productionPresent;return result;
}
if(process.argv[1]?.endsWith('rules-d1-readonly.mjs')){let result;try{result=await preflight(process.env);}catch{result={readonly:true,passed:false,invalidGate:true};}writeFileSync('qualification/rules-d1-readonly-result.json',JSON.stringify(result,null,2));console.log(JSON.stringify(result));if(!result.passed)process.exitCode=1;}
