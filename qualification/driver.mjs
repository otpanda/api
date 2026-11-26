import{readFileSync}from'node:fs';
const fixture=JSON.parse(readFileSync(new URL('./fixture.json',import.meta.url),'utf8'));
import {writeFileSync}from'node:fs';
import assert from'node:assert/strict';
const results=[],base=process.argv[2];
for(let round=0;round<3;round++){
 for(const window of[600,60])for(const group of[0,1]){
  const q=new URLSearchParams({window:String(window)});
  for(const id of fixture.ids.slice(group,group+1))q.append('entry',id);
  const response=await fetch(base+'/v1/manage/totp-codes?'+q,{headers:{Authorization:'Bearer '+fixture.access}});
  const text=await response.text();let data;try{data=JSON.parse(text);}catch{writeFileSync('qualification/non-json-result.json',JSON.stringify({status:response.status,body:text,window,round,group},null,2));throw Error('Non-JSON Worker response HTTP '+response.status);}
  assert.equal(response.status,200);assert.equal(data.body.entries.length,1);
  const r={requestId:data.requestId,round,window,group,status:data.status,d1Queries:data.queryCount,wallMs:data.wallMs,totalCodes:data.body.totalCodes,serverNow:data.body.serverNow,coverageUntil:data.body.coverageUntil};results.push(r);console.log(JSON.stringify(r));await new Promise(resolve=>setTimeout(resolve,400));writeFileSync('qualification/partial-result.json',JSON.stringify(results,null,2));
 }
}
writeFileSync('qualification/batch-result.json',JSON.stringify({policy:{entryCap:1,budget:32,minPeriod:20,maxPeriod:86400,maxWindow:600,minUsefulWindow:60,ratePerMinute:24,minRemainingMs:1000},scope:'Synthetic isolated actual runtime. Values are test policy, not chosen production defaults. wallMs is not CPU. CPU comes only from correlated Worker tail events.',results},null,2));
