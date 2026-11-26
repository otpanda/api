import{readFileSync}from'node:fs';
const fixture=JSON.parse(readFileSync(new URL('./fixture.json',import.meta.url),'utf8'));
import {writeFileSync}from'node:fs';
import assert from'node:assert/strict';
const results=[],base=process.argv[2];
// Cold batch first, then first ordinary session and warm batch on same isolate.
for(const kind of ['batch','future30','future60','session','future30','future60',...Array(4).fill('batch')]){
 const q=new URLSearchParams({window:'600'});if(kind==='future30')q.set('from','30');if(kind==='future60')q.set('from','60');for(const id of fixture.ids.slice(0,3))q.append('entry',id);
 const response=await fetch(base+(kind==='session'?'/v1/manage/session':'/v1/manage/totp-codes?'+q),{headers:{Authorization:'Bearer '+fixture.access}});
 const text=await response.text();let data;try{data=JSON.parse(text);}catch{throw Error('Non-JSON HTTP '+response.status);}
 assert.equal(response.status,200);
 const r={kind,requestId:data.requestId,status:data.status,d1Queries:data.queryCount,wallMs:data.wallMs,totalCodes:data.body.totalCodes};results.push(r);console.log(JSON.stringify(r));await new Promise(resolve=>setTimeout(resolve,1000));
}
writeFileSync('qualification/batch-result.json',JSON.stringify({scope:'Cold encrypted TOTP batch first, first ordinary session second, warm batch repeat third. Wall stage durations are not CPU. Tail request IDs correlate actual CPU.',results},null,2));
