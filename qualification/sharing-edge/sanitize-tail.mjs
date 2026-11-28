// Raw tail is private and never uploaded. Only allowlisted aggregates survive.
import{readFileSync,writeFileSync}from'node:fs';
const raw=readFileSync(process.argv[2],'utf8');let events;try{events=JSON.parse(raw);if(!Array.isArray(events))events=[events];}catch{events=[];let depth=0,start=0,string=false,esc=false;for(let i=0;i<raw.length;i++){const c=raw[i];if(string){if(esc)esc=false;else if(c==='\\')esc=true;else if(c==='"')string=false;continue;}if(c==='"')string=true;else if(c==='{'){if(depth++===0)start=i;}else if(c==='}'&&--depth===0)events.push(JSON.parse(raw.slice(start,i+1)));}}
const allowed=new Set(['setup','session','allow','deny','all','token','machine','revoke','revoked-machine']);const out=events.flatMap(e=>{let action;try{action=new URL(e.event?.request?.url).pathname.split('/').at(-1);}catch{return[];}if(!allowed.has(action))return[];return[{action,cpuMs:e.cpuTime,outcome:e.outcome,exceptions:e.exceptions?.length??0,truncated:e.truncated===true}];});
writeFileSync('qualification/sharing-edge/cpu.json',JSON.stringify(out,null,2));
if(out.length!==9||out.some(e=>!Number.isFinite(e.cpuMs)||e.outcome!=='ok'||e.exceptions||e.truncated))throw Error('Incomplete or unsuccessful CPU evidence');
// Setup is not product CPU qualification. Product requests must fit Free's10ms allowance.
if(out.some(e=>e.action!=='setup'&&e.cpuMs>10))throw Error('Free product CPU budget exceeded');
console.log(JSON.stringify({synthetic:true,samples:out.length,cpuEvidence:true}));
