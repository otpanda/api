// Remote upgrade qualification driver. Usage: node driver.mjs <base-url-with-prefix> <phase: seed-legacy|verify>. One POST per phase, never replayed.
// The workflow applies the pre-0052 migrations, runs phase seed-legacy, applies 0052 and 0053, then runs phase verify. Row counts accumulate in a state file so the shared ceiling covers both phases.
import {readFileSync,writeFileSync,existsSync} from 'node:fs';
import {CEILING,MIGRATION_ALLOWANCE,PER_REQUEST_CAP,mayStartNext,IN_FLIGHT_OVERSHOOT} from '../seed-sync/budget.mjs';
// Charged up front for the final `wrangler d1 migrations apply` of 0052 and 0053 only (local measured 4 and 1 rows); the driver cannot see the real count.
const UPGRADE_ALLOWANCE={writes:200,reads:2000};
const [,,base,phase]=process.argv,STATE='qualification/seed-sync-upgrade/state.json',OUT='qualification/seed-sync-upgrade/seed-sync-upgrade-result.json';
if(!['seed-legacy','verify'].includes(phase))throw Error('phase required');
const state=existsSync(STATE)?JSON.parse(readFileSync(STATE,'utf8')):{cum:{writes:MIGRATION_ALLOWANCE.writes,reads:MIGRATION_ALLOWANCE.reads},phases:{}};
if(phase==='verify'&&!state.upgradeCharged){state.cum.writes+=UPGRADE_ALLOWANCE.writes;state.cum.reads+=UPGRADE_ALLOWANCE.reads;state.upgradeCharged=true;}
if(phase==='verify'&&!state.phases['seed-legacy']?.pass)throw Error('verify refused: legacy seeding did not pass');
let ready=false;
for(let n=0;n<30;n++){try{const r=await fetch(base+'/ready');ready=r.status===200&&(await r.json()).ready===true;}catch{}if(ready)break;await new Promise(r=>setTimeout(r,2000));}
if(!ready)throw Error('Synthetic Worker readiness timed out');
const save=pass=>writeFileSync(OUT,JSON.stringify({synthetic:true,pass,metering:{ceiling:CEILING,perRequestCap:PER_REQUEST_CAP,inFlightOvershootBound:IN_FLIGHT_OVERSHOOT,cumulative:state.cum},phases:state.phases},null,2));
if(!mayStartNext(state.cum)){console.log('STOP before '+phase+': row ceiling');state.phases[phase]={skipped:'row ceiling'};save(false);writeFileSync(STATE,JSON.stringify(state));process.exit(1);}
const res=await fetch(base+'/'+phase,{method:'POST'}),text=await res.text();let data;
try{data=JSON.parse(text);}catch{state.phases[phase]={httpStatus:res.status,pass:false};save(false);writeFileSync(STATE,JSON.stringify(state));console.log('FATAL HTTP '+res.status);process.exit(1);}
state.phases[phase]={httpStatus:res.status,...data};
if(!Number.isFinite(data.totalRowsWritten)||!Number.isFinite(data.totalRowsRead)){console.log('STOP: no row counts reported');save(false);writeFileSync(STATE,JSON.stringify(state));process.exit(1);}
state.cum.writes+=data.totalRowsWritten;state.cum.reads+=data.totalRowsRead;
console.log(phase+': HTTP '+res.status+' pass='+data.pass+' rowsWritten='+data.totalRowsWritten+' rowsRead='+data.totalRowsRead+' queries='+data.totalQueries+' cumulative '+state.cum.writes+'/'+CEILING.writes+' written, '+state.cum.reads+'/'+CEILING.reads+' read');
for(const s of data.steps??[])console.log(s.pass?'PASS':'FAIL',s.name.slice(0,90),'queries='+s.queries,'rowsWritten='+s.rowsWritten,s.error??'');
if(data.fatal)console.log('FATAL',data.fatal);
const ok=res.status===200&&data.pass===true;save(ok&&phase==='verify');writeFileSync(STATE,JSON.stringify(state));
if(!ok){console.error('Seed-sync upgrade qualification failed in phase '+phase);process.exit(1);}
