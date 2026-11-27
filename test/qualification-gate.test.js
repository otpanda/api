import test from 'node:test';import assert from 'node:assert/strict';import {spawnSync} from 'node:child_process';
import {mayStartNext,CEILING,PER_REQUEST_CAP,MIGRATION_ALLOWANCE} from '../qualification/seed-sync/budget.mjs';import {runChecks} from '../qualification/seed-sync/checks.js';
const SHA='a'.repeat(40),ACCT='a04834f19f0dfd5dc4eb47515d15478d';
// Closed environment: only these variables reach the gate. The run is refused near the UTC daily reset, so those cases skip rather than flake.
const nowIso=()=>new Date().toISOString().replace(/\.\d+Z$/,'Z');
const nearReset=()=>{const n=new Date(),next=Date.UTC(n.getUTCFullYear(),n.getUTCMonth(),n.getUTCDate()+1);return next-n.getTime()<12*60*1000;};
const gate=(over={})=>{const env={PATH:process.env.PATH,GITHUB_EVENT_NAME:'workflow_dispatch',GITHUB_RUN_ATTEMPT:'1',CLOUDFLARE_ACCOUNT_ID:ACCT,GATE_ACCOUNT_ID:ACCT,GITHUB_SHA:SHA,GATE_COMMIT:SHA,GATE_PLAN:'workers-free',GATE_OBSERVED_AT:nowIso(),GATE_DAILY_WRITES:'15610',GATE_DAILY_READS:'227840',GATE_DB_COUNT:'1',...over};
 for(const k of Object.keys(env))if(env[k]===undefined)delete env[k];
 const r=spawnSync(process.execPath,['qualification/plan-gate.mjs'],{env,encoding:'utf8'});return{code:r.status,out:r.stdout+r.stderr};};
test('gate opens for fresh, bound, within-budget input (verified observation numbers)',{skip:nearReset()},()=>{const r=gate();assert.equal(r.code,0,r.out);assert.match(r.out,/gate open/);});
const closed=[['wrong plan',{GATE_PLAN:'workers-paid'},/plan/],['wrong account',{GATE_ACCOUNT_ID:'b'.repeat(32)},/account/],['wrong commit',{GATE_COMMIT:'b'.repeat(40)},/commit/],['stale',{GATE_OBSERVED_AT:'2020-01-01T00:00:00Z'},/older|different UTC day/],['future',{GATE_OBSERVED_AT:'2999-01-01T00:00:00Z'},/future/],['re-run',{GITHUB_RUN_ATTEMPT:'2'},/re-runs/],['push event',{GITHUB_EVENT_NAME:'push'},/dispatch/],['writes over headroom',{GATE_DAILY_WRITES:'60000'},/rows written/],['reads over headroom',{GATE_DAILY_READS:'2600000'},/rows read/],['database count',{GATE_DB_COUNT:'8'},/database count/],['missing field',{GATE_DAILY_READS:undefined},/GATE_DAILY_READS/],['malformed time',{GATE_OBSERVED_AT:'yesterday'},/ISO UTC/]];
for(const [name,over,re] of closed)test('gate closes: '+name,()=>{const r=gate(over);assert.equal(r.code,1,r.out);assert.match(r.out,re);assert.match(r.out,/No resources were created/);});
test('gate: no inputs at all is closed',()=>{const r=spawnSync(process.execPath,['qualification/plan-gate.mjs'],{env:{PATH:process.env.PATH},encoding:'utf8'});assert.equal(r.status,1);});
test('metering: stop-before-next once a full-cap request could cross the ceiling; migration allowance counts from the start',()=>{
 const cum={...MIGRATION_ALLOWANCE};assert.equal(mayStartNext(cum),true);
 assert.equal(mayStartNext({writes:CEILING.writes-PER_REQUEST_CAP.writes,reads:0}),true);assert.equal(mayStartNext({writes:CEILING.writes-PER_REQUEST_CAP.writes+1,reads:0}),false);
 assert.equal(mayStartNext({writes:0,reads:CEILING.reads-PER_REQUEST_CAP.reads+1}),false);assert.ok(MIGRATION_ALLOWANCE.writes<CEILING.writes&&MIGRATION_ALLOWANCE.reads<CEILING.reads);});
test('metering: a Worker request stops issuing statements once it passes its per-request row cap',async()=>{
 let calls=0;const meta={rows_written:PER_REQUEST_CAP.writes,rows_read:0},res={meta,results:[]};
 const stmt={bind(){return stmt;},run:async()=>{calls++;return res;},all:async()=>{calls++;return res;},first:async()=>{calls++;return null;},raw:async()=>{calls++;return[];}};
 const db={prepare:()=>stmt,batch:async s=>{calls++;return s.map(()=>res);}};
 await assert.rejects(()=>runChecks(db,'c13'),/per-request row cap/);const before=calls;assert.ok(before<=3,'no statements after the cap');});
