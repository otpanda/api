// Local checks of tool/ci against a stub Cloudflare API (fixed fake token, no network). Run: node tool/ci/checks.mjs
import http from 'node:http';import {spawn} from 'node:child_process';import {readFileSync} from 'node:fs';
const A='a04834f19f0dfd5dc4eb47515d15478d',FAKE='ci-test-fake-token';let fails=0,mode={};const calls=[];
const srv=http.createServer((q,r)=>{q.resume();q.on('end',()=>{calls.push(q.method+' '+q.url);const j=(o,c=200)=>{r.writeHead(c,{'content-type':'application/json'});r.end(JSON.stringify(o));};
 if(q.method!=='GET'&&!/graphql|telemetry\/query/.test(q.url))return j({success:false},500);
 if(/tokens\/verify/.test(q.url))return j({success:true,result:{status:'active'}});
 if(/graphql/.test(q.url))return mode.noAnalytics?j({errors:[{message:'denied'}]}):j({data:{viewer:{accounts:[{d1AnalyticsAdaptiveGroups:[{sum:{rowsRead:mode.read??1000,rowsWritten:mode.write??200}},{sum:{rowsRead:10,rowsWritten:0}}]}]}}});
 if(/subscriptions/.test(q.url))return mode.subsDenied?j({success:false},403):j({success:true,result:mode.subs??[]});
 if(/telemetry/.test(q.url))return mode.noObs?j({success:false},403):j({success:true,result:{events:{events:[]}}});
 if(/workers\/scripts/.test(q.url))return mode.noWorkers?j({success:false},403):j({success:true,result:[{id:'otpanda-api'},{id:'otpanda-seedsync-cpu-qualification-5'}]});
 if(/d1\/database/.test(q.url))return j({success:true,result:[{name:'otpanda',uuid:'626cd908-0951-49cf-92a2-9a54cbbb40a8'},{name:'otpanda-seedsync-cpu-qualification-5',uuid:'u1'}]});
 return j({success:true,result:[]});});});
await new Promise(r=>srv.listen(0,r));const base='http://127.0.0.1:'+srv.address().port+'/';
const sh=(file,args,env={})=>new Promise(res=>{const c=spawn('node',[file,...args],{env:{PATH:process.env.PATH,CLOUDFLARE_API_TOKEN:FAKE,CLOUDFLARE_ACCOUNT_ID:A,CF_API_BASE:base,...env}});let o='',e='';c.stdout.on('data',d=>o+=d);c.stderr.on('data',d=>e+=d);c.on('close',s=>res({status:s,stdout:o,stderr:e}));});
const run=(a,env)=>sh('tool/ci/preflight.mjs',a,env);const t=(n,ok,x='')=>{console.log(ok?'PASS':'FAIL',n,ok?'':x);if(!ok)fails++;};
let r=await run(['probe']);t('probe ok',r.status===0&&/"probe":"pass"/.test(r.stdout),r.stderr);
for(const m of ['probe','plan','orphans','readout'])await run([m]);
t('only GET plus the two read-only POST paths (graphql, telemetry/query)',calls.every(c=>/^GET /.test(c)||/^POST \/graphql$/.test(c)||/^POST \/accounts\/[0-9a-f]+\/workers\/observability\/telemetry\/query$/.test(c)),calls.filter(c=>!/^GET /.test(c)).join());
for(const [k,m] of [['noAnalytics','Account Analytics'],['noObs','Observability'],['noWorkers','Workers Scripts']]){mode={[k]:true};r=await run(['probe']);t('probe missing '+k+' -> exit 2 naming it',r.status===2&&r.stdout.includes(m),r.stdout);}
mode={};r=await run(['probe'],{CLOUDFLARE_ACCOUNT_ID:'x'});t('wrong account refused',r.status===2);
r=await run(['probe'],{CF_API_BASE:'http://127.0.0.1:1/'});t('network failure -> clean exit 2',r.status===2&&!/ERR_INVALID_ARG/.test(r.stderr),r.stderr);
r=await run(['plan']);t('plan: no workers subscription -> pass',r.status===0&&r.stdout.trim()==='{"plan":"pass"}');
mode={subs:[{rate_plan:{public_name:'Workers Free',id:'workers_free'}}]};r=await run(['plan']);t('plan: Workers Free listed -> pass, plan name not printed',r.status===0&&r.stdout.trim()==='{"plan":"pass"}');
mode={subs:[{rate_plan:{public_name:'Workers Paid',id:'workers_paid'}}]};r=await run(['plan']);t('plan: paid -> stop',r.status===2);
mode={subsDenied:true};r=await run(['plan']);t('plan: unreadable -> stop',r.status===2);
mode={};r=await run(['orphans']);t('orphans: coarse output, no names/ids/counts, nothing deleted',r.status===0&&r.stdout.trim()==='{"resources":"scratch-named-present"}'&&!calls.some(c=>/^DELETE/.test(c)),r.stdout);
r=await run(['readout']);t('readout: pass prints no counts',r.status===0&&r.stdout.trim()==='{"meter":"pass"}',r.stdout);
mode={write:75000};r=await run(['readout']);t('readout: under 30% remaining -> exit 2, no numbers in output',r.status===2&&!/\d{3}/.test(r.stdout+r.stderr),r.stderr);
mode={noAnalytics:true};r=await run(['readout']);t('readout: analytics unreadable -> exit 2',r.status===2);
mode={};
// privacy: nothing the stub knows (account id, prod db id, scratch name, usage numbers) may appear in any mode's output
{const secrets=[A,'626cd908','qualification-5','99800','4998990','otpanda-api','200','1000'];
 for(const m of ['probe','plan','orphans','readout']){const o=await run([m]);t('privacy: '+m+' output holds no account id, resource names or counts',!secrets.some(x=>(o.stdout+o.stderr).includes(x)),o.stdout+o.stderr);}
 mode={noWorkers:true};const o=await run(['probe']);t('privacy: failing probe names only permission classes',!secrets.some(x=>(o.stdout+o.stderr).includes(x))&&/Workers Scripts read/.test(o.stdout),o.stdout+o.stderr);mode={};}
srv.close();
const sha='a'.repeat(40),ok={IN_CONFIRM:'read-only-preflight',IN_SHA:sha,GITHUB_SHA:sha};
r=await sh('tool/ci/inputs.mjs',[],ok);t('inputs ok',r.status===0);
for(const [n,e] of [['bad confirm',{IN_CONFIRM:'yes'}],['sha mismatch',{IN_SHA:'b'.repeat(40)}],['short sha',{IN_SHA:'abc',GITHUB_SHA:'abc'}]]){r=await sh('tool/ci/inputs.mjs',[],{...ok,...e});t('inputs reject: '+n,r.status===1);}
{const y=readFileSync('.github/workflows/cloudflare-preflight.yml','utf8'),head=y.split('\njobs:')[0],steps=y.split(/\n {6}- /).slice(1);
 t('dispatch only, default-or-exact-qualification-branch gate',/\non:\n {2}workflow_dispatch:/.test(y)&&!/\n {2}(push|pull_request|pull_request_target|schedule|workflow_run):/.test(y)&&y.includes("|| github.ref == 'refs/heads/qualification/sharing-readonly-inspection-v1'")&&/if: github\.ref == format\('refs\/heads\/\{0\}', github\.event\.repository\.default_branch\)/.test(y));
 const jobEnv=y.split('\n    env:\n')[1].split('\n    steps:')[0];t('no secret in workflow/job env',!/secrets\./.test(head)&&!/secrets\./.test(jobEnv));
 t('token only in each Cloudflare step\'s own env',steps.filter(x=>/secrets\./.test(x)).every(x=>/\n {8}env:\n {10}CLOUDFLARE_API_TOKEN: \$\{\{ secrets\.CLOUDFLARE_API_TOKEN \}\}/.test(x))&&steps.filter(x=>/secrets\./.test(x)).length===5);
 t('uses pinned to 40-hex',[...y.matchAll(/uses: (\S+)/g)].every(m=>/@[0-9a-f]{40}$/.test(m[1])));
 t('no create/deploy/delete/npm/wrangler/upload anywhere',!/wrangler|npm |upload-artifact|run\.mjs|DELETE|--method|curl /.test(y));
 t('no input interpolation inside run blocks',![...y.matchAll(/run: [^\n]*/g)].some(m=>/\$\{\{/.test(m[0]))); }
process.exit(fails?1:0);
