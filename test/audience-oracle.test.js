// Causal audience oracle (reviewer evidence). Requires tree with migrations 0001-0067 and test/sqlite-helper.js at /tmp/r/t1 (path hardcoded in import; edit to ../test/sqlite-helper.js if placed in test/). Run: node --test test/zz-audience-oracle.test.js (node:sqlite).
// Executed: 150 seeds x 80 steps = 6932 applied ops per variant. NEW (with 0067): 0 misses. OLD control (skip 0067, 0065 triggers): 77 misses.
import test from 'node:test';import assert from 'node:assert/strict';
import {database} from './sqlite-helper.js';
function rng(seed){let s=seed>>>0;return()=>{s=(s*1664525+1013904223)>>>0;return s/2**32;};}
function world(skip){const db=database(':memory:',{skip}),s=db.sqlite;
 s.exec("INSERT INTO accounts VALUES('owner',1),('r1',1),('r2',1);INSERT INTO services(service_id,name)VALUES('sv','S');");
 const E=[];for(let i=0;i<6;i++){E.push('o'+i);s.prepare('INSERT INTO entries(entry_id,owner_id,service_id,label,created_at)VALUES(?,?,?,?,?)').run('o'+i,'owner','sv','L',1);}
 for(let i=0;i<3;i++){E.push('p'+i);s.prepare('INSERT INTO entries(entry_id,owner_id,service_id,label,created_at)VALUES(?,?,?,?,?)').run('p'+i,'r1','sv','L',1);}
 return {db,s,E};}
const revs=(s)=>new Map(s.prepare('SELECT entry_id,mutation_revision m FROM entries').all().map(r=>[r.entry_id,r.m]));
function audience(s,E){ // entry -> sorted token ids that can read it
 const out=new Map();for(const e of E)out.set(e,[]);
 const prof=s.prepare('SELECT * FROM machine_profiles WHERE revoked_at IS NULL').all();
 for(const p of prof){const toks=s.prepare('SELECT token_id FROM machine_tokens WHERE profile_id=? AND revoked_at IS NULL').all(p.profile_id).map(t=>t.token_id);
  if(!toks.length)continue;const sel=new Set(s.prepare('SELECT entry_id FROM machine_profile_entries WHERE profile_id=?').all(p.profile_id).map(r=>r.entry_id));
  for(const e of E){const owner=s.prepare('SELECT owner_id FROM entries WHERE entry_id=?').get(e).owner_id;
   let reach=owner===p.creator_id;
   if(!reach){const g=s.prepare('SELECT * FROM access_grants WHERE owner_id=? AND grantee_id=? AND revoked_at IS NULL AND can_delegate=1').get(owner,p.creator_id);
    if(g){const inl=s.prepare('SELECT 1 x FROM access_grant_entries WHERE grant_id=? AND entry_id=?').get(g.grant_id,e);reach=g.mode==='all'||(g.mode==='allow'&&!!inl)||(g.mode==='deny'&&!inl);}}
   if(!reach)continue;const inS=sel.has(e);const cov=p.mode==='all'||(p.mode==='allow'&&inS)||(p.mode==='deny'&&!inS);
   if(cov)out.get(e).push(...toks);}}
 for(const e of E)out.set(e,out.get(e).sort().join(','));return out;}
function run(skip,seeds,steps){let fails=[],ops=0;
 for(let seed=1;seed<=seeds;seed++){const w=world(skip),{s,E}=w,R=rng(seed*7919),pick=a=>a[Math.floor(R()*a.length)];
  const acc=['owner','r1','r2'];let pid=0,tid=0,gid=0;
  const profs=()=>s.prepare('SELECT profile_id FROM machine_profiles').all().map(r=>r.profile_id);
  const toks=()=>s.prepare('SELECT token_id FROM machine_tokens').all().map(r=>r.token_id);
  const grants=()=>s.prepare('SELECT grant_id FROM access_grants').all().map(r=>r.grant_id);
  for(let i=0;i<steps;i++){
   const kinds=['pins','pupd','pdel','sins','sdel','supd','tins','tupd','tdel','gins','gupd','gdel','geins','gedel'];
   const k=pick(kinds);const P=profs(),T=toks(),G=grants();const before=revs(s),aud=audience(s,E);let sql,args=[];
   try{
    if(k==='pins'){sql='INSERT INTO machine_profiles VALUES(?,?,?,?,1,NULL)';args=['P'+(++pid),pick(acc),'n',pick(['all','allow','deny'])];}
    else if(k==='pupd'&&P.length){const which=pick(['mode','revoked','creator','unrevoke']);const id=pick(P);
      if(which==='mode'){sql='UPDATE machine_profiles SET mode=? WHERE profile_id=?';args=[pick(['all','allow','deny']),id];}
      else if(which==='revoked'){sql='UPDATE machine_profiles SET revoked_at=5 WHERE profile_id=?';args=[id];}
      else if(which==='unrevoke'){sql='UPDATE machine_profiles SET revoked_at=NULL WHERE profile_id=?';args=[id];}
      else{sql='UPDATE machine_profiles SET creator_id=? WHERE profile_id=?';args=[pick(acc),id];}}
    else if(k==='pdel'&&P.length){sql='DELETE FROM machine_profiles WHERE profile_id=?';args=[pick(P)];}
    else if(k==='sins'&&P.length){sql='INSERT OR IGNORE INTO machine_profile_entries VALUES(?,?)';args=[pick(P),pick(E)];}
    else if(k==='sdel'&&P.length){sql='DELETE FROM machine_profile_entries WHERE profile_id=? AND entry_id=?';args=[pick(P),pick(E)];}
    else if(k==='supd'&&P.length){sql='UPDATE OR IGNORE machine_profile_entries SET entry_id=? WHERE profile_id=? AND entry_id=?';args=[pick(E),pick(P),pick(E)];}
    else if(k==='tins'&&P.length){sql="INSERT INTO machine_tokens VALUES(?,zeroblob(32),?,1,NULL,NULL)";args=['T'+(++tid),pick(P)];}
    else if(k==='tupd'&&T.length){const which=pick(['revoke','unrevoke','move']);const id=pick(T);
      if(which==='revoke'){sql='UPDATE machine_tokens SET revoked_at=9 WHERE token_id=?';args=[id];}
      else if(which==='unrevoke'){sql='UPDATE machine_tokens SET revoked_at=NULL WHERE token_id=?';args=[id];}
      else if(P.length){sql='UPDATE machine_tokens SET profile_id=? WHERE token_id=?';args=[pick(P),id];}}
    else if(k==='tdel'&&T.length){sql='DELETE FROM machine_tokens WHERE token_id=?';args=[pick(T)];}
    else if(k==='gins'){sql='INSERT OR IGNORE INTO access_grants(grant_id,owner_id,grantee_id,mode,can_delegate,created_at,granted_at,revoked_at)VALUES(?,?,?,?,?,1,1,NULL)';const o=pick(['owner','r1']),g=pick(acc.filter(a=>a!==o));args=['G'+(++gid),o,g,pick(['all','allow','deny']),pick([0,1])];}
    else if(k==='gupd'&&G.length){const which=pick(['mode','deleg','revoke','unrevoke']);const id=pick(G);
      if(which==='mode'){sql='UPDATE access_grants SET mode=? WHERE grant_id=?';args=[pick(['all','allow','deny']),id];}
      else if(which==='deleg'){sql='UPDATE access_grants SET can_delegate=? WHERE grant_id=?';args=[pick([0,1]),id];}
      else if(which==='revoke'){sql='UPDATE access_grants SET revoked_at=7 WHERE grant_id=?';args=[id];}
      else{sql='UPDATE access_grants SET revoked_at=NULL WHERE grant_id=?';args=[id];}}
    else if(k==='gdel'&&G.length){sql='DELETE FROM access_grants WHERE grant_id=?';args=[pick(G)];}
    else if(k==='geins'&&G.length){const id=pick(G);const o=s.prepare('SELECT owner_id FROM access_grants WHERE grant_id=?').get(id).owner_id;const es=E.filter(e=>(o==='owner'?e[0]==='o':e[0]==='p'));sql='INSERT OR IGNORE INTO access_grant_entries VALUES(?,?)';args=[id,pick(es)];}
    else if(k==='gedel'&&G.length){sql='DELETE FROM access_grant_entries WHERE grant_id=? AND entry_id=?';args=[pick(G),pick(E)];}
    if(!sql)continue;s.prepare(sql).run(...args);ops++;
   }catch(e){if(!/constraint|UNIQUE|CHECK|FOREIGN/i.test(String(e)))throw e;continue;}
   const after=revs(s),aud2=audience(s,E);
   for(const e of E){if(aud.get(e)!==aud2.get(e)&&after.get(e)===before.get(e))fails.push({seed,i,k,sql,args,e,before:aud.get(e),after:aud2.get(e)});}
  }
  s.close();}
 return {fails,ops};}
test('oracle fuzz',()=>{
 const neu=run([],150,80);assert.equal(neu.fails.length,0);console.log('NEW ops',neu.ops,'fails',neu.fails.length,JSON.stringify(neu.fails.slice(0,3)));
 const old=run(['0067_machine_audience_scope.sql'],150,80);assert.ok(old.fails.length>0);console.log('OLD ops',old.ops,'fails',old.fails.length,JSON.stringify(old.fails.slice(0,3)));
});
