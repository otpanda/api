// Read-only metadata/schema inspection. Fixed endpoints and fixed SQL only.
// Never logs response bodies, secret values, personal rows or arbitrary remote strings.
import {createHash} from 'node:crypto';
import {readFileSync,readdirSync} from 'node:fs';
const A='a04834f19f0dfd5dc4eb47515d15478d',D='626cd908-0951-49cf-92a2-9a54cbbb40a8',S='otpanda-api';
const token=process.env.CLOUDFLARE_API_TOKEN;
if(!token||process.env.CLOUDFLARE_ACCOUNT_ID!==A)throw Error('inspection configuration unavailable');
const base='https://api.cloudflare.com/client/v4/accounts/'+A+'/';
const sha=s=>createHash('sha256').update(s).digest('hex');
let failed=false;
async function call(label,path,sql){
 try{const r=await fetch(base+path,{method:sql?'POST':'GET',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},...(sql?{body:JSON.stringify({sql})}:{}),signal:AbortSignal.timeout(20000)});let j;try{j=await r.json();}catch{}
 if(!r.ok||j?.success!==true){failed=true;console.log(JSON.stringify({check:label,status:'unavailable',http:r.status}));return;}
 return j.result;
 }catch{failed=true;console.log(JSON.stringify({check:label,status:'unreachable'}));}
}
const settings=await call('settings','workers/scripts/'+S+'/settings');
if(settings&&!Array.isArray(settings.bindings)){failed=true;console.log(JSON.stringify({check:'settings',status:'unverifiable'}));}
if(Array.isArray(settings?.bindings)){const expected=['DB','IDENTITY_ADDRESS_LIMIT','IDENTITY_AUTH_GLOBAL_LIMIT','IDENTITY_READ_GLOBAL_LIMIT','REALTIME_HUB','SHARING_ENABLED','CONTEXT_DIGEST_SECRET','CONTEXT_DIGEST_KEYRING','CONTEXT_RETENTION_DAYS'];
 if(['DB','IDENTITY_ADDRESS_LIMIT','IDENTITY_AUTH_GLOBAL_LIMIT','IDENTITY_READ_GLOBAL_LIMIT'].some(name=>!settings.bindings.some(b=>b.name===name)))failed=true;
 console.log(JSON.stringify({check:'settings',status:'read',bindings:expected.map(name=>{const b=settings.bindings?.find(b=>b.name===name);return{name,present:!!b,type:['d1','ratelimit','durable_object_namespace','plain_text','secret_text'].includes(b?.type)?b.type:'other',...(b?.type==='ratelimit'?{limit:Number.isSafeInteger(b.simple?.limit)?b.simple.limit:null,period:Number.isSafeInteger(b.simple?.period)?b.simple.period:null}:{}),...(name==='DB'&&b?{expectedDatabase:b.id===D}:{}),...(name==='SHARING_ENABLED'&&b?.type==='plain_text'?{exactOn:b.text==='1'}:{})};})}));}
const UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
for(const kind of ['deployments','versions']){const x=await call(kind,'workers/scripts/'+S+'/'+kind);if(!x)continue;
 const list=kind==='versions'?x.items:x.deployments;
 const valid=Array.isArray(list)&&list.length>0&&list.every(v=>kind==='versions'?UUID.test(v.id):UUID.test(v.id)&&Array.isArray(v.versions)&&v.versions.length>0&&v.versions.every(z=>UUID.test(z.version_id)&&Number.isFinite(z.percentage)&&z.percentage>0&&z.percentage<=100)&&Math.abs(v.versions.reduce((a,z)=>a+z.percentage,0)-100)<0.001);
 if(!valid){failed=true;console.log(JSON.stringify({check:kind,status:'unverifiable'}));continue;}
 console.log(JSON.stringify({check:kind,status:'read',items:list.map(v=>kind==='versions'?{versionId:v.id}:{deploymentId:v.id,versions:v.versions.map(z=>({versionId:z.version_id,percentage:z.percentage}))})}));
}
const db=await call('database','d1/database/'+D);if(db)console.log(JSON.stringify({check:'database',status:'read',expectedDatabase:db.uuid===D}));
const schema=await call('schema','d1/database/'+D+'/query',"SELECT type,name,tbl_name,sql FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name");
const expectedSchema=JSON.parse(readFileSync('tool/ci/sharing-schema-expected.json','utf8'));
const norm=x=>x.replace(/[\s`"\[\]]+/g,'').toLowerCase().replace(/;$/,'');
if(schema){const rows=schema[0]?.results;if(!Array.isArray(rows)||rows.some(r=>typeof r.name!=='string'||typeof r.type!=='string'||(r.sql!==null&&typeof r.sql!=='string'))){failed=true;console.log(JSON.stringify({check:'schema',status:'unverifiable'}));}else{
 const objects=expectedSchema.objects.map(e=>{const r=rows.find(r=>r.name===e.name&&r.type===e.type);return{name:e.name,type:e.type,state:!r?'absent':typeof r.sql!=='string'?'unknown':norm(r.sql)===norm(e.sql)?'matches':'differs'};});
 if(objects.some(o=>o.state!=='matches'))failed=true;
 console.log(JSON.stringify({check:'schema',status:objects.every(o=>o.state==='matches')?'matches':'requires-review',definitionHash:sha(JSON.stringify(rows)),objects}));}}
const columns=await call('columns','d1/database/'+D+'/query',"SELECT m.name AS table_name,p.name,p.type,p.[notnull],p.dflt_value,p.pk FROM sqlite_schema m JOIN pragma_table_info(m.name) p WHERE m.type IN ('table','view') ORDER BY m.name,p.cid");
if(columns){const rows=columns[0]?.results;const valid=Array.isArray(rows)&&rows.every(r=>typeof r.table_name==='string'&&typeof r.name==='string'&&typeof r.type==='string'&&Number.isInteger(r.notnull)&&Number.isInteger(r.pk));
 if(!valid){failed=true;console.log(JSON.stringify({check:'columns',status:'unverifiable'}));}else{const checks=expectedSchema.columns.map(e=>{const r=rows.find(r=>r.table_name===e.table&&r.name===e.name);return{table:e.table,column:e.name,state:!r?'absent':['type','notnull','dflt_value','pk'].every(k=>r[k]===e[k])?'matches':'differs'};});if(checks.some(c=>c.state!=='matches'))failed=true;console.log(JSON.stringify({check:'columns',status:checks.every(c=>c.state==='matches')?'matches':'requires-review',columns:checks}));}}

const ledger=await call('ledger','d1/database/'+D+'/query','SELECT name FROM d1_migrations ORDER BY name');
if(ledger){const rows=ledger[0]?.results;if(!Array.isArray(rows)||rows.some(r=>typeof r.name!=='string')){failed=true;console.log(JSON.stringify({check:'ledger',status:'unverifiable'}));}else{const expected=readdirSync('migrations').filter(x=>x.endsWith('.sql'));if(expected.some(name=>!rows.some(r=>r.name===name))||rows.some(r=>!expected.includes(r.name)))failed=true;console.log(JSON.stringify({check:'ledger',status:'read',expected:expected.map(name=>({name,applied:rows.some(r=>r.name===name)})),unrecognizedCount:rows.filter(r=>!expected.includes(r.name)).length}));}}
// Pre-0060 exact grouping: new phrase/template columns do not exist yet and will
// all be NULL when the migration's deduplication runs. Counts only, never IDs.
if(Array.isArray(schema?.[0]?.results)&&!schema[0].results.some(r=>r.type==='table'&&r.name==='service_routes'&&/\bphrase\s+TEXT/i.test(r.sql??''))){
const impact=await call('rules-pre0060-impact','d1/database/'+D+'/query',"SELECT (SELECT count(*) FROM service_routes) total_routes,(SELECT count(*) FROM (SELECT 1 FROM service_routes GROUP BY owner_id,service_id,source_id,origin_kind,origin_value,COALESCE(entry_id,''),COALESCE(account_hint,'') HAVING count(*)>1)) duplicate_groups,(SELECT COALESCE(sum(n-1),0) FROM (SELECT count(*) n FROM service_routes GROUP BY owner_id,service_id,source_id,origin_kind,origin_value,COALESCE(entry_id,''),COALESCE(account_hint,'') HAVING count(*)>1)) duplicate_excess_rows,(SELECT count(*) FROM (SELECT 1 FROM service_routes GROUP BY owner_id,service_id,source_id,origin_kind,origin_value,COALESCE(entry_id,''),COALESCE(account_hint,'') HAVING count(*)>1 AND (count(DISTINCT quote(entry_id))>1 OR count(DISTINCT quote(account_hint))>1))) mixed_null_empty_groups,(SELECT count(*) FROM service_routes r JOIN sources s ON s.owner_id=r.owner_id AND s.source_id=r.source_id WHERE s.revoked_at IS NOT NULL) routes_on_revoked_sources,(SELECT count(*) FROM service_routes r JOIN sources s ON s.owner_id=r.owner_id AND s.source_id=r.source_id WHERE s.revoked_at IS NOT NULL AND r.entry_id IS NULL) entryless_routes_on_revoked_sources,(SELECT count(DISTINCT r.owner_id) FROM service_routes r JOIN sources s ON s.owner_id=r.owner_id AND s.source_id=r.source_id WHERE s.revoked_at IS NOT NULL) owners_on_revoked_sources");
if(impact){const rows=impact[0]?.results,keys=['total_routes','entryless_routes_on_revoked_sources','owners_on_revoked_sources','duplicate_groups','duplicate_excess_rows','mixed_null_empty_groups','routes_on_revoked_sources'],r=rows?.[0];if(!Array.isArray(rows)||rows.length!==1||!r||keys.some(k=>!Number.isSafeInteger(r[k])||r[k]<0)){failed=true;console.log(JSON.stringify({check:'rules-pre0060-impact',status:'unverifiable'}));}else console.log(JSON.stringify({check:'rules-pre0060-impact',status:'read',...Object.fromEntries(keys.map(k=>[k,r[k]]))}));}
}else if(Array.isArray(schema?.[0]?.results))console.log(JSON.stringify({check:'rules-pre0060-impact',status:'not-pre0060'}));else{failed=true;console.log(JSON.stringify({check:'rules-pre0060-impact',status:'unverifiable'}));}
// The accepted preapply ledger has no 0054 table. If it exists unexpectedly,
// only count affected previews, and never select its contents or identifiers.
if(Array.isArray(schema?.[0]?.results)&&schema[0].results.some(r=>r.type==='table'&&r.name==='unassigned_context')){
 const preview=await call('rules-preview-impact','d1/database/'+D+'/query','SELECT count(*) affected_previews FROM unassigned_context c JOIN sources s ON s.owner_id=c.owner_id AND s.source_id=c.source_id WHERE s.revoked_at IS NOT NULL');const rows=preview?.[0]?.results,n=rows?.[0]?.affected_previews;
 if(!Array.isArray(rows)||rows.length!==1||!Number.isSafeInteger(n)||n<0){failed=true;console.log(JSON.stringify({check:'rules-preview-impact',status:'unverifiable'}));}else console.log(JSON.stringify({check:'rules-preview-impact',status:'read',affected_previews:n}));
}else if(Array.isArray(schema?.[0]?.results))console.log(JSON.stringify({check:'rules-preview-impact',status:'table-absent',affected_previews:0}));else{failed=true;console.log(JSON.stringify({check:'rules-preview-impact',status:'unverifiable'}));}

if(failed)process.exitCode=2;
