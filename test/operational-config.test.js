import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const config=JSON.parse(readFileSync(new URL('../wrangler.jsonc',import.meta.url),'utf8'));
test('edge bindings remain distinct bounded counters for explicit auth-only deployment',()=>{
 const expected={SIGNUP_ADDRESS_LIMIT:10,SIGNUP_GLOBAL_LIMIT:10,SIGNUP_VERIFY_ADDRESS_LIMIT:30,SIGNUP_VERIFY_GLOBAL_LIMIT:15,IDENTITY_ADDRESS_LIMIT:60,IDENTITY_AUTH_GLOBAL_LIMIT:15,IDENTITY_READ_GLOBAL_LIMIT:30,REALTIME_ADDRESS_LIMIT:30,REALTIME_GLOBAL_LIMIT:60,REALTIME_TICKET_LIMIT:12};
 assert.equal(config.vars.DEPLOYMENT_STAGE,'auth-only');
 assert.equal(config.vars.AUTH_ONLY_SIGNUP_MODE,'public');
 assert.equal(config.main,'src/auth-only-worker.js');
 assert.deepEqual(Object.fromEntries(config.ratelimits.map(b=>[b.name,b.simple.limit])),expected);
 assert.equal(new Set(config.ratelimits.map(b=>b.namespace_id)).size,10);
 for(const b of config.ratelimits){assert.match(b.namespace_id,/^[1-9][0-9]*$/);assert.equal(b.simple.period,60);}
 assert.ok(!('ENCRYPTION_KEYRING' in config.vars));
 assert.ok(!('ACTIVE_KEY_ID' in config.vars));
});

test('realtime binding stage preserves one maintenance cron and SQLite class migration',()=>{
 assert.deepEqual(config.triggers.crons,['*/15 * * * *','*/5 * * * *']);
 assert.deepEqual(config.durable_objects.bindings,[{name:'REALTIME_HUB',class_name:'RealtimeHub'}]);
 assert.deepEqual(config.migrations,[{tag:'realtime-v1',new_sqlite_classes:['RealtimeHub']}]);
 assert.deepEqual(config.ratelimits.filter(x=>x.name.startsWith('REALTIME_')).map(x=>x.namespace_id),['68022008','68022009','68022010']);
});
