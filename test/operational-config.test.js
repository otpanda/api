import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const config=JSON.parse(readFileSync(new URL('../wrangler.jsonc',import.meta.url),'utf8'));
test('edge bindings remain distinct bounded counters for explicit auth-only deployment',()=>{
 const expected={SIGNUP_ADDRESS_LIMIT:10,SIGNUP_GLOBAL_LIMIT:10,SIGNUP_VERIFY_ADDRESS_LIMIT:30,SIGNUP_VERIFY_GLOBAL_LIMIT:15,IDENTITY_ADDRESS_LIMIT:60,IDENTITY_AUTH_GLOBAL_LIMIT:15,IDENTITY_READ_GLOBAL_LIMIT:30};
 assert.equal(config.vars.DEPLOYMENT_STAGE,'auth-only');
 assert.equal(config.vars.AUTH_ONLY_SIGNUP_MODE,'public');
 assert.equal(config.main,'src/auth-only-worker.js');
 assert.deepEqual(Object.fromEntries(config.ratelimits.map(b=>[b.name,b.simple.limit])),expected);
 assert.equal(new Set(config.ratelimits.map(b=>b.namespace_id)).size,7);
 for(const b of config.ratelimits){assert.match(b.namespace_id,/^[1-9][0-9]*$/);assert.equal(b.simple.period,60);}
 assert.ok(!('ENCRYPTION_KEYRING' in config.vars));
 assert.ok(!('ACTIVE_KEY_ID' in config.vars));
});
