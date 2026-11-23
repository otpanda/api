import test from 'node:test';
import assert from 'node:assert/strict';
import {canonicalClientAddress} from '../src/client-address.js';

test('IPv4 is canonicalized and strict',()=>{
 assert.equal(canonicalClientAddress('192.0.2.1'),'192.0.2.1');
 assert.equal(canonicalClientAddress('0.0.0.0'),'0.0.0.0');
 assert.equal(canonicalClientAddress('192.00.2.1'),undefined);
 assert.equal(canonicalClientAddress('256.1.1.1'),undefined);
 assert.equal(canonicalClientAddress('1.2.3'),undefined);
 assert.equal(canonicalClientAddress('1.2.3.4.5'),undefined);
});
test('IPv6 folds to a lowercase /64 prefix so rotation cannot multiply quotas',()=>{
 assert.equal(canonicalClientAddress('2001:DB8::1'),'2001:db8:0:0::/64');
 assert.equal(canonicalClientAddress('2001:db8::ffff'),'2001:db8:0:0::/64');
 assert.equal(canonicalClientAddress('2001:0db8:0000:0000:0000:0000:0000:0001'),'2001:db8:0:0::/64');
 assert.equal(canonicalClientAddress('2001:db8:0:1::1'),'2001:db8:0:1::/64');
 assert.equal(canonicalClientAddress('::'),'0:0:0:0::/64');
});
test('IPv4-mapped IPv6 shares the native IPv4 bucket',()=>{
 assert.equal(canonicalClientAddress('::ffff:192.0.2.1'),'192.0.2.1');
 assert.equal(canonicalClientAddress('::FFFF:192.0.2.1'),'192.0.2.1');
 assert.equal(canonicalClientAddress('0:0:0:0:0:ffff:192.0.2.1'),undefined);
});
test('malformed, zoned, forwarded and oversized values fail closed',()=>{
 for(const v of ['fe80::1%eth0','1.2.3.4, 5.6.7.8',' 192.0.2.1','192.0.2.1 ','','unknown','2001:db8:::1','2001:db8::1::2','x'.repeat(46),'12345',42,null,undefined,{}])assert.equal(canonicalClientAddress(v),undefined);
});
test('hex mapped IPv4 shares native dotted quota identity',()=>{assert.equal(canonicalClientAddress('::ffff:7f00:1'),'127.0.0.1');assert.equal(canonicalClientAddress('0:0:0:0:0:ffff:c000:201'),'192.0.2.1');});
test('canonical IPv6 quota identities are idempotent but noncanonical CIDR is rejected',()=>{const canonical='2001:db8:0:0::/64';assert.equal(canonicalClientAddress(canonical),canonical);for(const raw of ['2001:db8::/64','2001:DB8:0:0::/64','2001:db8:0:0::1/64','192.0.2.1/64','2001:db8:0:0::/32'])assert.equal(canonicalClientAddress(raw),undefined);});
