// Host-specific resolver, not a generic header trust helper. Use only at the
// direct public workers.dev boundary with no internal service-binding callers.
// Cloudflare adds CF-Worker to fetch subrequests; reject those, the fixed
// cross-zone worker identity and absent metadata sanity fields. These fields
// are not proof of provenance. A Request
// supplied by an internal caller can forge metadata, so wiring is load-bearing.
import{canonicalClientAddress}from'./client-address.js';
// Provider fixed Worker client IP, defense in depth only. CF-Worker refusal is
// primary. Source: https://developers.cloudflare.com/fundamentals/reference/http-headers/
const ORIGIN='https://otpanda-api.abrahammurciano.workers.dev';
export function resolveCloudflareDirectIngress(request){
 if(new URL(request.url).origin!==ORIGIN||request.headers.has('CF-Worker'))return;
 const cf=request.cf;
 if(!cf||typeof cf.colo!=='string'||!cf.colo||typeof cf.httpProtocol!=='string'||!cf.httpProtocol||typeof cf.tlsVersion!=='string'||!cf.tlsVersion.startsWith('TLS'))return;
 const raw=request.headers.get('CF-Connecting-IP'),address=canonicalClientAddress(raw);
 if(!address||address===canonicalClientAddress('2a06:98c0:3600::103'))return;
 return address;
}
