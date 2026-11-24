import {securityHeaders} from './sessions.js';
import {base64urlEncode} from './tokens.js';
export const scriptValue=value=>JSON.stringify(value).replaceAll('<','\\u003c').replaceAll('>','\\u003e').replaceAll('&','\\u0026').replaceAll('\u2028','\\u2028').replaceAll('\u2029','\\u2029');
const APP='https://otpanda.github.io/app/';
export function appFailure(state='',reason='restart',extra={}) {
 const target=new URL(APP);target.hash=new URLSearchParams({auth:reason,state:/^[A-Za-z0-9_-]{43}$/.test(state)?state:''});
 return new Response(null,{status:303,headers:{...securityHeaders,Location:target.href,...extra}});
}
export function silentPost(action,fields,extra={}) {
 const nonce=base64urlEncode(crypto.getRandomValues(new Uint8Array(18)));
 if(!['/auth/restore','/auth/device/logout','/auth/login/complete'].includes(action))throw new TypeError('Fixed bridge action required');
 const script=`(()=>{'use strict';const f=document.createElement('form');f.method='post';f.action=${scriptValue(action)};for(const [name,value] of ${scriptValue(Object.entries(fields))}){const i=document.createElement('input');i.type='hidden';i.name=name;i.value=value;f.append(i);}document.body.append(f);f.submit();})();`;
 return new Response(`<!doctype html><html><head><meta charset="utf-8"><title>OTPanda</title></head><body><script nonce="${nonce}">${script}</script></body></html>`,{headers:{...securityHeaders,'Referrer-Policy':'same-origin','Content-Type':'text/html; charset=utf-8','Content-Security-Policy':`default-src 'none'; script-src 'nonce-${nonce}'; form-action 'self' https://otpanda.github.io/app/; frame-ancestors 'none'; base-uri 'none'`,...extra}});
}
