import test from 'node:test';import assert from 'node:assert/strict';
import{signupEmail,googleVerifyEmail,recoveryEmail,notificationEmail}from'../src/email-templates.js';
import{createRecoveryMailDelivery,createRecoveryNotificationDelivery}from'../src/recovery-mail-transport.js';
const opts={apiKey:'synthetic-dummy',senderEmail:'project@example.test',replyToEmail:'reply@example.test'};
const CODE='ABCD2345';
const all=()=>[signupEmail('otpda_'+'a'.repeat(55)),googleVerifyEmail(CODE),recoveryEmail('recovery-request',CODE),recoveryEmail('recovery-complete',CODE),notificationEmail('requested'),notificationEmail('canceled'),notificationEmail('completed')];
test('plain text alternatives keep the exact original wording',()=>{
 assert.equal(recoveryEmail('recovery-request',CODE).text,'Someone asked to start email recovery for your OTPanda account. Your code is:\n\nABCD2345\n\nEnter it in the OTPanda app where you started. Entering it only starts a 7 day wait. It does not sign anyone in and does not give access to your codes. If this was not you, ignore this email and open OTPanda on a device signed in with a passkey and cancel the request or turn the setting off.');
 assert.equal(recoveryEmail('recovery-complete',CODE).text,'Your 7 day email recovery wait is over. Your code is:\n\nABCD2345\n\nEnter it in the OTPanda app where you started, then create a NEW passkey. Finishing removes every old passkey, device key, session and automation token from this account. Your codes, shares and linked Google account are kept. If this was not you, ignore this email.');
 assert.equal(googleVerifyEmail(CODE).text,'Your OTPanda verification code is:\n\nABCD2345\n\nReturn to the same browser to continue. This verifies your Google account email for OTPanda. If you did not request this, ignore this email.');
 assert.equal(notificationEmail('canceled').text,'The email recovery request for your OTPanda account was canceled.');
 assert.ok(notificationEmail('requested').text.includes('after 7 days'));assert.ok(notificationEmail('completed').text.endsWith('contact support right away.'));
 assert.ok(signupEmail('otpda_'+'a'.repeat(55)).text.includes('ten minutes'));
});
test('every email is branded, self-contained and carries the same security meaning in HTML',()=>{
 for(const m of all()){
  assert.match(m.html,/^<!doctype html>/);assert.ok(m.html.includes('#10b981')&&m.html.includes('OTPanda'));
  assert.ok(!/<script|<form|<iframe|href=|<a /i.test(m.html));assert.equal((m.html.match(/\son\w+=/gi)??[]).length,m.html.includes('Copy code')?1:0);
  assert.equal(m.html.includes('Copy code'),/Verification code|Recovery code/.test(m.html));
  if(m.html.includes('Copy code'))assert.ok(m.html.includes('Select the code and copy it')&&m.html.includes('user-select:all'));
  assert.ok(m.html.length<14000&&!/\{\{|undefined|null/.test(m.html));
  for(const phrase of ['7 day','ten minutes','ignore this email','cancel the request','contact support','NEW passkey','same browser','No account is created'])if(m.text.includes(phrase))assert.ok(m.html.includes(phrase),phrase);
 }
 const r=recoveryEmail('recovery-request',CODE);assert.ok(r.html.includes(CODE));
});
test('values are HTML escaped and unknown kinds are rejected',()=>{
 assert.throws(()=>signupEmail('<b>"x"</b>'),TypeError);
 for(const k of ['constructor','__proto__','marketing'])assert.throws(()=>recoveryEmail(k,CODE),TypeError),assert.throws(()=>notificationEmail(k),TypeError);
});
test('recovery delivery sends one recipient with html and text and rejects bad kinds',async()=>{
 const seen=[];const f=async(u,r)=>{seen.push(JSON.parse(r.body));return Response.json({messageId:'m'},{status:201});};
 const d=createRecoveryMailDelivery({...opts,fetchImpl:f});
 await d({kind:'recovery-request',to:'a@example.test',code:CODE,expiresAt:1});
 await createRecoveryNotificationDelivery({...opts,fetchImpl:f})({kind:'completed',to:'a@example.test'});
 assert.equal(seen.length,2);for(const p of seen){assert.equal(p.to.length,1);assert.ok(p.htmlContent&&p.textContent);}
 await assert.rejects(d({kind:'constructor',to:'a@example.test',code:CODE,expiresAt:1}),TypeError);
 await assert.rejects(d({kind:'recovery-request',to:'a@example.test',code:'bad',expiresAt:1}),TypeError);assert.equal(seen.length,2);
});
import vm from'node:vm';
test('copy button handler writes exactly the code to the clipboard and nothing else',async()=>{
 for(const m of [signupEmail('otpda_'+'a'.repeat(55)),googleVerifyEmail('482913'),recoveryEmail('recovery-request',CODE)]){
  const raw=/onclick="([^"]*)"/.exec(m.html)[1].replace(/&quot;/g,'"').replace(/&#39;/g,"'").replace(/&lt;/g,'<').replace(/&gt;/g,'>').replace(/&amp;/g,'&');
  const writes=[];const btn={textContent:'Copy code'};
  const ctx={navigator:{clipboard:{writeText:async t=>{writes.push(t);}}},document:{createElement(){throw Error('fallback not expected');}},setTimeout:()=>0,fetch(){throw Error('network');},XMLHttpRequest(){throw Error('network');}};
  const fn=vm.runInNewContext('(function(){'+raw+'})',ctx);fn.call(btn);await new Promise(r=>setImmediate(r));
  assert.equal(writes.length,1);assert.ok(m.text.includes(writes[0]));assert.equal(btn.textContent,'Copied');
 }
});

test('code format is strict: any markup, quote, script or whitespace payload is rejected before any HTML is built',()=>{
 const bad=['"><script>alert(1)</script>',"');alert(1);('",'a b c d e f','ABCD234\n5','<img src=x onerror=1>','\u2028abcdef','ABCDE','x'.repeat(81),'ABCD&amp;23','ab"onmouseover="1',"a'b'c'd'e'f",''];
 for(const b of bad){assert.throws(()=>signupEmail(b),TypeError);assert.throws(()=>googleVerifyEmail(b),TypeError);assert.throws(()=>recoveryEmail('recovery-request',b),TypeError);}
 assert.throws(()=>signupEmail(undefined),TypeError);assert.throws(()=>signupEmail({toString:()=>'ABCD2345'}),TypeError);
 for(const ok of ['482913','ABCD2345','otpda_'+'Ab3-_'.repeat(11)]){const h=signupEmail(ok).html;assert.ok(h.includes('onclick="'));assert.ok(!/onclick="[^"]*[<>']/.test(h));assert.equal((h.match(/"/g).length%2),0);}
});

test('long signup token gets a compact wrapped code style, short codes keep the large style',()=>{
 const tok=signupEmail('otpda_'+'Ab3-_'.repeat(11)).html;assert.ok(tok.includes('max-width:34ch')&&tok.includes('font:700 13px'));assert.ok(tok.includes('otpda_'+'Ab3-_'.repeat(11)));
 const short=signupEmail('482913').html;assert.ok(short.includes('font:700 34px')&&!short.includes('34ch'));
});
