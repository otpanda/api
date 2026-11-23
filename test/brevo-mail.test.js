import test from 'node:test';
import assert from 'node:assert/strict';
import {BrevoMailTransport, MailSubmissionError} from '../src/brevo-mail.js';
const options = {apiKey:'synthetic-dummy', senderEmail:'project@example.test', replyToEmail:'reply@example.test'};
const mail = {to:'recipient@example.test', subject:'Synthetic test', text:'Synthetic body only.'};
test('fixed HTTP contract, one recipient and acceptance not delivery', async()=>{
 let calls=0;
 const transport=new BrevoMailTransport({...options,fetchImpl:async(url,request)=>{
  calls++;assert.equal(url,'https://api.brevo.com/v3/smtp/email');
  assert.equal(request.method,'POST');assert.equal(request.redirect,'manual');assert.equal(request.credentials,'omit');assert.equal(request.cache,'no-store');
  assert.equal(request.headers['api-key'],options.apiKey);assert.ok(request.signal instanceof AbortSignal);
  assert.deepEqual(JSON.parse(request.body),{sender:{email:options.senderEmail,name:'OTPanda'},replyTo:{email:options.replyToEmail},to:[{email:mail.to}],subject:mail.subject,textContent:mail.text});
  return Response.json({messageId:'<synthetic@example.test>'},{status:201});
 }});
 assert.deepEqual(await transport.submit(mail),{status:'accepted'});assert.equal(calls,1);
 assert.ok(!JSON.stringify(transport).includes(options.apiKey));assert.ok(!String(transport).includes(options.senderEmail));
});
test('invalid input rejects before any network request',async()=>{
 let calls=0;const transport=new BrevoMailTransport({...options,fetchImpl:async()=>{calls++;throw Error();}});
 for(const change of [{to:'a@example.test,b@example.test'},{subject:'x\r\nBcc: hidden'},{subject:''},{text:'x'.repeat(16001)},{text:'bad\u0000value'}]) await assert.rejects(transport.submit({...mail,...change}),TypeError);
 assert.equal(calls,0);
 for(const change of [{apiKey:'x\ny'},{senderEmail:'bad'},{replyToEmail:'bad'},{timeoutMs:10001}])assert.throws(()=>new BrevoMailTransport({...options,...change}),TypeError);
});
test('provider failures never leak response, message or secret and never retry',async()=>{
 for(const status of [400,401,429,500,302]){
  let calls=0;const transport=new BrevoMailTransport({...options,fetchImpl:async()=>{calls++;return new Response(options.apiKey+mail.to,{status});}});
  await assert.rejects(transport.submit(mail),e=>e instanceof MailSubmissionError&&!String(e).includes(options.apiKey)&&!String(e).includes(mail.to));assert.equal(calls,1);
 }
 const transport=new BrevoMailTransport({...options,fetchImpl:async()=>{throw Error(options.apiKey+mail.to);}});
 await assert.rejects(transport.submit(mail),e=>e.outcome==='uncertain'&&!String(e).includes(mail.to));
});
test('malformed and unbounded success replies are uncertain',async()=>{
 for(const response of [new Response('{}',{status:201}),new Response('not json',{status:201}),Response.json({messageId:'x\nsecret'},{status:201}),new Response(new Uint8Array([255]),{status:201}),new Response('x'.repeat(8193),{status:201})]){
  const transport=new BrevoMailTransport({...options,fetchImpl:async()=>response});await assert.rejects(transport.submit(mail),MailSubmissionError);
 }
});
test('stream ceiling cancels and advertised ceiling rejects without reading',async()=>{
 let canceled=0,reads=0;
 const transport=new BrevoMailTransport({...options,fetchImpl:async()=>new Response(new ReadableStream({pull(c){reads++;c.enqueue(new Uint8Array(5000));},cancel(){canceled++;}}),{status:201})});
 await assert.rejects(transport.submit(mail),MailSubmissionError);assert.equal(canceled,1);assert.ok(reads<=3);
 let pulled=false;
 const oversized=new BrevoMailTransport({...options,fetchImpl:async()=>new Response(new ReadableStream({start(){},pull(){pulled=true;}}),{status:201,headers:{'content-length':'8193'}})});
 await assert.rejects(oversized.submit(mail),MailSubmissionError);
});
test('timeout bounds a hung fetch and hung body without retry',async()=>{
 for(const fetchImpl of [()=>new Promise(()=>{}),async()=>new Response(new ReadableStream({start(){}}),{status:201})]){
  const transport=new BrevoMailTransport({...options,timeoutMs:10,fetchImpl});await assert.rejects(transport.submit(mail),e=>e instanceof MailSubmissionError&&e.outcome==='uncertain');
 }
});
