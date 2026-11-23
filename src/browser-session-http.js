// First-party restore boundary. No login/session creation or native clients.
import {cookie,readCookie,json,securityHeaders,takeRateLimit} from './sessions.js';
import {generateAccessToken} from './tokens.js';
const API='https://otpanda-api.abrahammurciano.workers.dev',APP='https://otpanda.github.io',REDIRECT=APP+'/app/';
export const REFRESH_COOKIE='__Host-otpanda_device';
const CSRF='__Host-otpanda_restore';
const OPAQUE=/^[A-Za-z0-9_-]{43}$/;
const STATE=/^[A-Za-z0-9_-]{32,128}$/;
const cors={'Access-Control-Allow-Origin':APP,'Vary':'Origin'};
function parameters(data){
 if([...data.keys()].some(k=>!['challenge','state','redirect_uri','csrf'].includes(k)))return;
 if(['challenge','state','redirect_uri'].some(k=>data.getAll(k).length!==1))return;
 const challenge=data.get('challenge'),state=data.get('state'),redirectUri=data.get('redirect_uri');
 if(!OPAQUE.test(challenge)||!STATE.test(state)||redirectUri!==REDIRECT)return;
 return {challenge,state,redirectUri};
}
async function boundedText(request,max){const reader=request.body?.getReader();if(!reader)return '';const chunks=[];let size=0;try{while(true){const {done,value}=await reader.read();if(done)break;size+=value.byteLength;if(size>max){await reader.cancel();return undefined;}chunks.push(value);}return new TextDecoder('utf-8',{fatal:true}).decode(Uint8Array.from(chunks.flatMap(c=>Array.from(c))));}catch{return undefined;}finally{reader.releaseLock();}}
function html(body,status=200,extra={}){return new Response(body,{status,headers:{...securityHeaders,'Referrer-Policy':'same-origin','Content-Type':'text/html; charset=utf-8','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://otpanda.github.io/app/; frame-ancestors 'none'; base-uri 'none'",...extra}});}
export function createBrowserSessionHttp({sessions,exchanges,db,clock=Date.now}={}){
 if(!sessions||!exchanges||!db)throw new TypeError('Session dependencies required');
 return {async fetch(request,{clientAddress}={}){
  const url=new URL(request.url);
  if(url.origin!==API)return json({error:'not_found'},404);
  if(!['/auth/restore','/auth/exchange'].includes(url.pathname))return json({error:'not_found'},404);
  const exchange=url.pathname==='/auth/exchange';
  const origin=request.headers.get('origin');
  if(exchange&&origin!==APP)return json({error:'forbidden'},403);
  if(exchange&&request.method==='OPTIONS'){
   const headers=request.headers.get('access-control-request-headers')?.toLowerCase().split(',').map(v=>v.trim())??[];
   if(request.headers.get('access-control-request-method')!=='POST'||headers.some(h=>h!=='content-type'))return json({error:'forbidden'},403);
   return new Response(null,{status:204,headers:{...securityHeaders,...cors,'Access-Control-Allow-Methods':'POST','Access-Control-Allow-Headers':'Content-Type'}});
  }
  if((exchange&&request.method!=='POST')||(!exchange&&!['GET','POST'].includes(request.method)))return json({error:'method_not_allowed'},405);
  // Address is supplied by trusted runtime metadata, never forwarded headers.
  if(typeof clientAddress!=='string'||!clientAddress||clientAddress.length>128)return json({error:'unavailable'},503);
  const limit=await takeRateLimit(db,'browser-session:'+url.pathname+':'+clientAddress,{now:clock(),limit:30});
  if(!limit.allowed)return json({error:'rate_limited'},429,{'Retry-After':String(limit.retryAfter),...(exchange?cors:{})});
  if(exchange){
   if(url.search||request.headers.get('content-type')!=='application/json'||Number(request.headers.get('content-length')??0)>4096)return json({error:'invalid_request'},400,cors);
   const text=await boundedText(request,4096);if(text===undefined)return json({error:'invalid_request'},400,cors);
   let data;try{data=JSON.parse(text);}catch{return json({error:'invalid_request'},400,cors);}
   if(!data||Array.isArray(data)||Object.keys(data).sort().join(',')!=='code,redirect_uri,verifier')return json({error:'invalid_request'},400,cors);
   const result=await exchanges.exchange({code:data.code,verifier:data.verifier,redirectUri:data.redirect_uri});
   return result?json(result,200,cors):json({error:'invalid_grant'},401,cors);
  }
  if(request.method==='GET'){
   const p=parameters(url.searchParams);if(!p||url.searchParams.has('csrf'))return html('<h1>Invalid restoration request</h1>',400);
   const csrf=generateAccessToken().token;
   // All interpolated query values have narrow alphabets or a fixed constant.
   return html(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta name="color-scheme" content="light"><title>Continue to OTPanda</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f5f8f7;color:#17332a;font:16px/1.55 system-ui,sans-serif;padding:24px}.card{width:100%;max-width:460px;background:white;border:1px solid #dfe8e2;border-radius:24px;padding:32px;box-shadow:0 12px 36px #17332a0a}.brand{display:flex;gap:10px;align-items:center;font-weight:800;font-size:21px;letter-spacing:-.5px}.mark svg{width:36px;height:36px}.mark{width:40px;height:40px;display:grid;place-items:center;background:#e7f8ee;border-radius:12px;color:#0a7955;font-size:23px}h1{font-size:28px;line-height:1.2;letter-spacing:-.7px;margin:30px 0 14px}p{color:#52665e;margin:0 0 24px}.note{font-size:13px;margin:22px 0 0}button{border:0;border-radius:12px;min-height:48px;width:100%;background:#0a7955;color:white;font:700 16px system-ui;cursor:pointer}button:focus-visible{outline:3px solid #17332a;outline-offset:3px}@media(max-width:380px){body{padding:16px}.card{padding:24px}h1{font-size:25px}}</style></head><body><main class="card"><div class="brand"><span class="mark" aria-hidden="true"><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1072 1072" role="img" aria-labelledby="title desc">
<title id="title">Otty, the OTPanda mascot</title><desc id="desc">A black and white panda with a curled tuft, bright eyes and a raised asterisk paw, surrounded by sweeping ribbons.</desc>
<defs>
<linearGradient id="green" x1="0" y1="0" x2="1" y2="1"><stop stop-color="#10B981"/><stop offset=".52" stop-color="#00CB91"/><stop offset="1" stop-color="#009C69"/></linearGradient>
<linearGradient id="greenShade" x1="0" x2="1"><stop stop-color="#00885E"/><stop offset="1" stop-color="#10B981"/></linearGradient>
<radialGradient id="fur" cx=".38" cy=".05" r="1"><stop stop-color="#484955"/><stop offset=".48" stop-color="#20212B"/><stop offset="1" stop-color="#090C12"/></radialGradient>
<radialGradient id="innerEar" cx=".6" cy=".75" r=".8"><stop stop-color="#1B1D27"/><stop offset="1" stop-color="#070A10"/></radialGradient>
<linearGradient id="whiteFur" x1=".35" y1=".3" x2=".6" y2="1"><stop stop-color="#FFFFFF"/><stop offset=".7" stop-color="#F9F9FC"/><stop offset="1" stop-color="#D7D8E0"/></linearGradient>
<radialGradient id="badge" cx=".4" cy=".15" r="1"><stop stop-color="#006744"/><stop offset="1" stop-color="#003522"/></radialGradient>
<linearGradient id="paw" x1=".4" y1="0" x2=".65" y2="1"><stop stop-color="#444754"/><stop offset=".65" stop-color="#242630"/><stop offset="1" stop-color="#11151D"/></linearGradient>
</defs><g id="swirls" fill="url(#green)">
<path d="M94 253C199 97 342 40 473 62C564 74 641 109 693 147C542 79 359 70 219 161C170 192 129 229 94 253Z"/>
<path d="M218 217C112 357 94 543 154 699C217 864 373 971 550 981C681 988 804 945 898 881C784 982 632 1032 482 1009C285 980 133 851 88 659C45 484 99 305 218 217Z"/>
<path d="M251 310C314 166 460 123 591 161C637 174 679 195 715 222C577 164 430 183 337 294C251 397 239 544 300 669C184 589 143 469 176 354C217 207 365 113 605 126C429 81 289 167 251 310Z"/>
<path d="M961 473C1019 598 1006 713 931 801L891 746C948 667 973 573 961 473Z"/>
</g>
<path fill="url(#greenShade)" d="M251 310C209 421 218 542 277 642L301 670C183 591 143 469 176 354C196 283 242 225 309 187C275 221 259 264 251 310Z"/>
<g id="panda">
<path fill="url(#fur)" stroke="#080E13" stroke-width="9" d="M286 365C321 277 452 218 576 226C746 208 864 315 912 454C928 497 944 534 930 575C917 624 897 683 872 737C845 811 780 890 673 905C504 926 358 851 283 738C196 657 174 491 286 365Z"/>
<path fill="url(#whiteFur)" d="M337 322C405 266 488 243 585 244C698 231 825 301 881 414C899 450 913 491 915 533C925 584 897 633 868 670C802 739 711 763 615 758C503 762 378 759 303 706C218 645 217 559 245 479C266 415 285 370 337 322Z"/>
<path fill="#FFFFFF" d="M344 333C411 275 492 254 590 255C709 241 821 311 868 408C902 478 906 528 886 574C824 694 646 759 482 726C373 705 290 658 264 573C244 504 286 387 344 333Z" opacity=".5"/>
<path fill="url(#fur)" stroke="#0A1015" stroke-width="8" d="M259 400C213 372 220 301 244 258C275 205 326 177 375 180C426 181 469 214 480 255C492 287 471 309 442 312C406 307 383 325 361 359C334 401 297 423 259 400Z"/>
<path fill="url(#innerEar)" d="M308 361C284 344 290 302 314 276C343 245 384 241 414 266C426 276 433 292 432 308C403 305 383 325 361 359C342 364 324 368 308 361Z"/>
<path fill="url(#fur)" stroke="#0A1015" stroke-width="8" d="M716 238C742 203 788 191 833 205C890 222 921 268 919 315C919 350 901 381 877 396C851 360 828 322 793 296C768 276 737 258 716 238Z"/>
<path fill="url(#innerEar)" d="M782 290C797 260 829 252 853 269C879 288 883 327 866 349C841 321 814 302 782 290Z"/>
<path fill="url(#fur)" d="M563 263C572 247 577 233 574 218C568 201 574 185 587 187C615 187 628 210 625 237C650 232 674 236 694 246C665 245 649 251 633 257C647 270 647 282 640 290C627 272 615 266 601 264C613 275 611 285 604 288C589 276 567 278 563 263Z"/>
<path fill="#FFFFFF" d="M587 209C600 209 609 219 610 235L591 242C597 228 592 216 587 209Z"/>
<path fill="url(#fur)" d="M397 469C451 419 506 389 549 401C589 412 613 449 609 493C605 544 567 585 519 612C478 635 432 633 405 612C366 581 371 513 397 469Z"/>
<path fill="url(#fur)" d="M779 410C808 394 837 414 859 446C883 478 899 518 887 550C878 576 855 596 835 605C801 590 769 567 753 536C739 506 739 432 779 410Z"/>
<g id="eyes">
<path fill="#FCFCFF" d="M505 501C525 471 555 471 566 497C580 530 556 562 529 555C505 550 493 529 505 501Z"/>
<ellipse fill="#0C1017" cx="526" cy="521" rx="27" ry="33" transform="rotate(15 526 521)"/>
<ellipse fill="#03070C" cx="525" cy="522" rx="17" ry="21"/>
<circle fill="#FFFFFF" cx="524" cy="503" r="9"/>
<path fill="#FCFCFF" d="M777 496C791 471 812 473 823 497C838 527 823 553 804 549C785 547 768 521 777 496Z"/>
<ellipse fill="#0C1017" cx="797" cy="518" rx="18" ry="29" transform="rotate(-12 797 518)"/>
<ellipse fill="#03070C" cx="797" cy="519" rx="12" ry="18"/>
<circle fill="#FFFFFF" cx="788" cy="503" r="7"/>
</g>
<path fill="url(#fur)" d="M659 550C676 540 709 541 733 549C755 561 726 587 705 592C688 598 642 566 659 550Z"/>
<path fill="#646571" opacity=".55" d="M664 551C683 546 710 547 728 551C715 560 680 562 664 551Z"/>
<path fill="none" stroke="#090D14" stroke-width="15" stroke-linecap="round" d="M698 589L697 617C672 644 633 650 610 613M697 617C709 632 719 637 730 631"/>
<path fill="url(#paw)" stroke="#090D14" stroke-width="12" d="M304 741C348 773 401 792 448 780C495 767 557 753 606 757C651 759 680 786 697 824C718 863 703 890 678 900C554 918 423 870 346 801C327 783 314 762 304 741Z"/>
</g>
<g id="asterisk-paw">
<path fill="url(#badge)" stroke="#004B31" stroke-width="7" d="M750 649C818 588 888 594 943 642C997 689 990 769 954 828C919 882 854 902 790 875C728 850 691 789 698 733C701 702 719 674 750 649Z"/>
<path fill="none" stroke="#78D9B3" stroke-opacity=".55" stroke-width="6" stroke-linecap="round" d="M758 649C820 603 879 600 924 636"/>
<path fill="#FFFFFF" d="M827 650Q824 650 823 656L819 714L774 682Q768 677 764 683L752 704Q749 710 755 714L804 742L753 770Q748 773 751 779L764 802Q768 808 774 803L817 772L814 829Q814 836 821 836L847 837Q853 837 854 830L855 773L901 805Q907 810 911 804L924 782Q928 776 921 772L871 743L923 717Q930 713 926 707L914 684Q911 678 905 681L859 712L864 658Q864 651 857 651Z"/>
</g></svg></span>OTPanda</div><h1>Your codes, one step away.</h1><p>Continue to restore this browser's session. You won't need another sign-in if your saved session is still available.</p><form method="post" action="/auth/restore"><input type="hidden" name="challenge" value="${p.challenge}"><input type="hidden" name="state" value="${p.state}"><input type="hidden" name="redirect_uri" value="${REDIRECT}"><input type="hidden" name="csrf" value="${csrf}"><button type="submit">Continue</button></form><p class="note">Cleared your browser data or signed out? You may need to sign in again. This page never asks for email codes or recovery details.</p></main></body></html>`,200,{'Set-Cookie':cookie(CSRF,csrf,300)});
  }
  if(origin!==API||url.search||request.headers.get('content-type')!=='application/x-www-form-urlencoded')return html('<h1>Request not allowed</h1>',403);
  const text=await boundedText(request,2048);if(text===undefined)return html('<h1>Invalid request</h1>',400);
  const data=new URLSearchParams(text),p=parameters(data),csrf=readCookie(request,CSRF);
  if(!p||data.getAll('csrf').length!==1||!csrf||csrf.length>200||data.get('csrf')!==csrf)return html('<h1>Request expired. Start again.</h1>',403);
  const refresh=readCookie(request,REFRESH_COOKIE),result=await sessions.rotate(refresh,{clientKind:'web'});
  if(result.status==='retry')return html('<h1>Another tab is restoring your session. Please try again.</h1>',409);
  if(result.status!=='rotated')return html('<h1>Sign in again</h1><p>Your browser session is unavailable.</p>',401,{'Set-Cookie':cookie(REFRESH_COOKIE,'',0)});
  const headers=new Headers({...securityHeaders,'Set-Cookie':cookie(REFRESH_COOKIE,result.refresh,Math.max(0,Math.floor((result.refreshExpiresAt-clock())/1000)))});
  headers.append('Set-Cookie',cookie(CSRF,'',0));
  const grant=await exchanges.mint({deviceId:result.deviceId,challenge:p.challenge,redirectUri:REDIRECT});
  if(!grant){headers.set('Content-Type','text/html; charset=utf-8');return new Response('<h1>Sign in again</h1>',{status:401,headers});}
  const target=new URL(REDIRECT);target.hash=new URLSearchParams({code:grant.code,state:p.state}).toString();
  headers.set('Location',target.href);return new Response(null,{status:303,headers});
 }};
}
