// Branded HTML and exact plain-text alternatives for every OTPanda transactional
// email. Server-only: callers pass a proof-validated code or a fixed kind, never
// free text. Codes, wording, wait times and cancellation guidance are unchanged
// from the plain-text templates; HTML only adds presentation. Table layout and
// inline CSS so it survives mail clients. No external scripts, forms or links, and
// the code is never put in a URL. The Copy button is a progressive enhancement:
// it works only in clients that allow inline script (most strip it), and the
// code stays selectable text for manual copying everywhere.
const GREEN='#10b981',INK='#082c25',PAPER='#f6f8ef',MUTED='#53665e',LINE='#d7e0d7',MINT='#3ddba7';
const LOGO='https://otpanda.github.io/home/assets/brand/otty-tile-v7-192.png';
const FONT="-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif";
const MONO="ui-monospace,SFMono-Regular,Menlo,Consolas,'Courier New',monospace";
const esc=s=>String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
const para=t=>`<p style="margin:0 0 16px;font:16px/1.65 ${FONT};color:${INK}">${esc(t)}</p>`;
function copyHandler(code){
 // Plain clipboard write with a legacy fallback. Runs only where the client permits script.
 const c=JSON.stringify(code);
 return `var b=this,c=${c},d=function(){b.textContent='Copied';setTimeout(function(){b.textContent='Copy code'},1800)};try{navigator.clipboard.writeText(c).then(d,function(){var t=document.createElement('textarea');t.value=c;document.body.appendChild(t);t.select();document.execCommand('copy');document.body.removeChild(t);d()})}catch(e){var t=document.createElement('textarea');t.value=c;document.body.appendChild(t);t.select();try{document.execCommand('copy');d()}catch(f){}document.body.removeChild(t)}`;
}
const CODE=/^[A-Za-z0-9_-]{6,80}$/;
const need=code=>{if(typeof code!=='string'||!CODE.test(code))throw new TypeError('Server code required');return code;};
function codeBlock(code,label){
 return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:6px 0 22px;background:#ecf8ef;border:1px solid #bcebd7;border-radius:14px"><tr><td align="center" style="padding:22px 14px 20px"><div style="font:700 11px/1 ${MONO};letter-spacing:.16em;text-transform:uppercase;color:${MUTED}"><span style="color:${GREEN}">&#9679;</span>&nbsp; ${esc(label)}</div><div style="margin:16px auto 18px;${code.length>12?`max-width:34ch;font:700 13px/1.6 ${MONO};letter-spacing:.02em`:`font:700 34px/1.2 ${MONO};letter-spacing:.16em`};color:${INK};word-break:break-all;-webkit-user-select:all;user-select:all">${esc(code)}</div><button type="button" onclick="${esc(copyHandler(code))}" style="background:${GREEN};color:${INK};border:0;border-radius:8px;padding:13px 26px;font:750 15px/1 ${FONT};cursor:pointer">Copy code</button><div style="margin-top:14px;font:12px/1.5 ${FONT};color:${MUTED}">Button not working in your mail app? Select the code and copy it.</div></td></tr></table>`;
}
function notice(t){
 return `<table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="margin:6px 0 0"><tr><td style="background:#f8ecc4;border-radius:10px;padding:14px 16px;font:14px/1.55 ${FONT};color:#4a3a0a">${esc(t)}</td></tr></table>`;
}
function shell({preheader,title,eyebrow,blocks}){
 const words=title.split(' '),accent=words.pop(),plain=words.join(' ');
 return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="color-scheme" content="light"><meta name="supported-color-schemes" content="light"><title>${esc(title)}</title></head><body style="margin:0;padding:0;background:${PAPER}"><div style="display:none;max-height:0;overflow:hidden;opacity:0;color:${PAPER}">${esc(preheader)}</div><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background:${PAPER}"><tr><td align="center" style="padding:28px 12px 32px"><table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="max-width:560px"><tr><td style="padding:0 4px 16px"><table role="presentation" cellpadding="0" cellspacing="0" border="0"><tr><td style="padding-right:10px"><img src="${LOGO}" width="40" height="40" alt="" style="display:block;border:0;border-radius:11px"></td><td style="font:800 22px/1 ${FONT};color:${INK};letter-spacing:-.02em">OTPanda</td></tr></table></td></tr><tr><td style="background:${INK};border-radius:18px 18px 0 0;padding:32px 28px 30px"><div style="font:700 11px/1 ${MONO};letter-spacing:.16em;text-transform:uppercase;color:${MINT}"><span style="color:${GREEN}">&#9679;</span>&nbsp; ${esc(eyebrow)}</div><h1 style="margin:16px 0 0;font:800 32px/1.1 ${FONT};letter-spacing:-.03em;color:#ffffff">${esc(plain)} <span style="color:${MINT}">${esc(accent)}.</span></h1></td></tr><tr><td style="background:#ffffff;border:1px solid ${LINE};border-top:0;border-radius:0 0 18px 18px;padding:28px 28px 26px">${blocks.join('')}</td></tr><tr><td align="center" style="padding:22px 8px 0;font:12px/1.6 ${FONT};color:${MUTED}"><span style="color:${GREEN};font-size:16px">&#10035;</span><br><strong style="color:${INK}">OTPanda</strong> &middot; Your codes. Your devices. Your rules.<br>You received this because of activity on an OTPanda account.</td></tr></table></td></tr></table></body></html>`;
}
function make({subject,title,eyebrow,codeLabel='Verification code',preheader,intro,code,outro,warning,text}){
 const blocks=[...intro.map(para)];
 if(code!==undefined)blocks.push(codeBlock(code,codeLabel));
 blocks.push(...outro.map(para));
 if(warning)blocks.push(notice(warning));
 return {subject,text,html:shell({preheader,title,eyebrow,blocks})};
}
const ENTER_RECOVERY='Enter it in the OTPanda app where you started.';
export function signupEmail(code){
 need(code);
 return make({subject:'Verify your email for OTPanda',title:'Verify your email',eyebrow:'Email verification',preheader:'Your OTPanda verification code. It expires ten minutes after it was requested.',
  intro:['Return to the same browser where you started signup and paste this code.'],code,
  outro:['It expires ten minutes after it was requested.','No account is created until email verification and signup finish.'],
  warning:'If you did not request this, ignore this email.',
  text:'Your OTPanda verification code is:\n\n'+code+'\n\nReturn to the same browser where you started signup and paste this code. It expires ten minutes after it was requested. If you did not request this, ignore this email. No account is created until email verification and signup finish.'});
}
export function googleVerifyEmail(code){
 need(code);
 return make({subject:'Verify your email for OTPanda',title:'Verify your email',eyebrow:'Google account',preheader:'Your OTPanda verification code for your Google account.',
  intro:['Return to the same browser to continue. This verifies your Google account email for OTPanda.'],code,outro:[],
  warning:'If you did not request this, ignore this email.',
  text:'Your OTPanda verification code is:\n\n'+code+'\n\nReturn to the same browser to continue. This verifies your Google account email for OTPanda. If you did not request this, ignore this email.'});
}
const RECOVERY={
 'recovery-request':{subject:'OTPanda email recovery request',title:'Email recovery request',eyebrow:'Account recovery',codeLabel:'Recovery code',preheader:'Someone asked to start email recovery for your OTPanda account.',
  intro:['Someone asked to start email recovery for your OTPanda account.'],
  outro:[ENTER_RECOVERY+' Entering it only starts a 7 day wait. It does not sign anyone in and does not give access to your codes.'],
  warning:'If this was not you, ignore this email and open OTPanda on a device signed in with a passkey and cancel the request or turn the setting off.',
  text:['Someone asked to start email recovery for your OTPanda account. Your code is:\n\n','\n\nEnter it in the OTPanda app where you started. Entering it only starts a 7 day wait. It does not sign anyone in and does not give access to your codes. If this was not you, ignore this email and open OTPanda on a device signed in with a passkey and cancel the request or turn the setting off.']},
 'recovery-complete':{subject:'OTPanda email recovery code',title:'Finish email recovery',eyebrow:'Account recovery',codeLabel:'Recovery code',preheader:'Your 7 day email recovery wait is over.',
  intro:['Your 7 day email recovery wait is over.'],
  outro:[ENTER_RECOVERY+' Then create a NEW passkey.','Finishing removes every old passkey, device key, session and automation token from this account. Your codes, shares and linked Google account are kept.'],
  warning:'If this was not you, ignore this email.',
  text:['Your 7 day email recovery wait is over. Your code is:\n\n','\n\nEnter it in the OTPanda app where you started, then create a NEW passkey. Finishing removes every old passkey, device key, session and automation token from this account. Your codes, shares and linked Google account are kept. If this was not you, ignore this email.']},
};
export function recoveryEmail(kind,code){
 const t=Object.hasOwn(RECOVERY,kind)?RECOVERY[kind]:undefined;if(!t)throw new TypeError('Server recovery proof required');need(code);
 return make({...t,code,text:t.text[0]+code+t.text[1]});
}
const NOTIFY={
 requested:{subject:'OTPanda email recovery was requested',title:'Email recovery was requested',eyebrow:'Security notice',preheader:'Email recovery was requested for your OTPanda account.',
  intro:['Email recovery was requested for your OTPanda account. If nobody cancels it, it can be completed after 7 days.','Completing it removes every old passkey, device key, session and automation token.'],
  warning:'If this was not you, open OTPanda on a device signed in with a passkey and cancel the request or turn the setting off.',
  text:'Email recovery was requested for your OTPanda account. If nobody cancels it, it can be completed after 7 days. Completing it removes every old passkey, device key, session and automation token. If this was not you, open OTPanda on a device signed in with a passkey and cancel the request or turn the setting off.'},
 canceled:{subject:'OTPanda email recovery was canceled',title:'Email recovery was canceled',eyebrow:'Security notice',preheader:'The email recovery request for your OTPanda account was canceled.',
  intro:['The email recovery request for your OTPanda account was canceled.'],
  text:'The email recovery request for your OTPanda account was canceled.'},
 completed:{subject:'OTPanda email recovery was completed',title:'Email recovery was completed',eyebrow:'Security notice',preheader:'Email recovery was completed for your OTPanda account.',
  intro:['Email recovery was completed for your OTPanda account.','Every old passkey, device key, session and automation token was removed and a new passkey was added. Your codes, shares and linked Google account were kept.'],
  warning:'If this was not you, contact support right away.',
  text:'Email recovery was completed for your OTPanda account. Every old passkey, device key, session and automation token was removed and a new passkey was added. Your codes, shares and linked Google account were kept. If this was not you, contact support right away.'},
};
export function notificationEmail(kind){
 const t=Object.hasOwn(NOTIFY,kind)?NOTIFY[kind]:undefined;if(!t)throw new TypeError('Server notification required');
 return make({...t,outro:[]});
}
