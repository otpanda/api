// Exact recovery mail templates over the existing bounded Brevo transport.
// Server-only: the HTTP client never supplies a subject, body or recipient.
import{BrevoMailTransport}from'./brevo-mail.js';
const KINDS={
 'recovery-request':['OTPanda email recovery request','Someone asked to start email recovery for your OTPanda account. Your code is:\n\n','\n\nEnter it in the OTPanda app where you started. Entering it only starts a 7 day wait. It does not sign anyone in and does not give access to your codes. If this was not you, ignore this email and open OTPanda on a device signed in with a passkey and cancel the request or turn the setting off.'],
 'recovery-complete':['OTPanda email recovery code','Your 7 day email recovery wait is over. Your code is:\n\n','\n\nEnter it in the OTPanda app where you started, then create a NEW passkey. Finishing removes every old passkey, device key, session and automation token from this account. Your codes, shares and linked Google account are kept. If this was not you, ignore this email.'],

 'notify-requested':['OTPanda email recovery was requested','Email recovery was requested for your OTPanda account. If nobody cancels it, it can be completed after 7 days. Completing it removes every old passkey, device key, session and automation token. If this was not you, open OTPanda on a device signed in with a passkey and cancel the request or turn the setting off.',''],
 'notify-canceled':['OTPanda email recovery was canceled','The email recovery request for your OTPanda account was canceled.',''],
 'notify-completed':['OTPanda email recovery was completed','Email recovery was completed for your OTPanda account. Every old passkey, device key, session and automation token was removed and a new passkey was added. Your codes, shares and linked Google account were kept. If this was not you, contact support right away.',''],
};
export function createRecoveryNotificationDelivery(configuration){
 const transport=new BrevoMailTransport(configuration);
 return async function deliver({kind,to}){const t=KINDS['notify-'+kind];if(!t||typeof to!=='string')throw new TypeError('Server notification required');return transport.submit({to,subject:t[0],text:t[1]});};
}
export function createRecoveryMailDelivery(configuration){
 const transport=new BrevoMailTransport(configuration);
 return async function deliver(proof){
  const t=proof&&KINDS[proof.kind];
  if(!t||!/^[A-HJ-NP-Z2-9]{8}$/.test(proof.code)||!Number.isSafeInteger(proof.expiresAt))throw new TypeError('Server recovery proof required');
  return transport.submit({to:proof.to,subject:t[0],text:t[1]+proof.code+t[2]});
 };
}
