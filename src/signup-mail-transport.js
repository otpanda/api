// Exact signup template and bounded transport composition. Internal/unmounted.
// Credential and sender configuration remain server-only. No marketing/source
// ingestion and no arbitrary message body accepted from an HTTP client.
import{BrevoMailTransport}from'./brevo-mail.js';
export function createSignupMailDelivery(configuration){
 const transport=new BrevoMailTransport(configuration);
 return async function deliver(proof){
  if(!proof||proof.kind!=='signup-email'||!/^otpda_[A-Za-z0-9_-]{55}$/.test(proof.token)||!Number.isSafeInteger(proof.expiresAt))throw new TypeError('Server signup proof required');
  return transport.submit({to:proof.to,subject:'Verify your email for OTPanda',text:'Your OTPanda signup code is:\n\n'+proof.token+'\n\nReturn to the same browser where you started signup and paste this code. It expires ten minutes after it was requested. If you did not request this, ignore this email. No account is created until you choose and verify a passkey.'});
 };
}
