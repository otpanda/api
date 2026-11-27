// Exact recovery mail templates over the existing bounded Brevo transport.
// Server-only: the HTTP client never supplies a subject, body or recipient.
import{BrevoMailTransport}from'./brevo-mail.js';
import{recoveryEmail,notificationEmail}from'./email-templates.js';
const KINDS={'recovery-request':1,'recovery-complete':1};
const NOTIFY=new Set(['requested','canceled','completed','seed-sync-enrolled']);
export function createRecoveryNotificationDelivery(configuration){
 const transport=new BrevoMailTransport(configuration);
 return async function deliver({kind,to}){if(!NOTIFY.has(kind)||typeof to!=='string')throw new TypeError('Server notification required');return transport.submit({to,...notificationEmail(kind)});};
}
export function createRecoveryMailDelivery(configuration){
 const transport=new BrevoMailTransport(configuration);
 return async function deliver(proof){
  if(!proof||!Object.hasOwn(KINDS,proof.kind)||!/^[A-HJ-NP-Z2-9]{8}$/.test(proof.code)||!Number.isSafeInteger(proof.expiresAt))throw new TypeError('Server recovery proof required');
  return transport.submit({to:proof.to,...recoveryEmail(proof.kind,proof.code)});
 };
}
