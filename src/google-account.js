// Account resolution after validated Google token evidence. Does not authorize
// sessions, merge accounts, or change an existing provider link.
import {canonicalAccountEmail,mailboxKey} from './account-identity.js';
export class GoogleAccountService {
 constructor(db,{clock=Date.now}={}){this.db=db;this.clock=clock;}
 async resolve(identity){
  if(identity?.issuer!=='https://accounts.google.com'||typeof identity.subject!=='string'||!identity.subject||identity.subject.length>255||typeof identity.authoritative!=='boolean')return;
  let email;try{email=canonicalAccountEmail(identity.email);}catch{return;}
  const existing=await this.db.prepare('SELECT i.owner_id,e.email,s.generation FROM provider_identities i JOIN account_emails e ON e.owner_id=i.owner_id JOIN account_security s ON s.owner_id=i.owner_id WHERE i.revoked_at IS NULL AND i.issuer=?1 AND i.subject=?2').bind(identity.issuer,identity.subject).first();
  if(existing)return {status:'linked',ownerId:existing.owner_id,generation:existing.generation};
  const legacy=await this.db.prepare('SELECT owner_id FROM identities WHERE issuer=?1 AND subject=?2').bind(identity.issuer,identity.subject).first();if(legacy)return {status:'legacy-account'};
  const owner=await this.db.prepare('SELECT owner_id FROM account_mailbox_keys WHERE mailbox_key=?1').bind(mailboxKey(email)).first();if(owner){const raced=await this.db.prepare('SELECT i.owner_id,s.generation FROM provider_identities i JOIN account_security s ON s.owner_id=i.owner_id WHERE i.revoked_at IS NULL AND i.issuer=?1 AND i.subject=?2 AND i.owner_id=?3').bind(identity.issuer,identity.subject,owner.owner_id).first();return raced?{status:'linked',ownerId:raced.owner_id,generation:raced.generation}:{status:'existing-account'};}
  // Product policy accepts the validated Google identity's verified-email
  // claim for new account signup, including external Google mailboxes.
  // Existing-email collisions above still require exact-owner linking proof.
  // Provider subject, never email, remains the login credential.
  const ownerId=crypto.randomUUID(),now=this.clock();if(!Number.isSafeInteger(now)||now<0)throw new TypeError('Valid instant required');
  try{
   await this.db.batch([
    this.db.prepare('INSERT INTO accounts(owner_id,created_at) VALUES(?1,?2)').bind(ownerId,now),
    this.db.prepare('INSERT INTO account_emails(owner_id,email,verified_at,updated_at) VALUES(?1,?2,?3,?3)').bind(ownerId,email,now),
    this.db.prepare('INSERT INTO account_security(owner_id) VALUES(?1)').bind(ownerId),
    this.db.prepare("INSERT INTO provider_identities(identity_id,owner_id,provider,issuer,subject,email,created_at) VALUES(?1,?2,'google',?3,?4,?5,?6)").bind(crypto.randomUUID(),ownerId,identity.issuer,identity.subject,email,now),
   ]);
   return{status:'created',ownerId,generation:0};
  }catch{
   // A concurrent unique-email or provider race creates no orphan owner.
   const linked=await this.db.prepare('SELECT i.owner_id,e.email,s.generation FROM provider_identities i JOIN account_emails e ON e.owner_id=i.owner_id JOIN account_security s ON s.owner_id=i.owner_id WHERE i.revoked_at IS NULL AND i.issuer=?1 AND i.subject=?2').bind(identity.issuer,identity.subject).first();
   if(linked)return {status:'linked',ownerId:linked.owner_id,generation:linked.generation};
   const row=await this.db.prepare('SELECT owner_id FROM account_mailbox_keys WHERE mailbox_key=?1').bind(mailboxKey(email)).first();return row?{status:'existing-account'}:undefined;
  }
 }
}
