// Shared authentication-method predicates for persistent device sessions.
// A session proves exactly one method: a passkey credential or a linked
// Google identity. Every session reader uses these fragments so a revoked
// credential or provider link ends the session regardless of method.
// Fragments assume aliases d (device_sessions) and bind no parameters.
export const SESSION_METHOD_JOIN='LEFT JOIN passkey_credentials p ON p.credential_id=d.credential_id LEFT JOIN provider_identities g ON g.identity_id=d.provider_identity_id';
export const SESSION_METHOD_ACTIVE='((d.credential_id IS NOT NULL AND p.credential_id IS NOT NULL AND p.revoked_at IS NULL AND p.owner_id=d.owner_id) OR (d.provider_identity_id IS NOT NULL AND g.identity_id IS NOT NULL AND g.revoked_at IS NULL AND g.owner_id=d.owner_id))';
// Proof method at issue time. Existing proofs without authMethod are passkeys.
// A Google proof carries no credential. Mixed or partial proofs are rejected.
export function proofMethod(proof){
 if(!proof)return undefined;
 const m=proof.authMethod??'passkey';
 if(m==='passkey'){
  if(typeof proof.credentialId!=='string'||proof.issuer!==undefined||proof.subject!==undefined)return undefined;
  return {credentialId:proof.credentialId,issuer:null,subject:null};
 }
 if(m==='google'){
  if(proof.credentialId!==undefined||typeof proof.issuer!=='string'||!proof.issuer||typeof proof.subject!=='string'||!proof.subject)return undefined;
  return {credentialId:null,issuer:proof.issuer,subject:proof.subject};
 }
 return undefined;
}
// Insert-time pieces. cred/iss/sub/owner/gen are SQL placeholders such as '?3'.
// Google resolves the link row inside the write: same owner, not revoked, and
// its stable issuer/subject is active. Later provider email drift never moves
// an owner or silently changes its verified account email.
export function methodInsert({cred,iss,sub,owner,gen}){
 const link=`(SELECT g.identity_id FROM provider_identities g WHERE ${cred} IS NULL AND g.issuer=${iss} AND g.subject=${sub} AND g.owner_id=${owner} AND g.revoked_at IS NULL)`;
 const passkey=`(${cred} IS NOT NULL AND EXISTS (SELECT 1 FROM passkey_credentials p WHERE p.credential_id=${cred} AND p.owner_id=${owner} AND p.revoked_at IS NULL))`;
 return {
  providerColumn:link,
  guard:`EXISTS (SELECT 1 FROM account_security s WHERE s.owner_id=${owner} AND s.generation=${gen}) AND (${passkey} OR ${link} IS NOT NULL)`,
 };
}
