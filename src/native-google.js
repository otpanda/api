// Native Google sign-in (Android Credential Manager, google flavor only). Fails closed: with no configured
// audience nothing verifies. Policy is the existing Google account policy: this path completes ONLY the
// simple cases (an already linked identity, or a brand new account) and only when the owner has no
// "extra verification on new devices" protection. Every other case returns browser_required and creates nothing.
import {generateAccessToken,parseAccessToken,digestSecret,digestToHex} from './tokens.js';
import {googleEmailEvidence} from './account-identity.js';
import {GoogleAccountService} from './google-account.js';
import {importRenewalKey} from './access-renewal.js';
import {FirstPasskeyEnrollment} from './first-passkey-enrollment.js';
import {hashText} from './sessions.js';
const ISS=new Set(['https://accounts.google.com','accounts.google.com']),NONCE_TTL=300_000,LEEWAY=60_000,MAX_TOKEN=8192;
const b64=t=>{if(typeof t!=='string'||!/^[A-Za-z0-9_-]+$/.test(t)||t.length%4===1)throw new TypeError('b64');const b=atob(t.replace(/-/g,'+').replace(/_/g,'/'));return Uint8Array.from(b,c=>c.charCodeAt(0));};
const segment=s=>{try{const bytes=b64(s);return JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{return undefined;}};
// getKey(kid) returns a public RSA JWK (kty RSA, n, e) or undefined. Production supplies Google's JWKS fetch; tests inject.
export async function verifyGoogleIdToken({token,audiences,getKey,now,authorizedParties=[]}){
 try{
  if(typeof token!=='string'||token.length>MAX_TOKEN||!Array.isArray(audiences)||!audiences.length||typeof getKey!=='function'||!Number.isSafeInteger(now))return undefined;
  const parts=token.split('.');if(parts.length!==3)return undefined;
  const header=segment(parts[0]),claims=segment(parts[1]);
  if(!header||!claims||header.alg!=='RS256'||typeof header.kid!=='string'||header.kid.length>128||header.crit!==undefined)return undefined;
  const jwk=await getKey(header.kid);if(!jwk||jwk.kty!=='RSA'||typeof jwk.n!=='string'||typeof jwk.e!=='string')return undefined;
  const key=await crypto.subtle.importKey('jwk',{kty:'RSA',n:jwk.n,e:jwk.e,alg:'RS256',ext:true},{name:'RSASSA-PKCS1-v1_5',hash:'SHA-256'},false,['verify']);
  const sig=b64(parts[2]);
  if(!await crypto.subtle.verify('RSASSA-PKCS1-v1_5',key,sig,new TextEncoder().encode(parts[0]+'.'+parts[1])))return undefined;
  if(!ISS.has(claims.iss))return undefined;
  const aud=Array.isArray(claims.aud)?claims.aud:[claims.aud];
  if(!aud.length||!aud.every(a=>typeof a==='string')||!aud.some(a=>audiences.includes(a)))return undefined;
  if(aud.length>1&&!audiences.includes(claims.azp))return undefined;
  // Optional presenter pin (the Android OAuth client ids). Configured means azp must be present and listed; unset means no pin.
  if(authorizedParties.length&&!authorizedParties.includes(claims.azp))return undefined;
  if(!Number.isSafeInteger(claims.exp)||claims.exp*1000<=now-0||!Number.isSafeInteger(claims.iat)||claims.iat*1000>now+LEEWAY)return undefined;
  if(typeof claims.nonce!=='string'||typeof claims.sub!=='string'||typeof claims.email!=='string'||claims.email_verified!==true)return undefined;
  return {...claims,iss:'https://accounts.google.com'};
 }catch{return undefined;}
}
const bind=renewalKey=>'native-google-v1:'+renewalKey;
export class NativeGoogle{
 constructor(db,{native,audiences=[],authorizedParties=[],getKey,clock=Date.now,accounts=new GoogleAccountService(db,{clock}),enrollment=new FirstPasskeyEnrollment(db,{clock}),continuations}={}){
  Object.assign(this,{db,native,enrollment,continuations,audiences:audiences.filter(a=>typeof a==='string'&&a.endsWith('.apps.googleusercontent.com')),authorizedParties:authorizedParties.filter(a=>typeof a==='string'&&a.endsWith('.apps.googleusercontent.com')),getKey,clock,accounts});
 }
 get configured(){return this.audiences.length>0&&typeof this.getKey==='function';}
 now(){const n=this.clock();if(!Number.isSafeInteger(n)||n<0)throw new TypeError('Valid instant required');return n;}
 async begin(){
  if(!this.configured)return undefined;
  const s=generateAccessToken(),now=this.now();
  await this.db.prepare('INSERT INTO native_google_nonces (nonce_id,secret_digest,created_at,expires_at) VALUES (?1,?2,?3,?4)').bind(s.tokenId,digestToHex(await digestSecret(s.secret)),now,now+NONCE_TTL).run();
  return {nonce:s.token,expiresAt:now+NONCE_TTL};
 }
 // status: ok | browser_required | denied | unavailable
 async complete({idToken,renewalKey,recognition,remember}){
  if(!this.configured)return {status:'unavailable'};
  if(!await importRenewalKey(renewalKey))return {status:'denied'};
  const now=this.now(),claims=await verifyGoogleIdToken({token:idToken,audiences:this.audiences,authorizedParties:this.authorizedParties,getKey:this.getKey,now});if(!claims)return {status:'denied'};
  const n=parseAccessToken(claims.nonce);if(!n)return {status:'denied'};
  // One use, claimed before any account effect. A failed later step does not return the nonce.
  const claimed=await this.db.prepare('DELETE FROM native_google_nonces WHERE nonce_id=?1 AND secret_digest=?2 AND created_at<=?3 AND expires_at>?3 RETURNING nonce_id').bind(n.tokenId,digestToHex(await digestSecret(n.secret)),now).first();
  if(!claimed)return {status:'denied'};
  let identity;try{identity=googleEmailEvidence(claims);}catch{return {status:'denied'};}
  const account=await this.accounts.resolve(identity);
  if(account?.status==='existing-account'&&typeof this.continuations==='function'){
   // The Google subject is not linked yet but this mailbox already has an account: same pending link the web uses. It is bound to this
   // install's renewal key, owner-bound, and only a fresh passkey step-up for that owner can link and sign in.
   const c=await this.cont(),pending=c?await c.create({identity,appState:'native',challenge:'',binding:bind(renewalKey),remember:remember===true}).catch(()=>undefined):undefined;
   return pending&&pending.kind==='link'?{status:'continue_required',continuation:{token:pending.token,email:pending.email,expiresAt:pending.expiresAt}}:{status:'browser_required'};
  }
  if(!account||!['linked','created'].includes(account.status))return {status:'browser_required'};
  return this.issue({account,identity,renewalKey,recognition,remember,verifiedAt:now});
 }
 async issue({account,identity,renewalKey,recognition,remember,strong=false,verifiedAt}){
  // Same recognition model as web: a presented token counts only for this owner, generation and Google link; remember mints one unless a valid one exists.
  let recog;const parsed=recognition===undefined?undefined:parseAccessToken(recognition);
  if(parsed)recog={id:parsed.tokenId,digest:digestToHex(await digestSecret(parsed.secret))};
  const valid=recog?await this.db.prepare('SELECT 1 x FROM recognized_browsers r JOIN provider_identities g ON g.identity_id=r.provider_identity_id WHERE r.recognition_id=?1 AND r.secret_digest=?2 AND r.owner_id=?3 AND r.generation=?4 AND r.revoked_at IS NULL AND g.revoked_at IS NULL AND g.issuer=?5 AND g.subject=?6').bind(recog.id,recog.digest,account.ownerId,account.generation,identity.issuer,identity.subject).first():null;
  let fresh;if(remember===true&&!valid){const t=generateAccessToken();fresh={id:t.tokenId,digest:digestToHex(await digestSecret(t.secret)),token:t.token};}
  const device=await this.native.issueProvider({ownerId:account.ownerId,generation:account.generation,issuer:identity.issuer,subject:identity.subject,renewalKey,recognition:valid?recog:undefined,newRecognition:fresh,strong});
  if(!device)return {status:'browser_required'};
  if(fresh&&device.recorded)device.recognition=fresh.token;
  // Optional first-method grant (Google-only account, 120 s, key possession only). Absent when any strong method already exists.
  const grant=await this.enrollment.issue({ownerId:account.ownerId,deviceId:device.deviceId,generation:account.generation,issuer:identity.issuer,subject:identity.subject,verifiedAt}).catch(()=>undefined);
  return {status:'ok',device:grant?{...device,enrollGrant:grant.token}:device};
 }

 // A missing or failing continuation factory (for example the code keyring is unavailable) disables the continue step only.
 async cont(){try{return typeof this.continuations==='function'?await this.continuations():undefined;}catch{return undefined;}}
 // Pending link validated: exists, owner-bound, not link-only, and created for THIS install's renewal key. Oracle-free (undefined for any miss).
 async pending(token,renewalKey){
  if(typeof this.continuations!=='function'||typeof token!=='string'||!await importRenewalKey(renewalKey))return undefined;
  const c=await this.cont(),q=c&&await c.read(token).catch(()=>undefined);
  if(!q||!q.data.ownerId||q.data.linkOnly||await hashText(bind(renewalKey))!==q.r.binding_digest)return undefined;
  return {c,q};
 }
 async continueBegin({token,renewalKey}){const p=await this.pending(token,renewalKey);return p?p.c.beginLink(token):undefined;}
 // Passkey step-up for this owner and this exact Google identity links it and (single use, 60 s) signs the install in. A fresh passkey proof is a strong method, so the new-device gate is not asked again.
 async continueFinish({token,renewalKey,ceremony,response,recognition}){
  const p=await this.pending(token,renewalKey);if(!p)return {status:'denied'};
  let ok=false;try{ok=await p.c.verify({token,ceremony,response});}catch{ok=false;}if(!ok)return {status:'denied'};
  const data=await p.c.consume({token,binding:bind(renewalKey)});if(!data?.ownerId)return {status:'denied'};
  const account=await this.accounts.resolve(data.identity);
  if(account?.status!=='linked'||account.ownerId!==data.ownerId||account.generation!==data.expectedGeneration)return {status:'denied'};
  const r=await this.issue({account,identity:data.identity,renewalKey,recognition,remember:data.remember===true,strong:true,verifiedAt:this.now()});
  return r.status==='ok'?r:{status:'denied'};
 }
}
