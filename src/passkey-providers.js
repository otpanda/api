// Display-only provider hints from the AAGUID an authenticator reports at registration. Self-reported, unattested: never say a passkey is
// verified or "stored in" a provider. Unknown, absent and all-zero AAGUIDs have no provider (the UI falls back to a generic name).
// Each id below was read from at least the sources named. Add only ids with a source.
//  Google Password Manager: https://web.dev/articles/webauthn-aaguid ; https://www.corbado.com/glossary/aaguid
//  Windows Hello (3): https://learn.microsoft.com/en-us/entra/identity/authentication/how-to-authentication-entra-passkeys-on-windows
//  1Password: https://www.1password.community/1password-at-home-31/how-does-an-app-know-that-the-passkey-is-saved-in-1password-11063
//  Bitwarden: https://jamesvincent.co.uk/2025/12/18/adding-a-bitwarden-synced-passkey-to-an-entra-id-account/
//  Apple Passwords (iCloud Keychain): aggregators only (https://www.corbado.com/glossary/aaguid ; https://aaguid.nicolasuter.ch/ ; https://mojoauth.com/blog/passkey-aaguid-password-manager-mapping)
const PROVIDERS=new Map([
 ['ea9b8d66-4d01-1d21-3ce4-b6b48cb575d4','Google Password Manager'],
 ['fbfc3007-154e-4ecc-8c0b-6e020557d7bd','Apple Passwords'],
 ['08987058-cadc-4b81-b6e1-30de50dcbe96','Windows Hello'],
 ['9ddd1817-af5a-4672-a2b9-3e3dd95000a9','Windows Hello'],
 ['6028b017-b1d4-4c02-b4b3-afcdafc96bb2','Windows Hello'],
 ['bada5566-a7aa-401f-bd96-45619a55120d','1Password'],
 ['d548826e-79b4-db40-a3d8-11116f7e8349','Bitwarden']
]);
const ZERO='00000000-0000-0000-0000-000000000000',UUID=/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
export function normalAaguid(value){const v=typeof value==='string'?value.toLowerCase():'';return UUID.test(v)&&v!==ZERO?v:null;}
export function providerName(aaguid){const v=normalAaguid(aaguid);return v?PROVIDERS.get(v)??null:null;}
// Labels: NFC, trimmed, 1..40 code points, no control, bidi or line separator characters. null or empty clears.
export function normalLabel(value,max=40){
 if(value===null||value==='')return null;if(typeof value!=='string')return undefined;
 const v=value.normalize('NFC').trim();if(!v||[...v].length>max||v.length>max)return undefined;
 return /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(v)?undefined:v;
}
// Metadata only: a failure never affects registration. Called after the credential row is committed.
export async function storeAaguid(db,{credentialId,ownerId,aaguid}){
 const v=normalAaguid(aaguid);if(!v)return;
 try{await db.prepare('INSERT INTO passkey_metadata(credential_id,owner_id,aaguid) SELECT ?1,?2,?3 WHERE EXISTS(SELECT 1 FROM passkey_credentials WHERE credential_id=?1 AND owner_id=?2) ON CONFLICT(credential_id) DO UPDATE SET aaguid=excluded.aaguid WHERE passkey_metadata.aaguid IS NULL').bind(credentialId,ownerId,v).run();}catch{}
}
