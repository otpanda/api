// Inactive new-browser key import only. Does not initialize legacy OIDC/runtime,
// generate secrets or retain enumerable raw key material.
import{base64urlDecode}from'./tokens.js';
const ID=/^[A-Za-z0-9_-]{1,64}$/;
export async function importBrowserKeyring({ENCRYPTION_KEYRING,ACTIVE_KEY_ID}={}){
 if(typeof ACTIVE_KEY_ID!=='string'||!ID.test(ACTIVE_KEY_ID)||typeof ENCRYPTION_KEYRING!=='string'||ENCRYPTION_KEYRING.length>4096)throw new TypeError('Browser key configuration unavailable');
 let rows;try{rows=JSON.parse(ENCRYPTION_KEYRING);}catch{throw new TypeError('Browser key configuration unavailable');}
 if(!Array.isArray(rows)||rows.length<1||rows.length>8)throw new TypeError('Browser key configuration unavailable');
 const keys=new Map();for(const row of rows){if(!row||Array.isArray(row)||Object.keys(row).sort().join(',')!=='id,key'||typeof row.id!=='string'||!ID.test(row.id)||keys.has(row.id))throw new TypeError('Browser key configuration unavailable');const raw=base64urlDecode(row.key,32);if(!raw)throw new TypeError('Browser key configuration unavailable');try{keys.set(row.id,await crypto.subtle.importKey('raw',raw,{name:'AES-GCM'},false,['encrypt','decrypt']));}finally{raw.fill(0);}}
 if(!keys.has(ACTIVE_KEY_ID))throw new TypeError('Browser key configuration unavailable');
 return{keys,activeKeyId:ACTIVE_KEY_ID};
}
