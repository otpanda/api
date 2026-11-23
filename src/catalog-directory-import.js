// Pure offline adapter for a previously fetched 2FA Directory v3 JSON snapshot.
// This creates public metadata only, not OTP sender rules or verified evidence.
import {normalizeDomain} from './service-metadata.js';
const SOURCE='https://2fa.directory/api/v3/all.json',ATTRIBUTION='Data sourced from 2FA Directory by 2factorauth.';
export function importDirectoryV3(bytes,{fetchedAt,sha256}={}){
 if(!(bytes instanceof Uint8Array)||bytes.byteLength>4194304||!Number.isSafeInteger(fetchedAt)||fetchedAt<0||typeof sha256!=='string'||!/^[a-f0-9]{64}$/.test(sha256))throw new TypeError('Bounded snapshot and provenance required');
 let rows;try{rows=JSON.parse(new TextDecoder('utf-8',{fatal:true}).decode(bytes));}catch{throw new TypeError('Directory JSON required');}
 if(!Array.isArray(rows)||rows.length>5000)throw new TypeError('Bounded directory rows required');
 const services=new Map(),rejected=[];
 for(let index=0;index<rows.length;index++){
  const row=rows[index];
  if(!Array.isArray(row)||row.length!==2||typeof row[0]!=='string'||!row[0].trim()||row[0].length>120||/[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]/u.test(row[0])||!row[1]||typeof row[1]!=='object'||Array.isArray(row[1])){rejected.push(index);continue;}
  let domain;try{domain=normalizeDomain(row[1].domain);if(!domain.includes('.')||/^[0-9.]+$/.test(domain)||domain.endsWith('.local')||domain.endsWith('.localhost')||domain.endsWith('.internal'))throw new TypeError();}catch{rejected.push(index);continue;}
  const value={serviceId:domain,name:row[0].trim(),websiteHost:domain};
  if(services.has(domain)){if(JSON.stringify(services.get(domain))!==JSON.stringify(value))throw new TypeError('Conflicting directory service identity');continue;}
  services.set(domain,value);
 }
 // Records are partitioned into bounded engine snapshots; nothing is silently
 // dropped to fit the engine cap. Ignore contacts, support addresses, notes,
 // documentation and alternate domains, none establishes an OTP sender.
 const all=[...services.values()].sort((a,b)=>a.serviceId<b.serviceId?-1:a.serviceId>b.serviceId?1:0),shards=[];
 for(let i=0;i<all.length;i+=1000)shards.push({services:all.slice(i,i+1000),mappings:[]});
 return {provenance:{sourceUrl:SOURCE,format:'2fa-directory-v3',fetchedAt,sha256,license:'MIT',attribution:ATTRIBUTION,signatureVerified:false},count:all.length,rejectedRowIndexes:rejected,shards};
}
