// Exact website matching only. These are not email/SMS sender rules and do not grant code access.
export function normalizeWebsiteDomain(value){
 if(typeof value!=='string'||value.length>253||value!==value.trim())throw new TypeError('Exact public hostname required');
 const h=value.toLowerCase();
 if(!/^[a-z0-9-]+(?:\.[a-z0-9-]+)+$/.test(h)||h.split('.').some(p=>p.length>63||p.startsWith('-')||p.endsWith('-'))||/^[0-9.]+$/.test(h)||['.local','.localhost','.internal'].some(s=>h.endsWith(s)))throw new TypeError('Exact public hostname required');
 return h;
}
export function normalizeWebsiteDomains(values){
 if(!Array.isArray(values)||values.length>32)throw new TypeError('At most 32 exact domains');
 return [...new Set(values.map(normalizeWebsiteDomain))].sort();
}
export function websiteEligible(site,listed=[],personal=[]){
 try{const u=new URL(site);if(u.protocol!=='https:'||u.username||u.password||u.port)return false;const host=normalizeWebsiteDomain(u.hostname);return [...normalizeWebsiteDomains(listed),...normalizeWebsiteDomains(personal)].includes(host);}catch{return false;}
}
