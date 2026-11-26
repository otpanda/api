// Pure explicit policy. Caller supplies current shared route constraints; no production defaults.
export function responsePolicy({minPeriod,maxPeriod,digits,maxCodesPerEntry,budget}){
 if(!Number.isSafeInteger(minPeriod)||minPeriod<1||!Number.isSafeInteger(maxPeriod)||maxPeriod<minPeriod||!Array.isArray(digits)||!digits.length||new Set(digits).size!==digits.length||digits.some(d=>!Number.isSafeInteger(d)||d<1||d>16)||![maxCodesPerEntry,budget].every(n=>Number.isSafeInteger(n)&&n>0))throw new TypeError('Invalid explicit policy');
 const patterns=new Map(digits.map(d=>[d,new RegExp(`^\\d{${d}}$`)]));
 return Object.freeze({minPeriod,maxPeriod,maxCodesPerEntry,budget,validEntry(e){return e&&typeof e.entryId==='string'&&e.entryId.length>0&&Number.isSafeInteger(e.period)&&e.period>=minPeriod&&e.period<=maxPeriod&&patterns.has(e.digits)&&Number.isSafeInteger(e.validFrom)&&e.validFrom>=0&&e.validFrom%e.period===0&&Array.isArray(e.codes)&&e.codes.length>0&&e.codes.length<=maxCodesPerEntry&&e.codes.every(c=>typeof c==='string'&&patterns.get(e.digits).test(c));}});
}
export function validateResponse(r,ids,policy,{startOffsetMs=0}={}){
 if(!r||!Array.isArray(r.entries)||!Array.isArray(r.omitted)||!Number.isSafeInteger(r.serverNow)||r.serverNow<0||!Number.isSafeInteger(r.totalCodes)||r.totalCodes<0||r.totalCodes>policy.budget)return false;
 const wanted=new Set(ids),seen=new Set();let total=0;
 const take=id=>typeof id==='string'&&wanted.has(id)&&!seen.has(id)&&(seen.add(id),true);
 for(const o of r.omitted)if(!o||!take(o.entryId)||!['unavailable','period_too_short'].includes(o.reason))return false;
 for(const e of r.entries){
  if(!policy.validEntry(e)||!take(e.entryId))return false;
  const tail=(e.validFrom+e.codes.length*e.period)*1000;
  if(!Number.isSafeInteger(tail)||e.validFrom*1000>r.serverNow+startOffsetMs||(e.validFrom+e.period)*1000<=r.serverNow+startOffsetMs||tail<r.coverageUntil)return false;
  total+=e.codes.length;
 }
 return seen.size===wanted.size&&total===r.totalCodes&&(r.entries.length===0?r.coverageUntil===null:Number.isSafeInteger(r.coverageUntil)&&r.coverageUntil>r.serverNow+startOffsetMs);
}
