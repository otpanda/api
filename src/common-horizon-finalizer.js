// Pure response invariant preparation only. No route activation, secrets, numeric cap defaults or authorization substitute.
export function finalizeCommonHorizon({requestedIds,entries,omitted=[],coverageUntil,nowMs,minRemainingMs,policy}){
 if(!Array.isArray(requestedIds)||new Set(requestedIds).size!==requestedIds.length||!Array.isArray(entries)||!Array.isArray(omitted)||!Number.isSafeInteger(nowMs)||nowMs<0||!Number.isSafeInteger(minRemainingMs)||minRemainingMs<1||!policy||typeof policy.validEntry!=='function')throw new TypeError('Invalid explicit response configuration');
 const asked=new Set(requestedIds),seen=new Set(),out=[],missing=[];
 const see=id=>{if(!asked.has(id)||seen.has(id))throw new TypeError('Unknown or duplicate response entry');seen.add(id);};
 for(const o of omitted){see(o.entryId);missing.push({entryId:o.entryId,reason:o.reason==='period_too_short'?'period_too_short':'unavailable'});}
 let totalCodes=0;
 for(const e of entries){
  see(e.entryId);
  if(!policy.validEntry(e))throw new TypeError('Invalid generated code shape');
  let drop=0;while(drop<e.codes.length&&(e.validFrom+(drop+1)*e.period)*1000<=nowMs)drop++;
  const validFrom=e.validFrom+drop*e.period,codes=e.codes.slice(drop),tail=(validFrom+codes.length*e.period)*1000;
  if(!codes.length||validFrom*1000>nowMs||(validFrom+e.period)*1000<=nowMs||!Number.isSafeInteger(tail)||tail<coverageUntil)return {status:'expired'};
  totalCodes+=codes.length;if(totalCodes>policy.budget)throw new RangeError('Total code budget exceeded');
  out.push({entryId:e.entryId,period:e.period,digits:e.digits,validFrom,codes});
 }
 for(const id of requestedIds)if(!seen.has(id))throw new TypeError('Missing explicit entry result');
 if(!out.length){if(coverageUntil!==null)throw new TypeError('Empty coverage must be null');return {status:'ok',serverNow:nowMs,coverageUntil:null,totalCodes:0,entries:[],omitted:missing};}
 if(!Number.isSafeInteger(coverageUntil)||coverageUntil-nowMs<minRemainingMs)return {status:'expired'};
 return {status:'ok',serverNow:nowMs,coverageUntil,totalCodes,entries:out,omitted:missing};
}
