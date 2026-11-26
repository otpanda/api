// Pure planning only. No defaults are selected or qualified here.
const integer=(v,min=1)=>Number.isSafeInteger(v)&&v>=min;
export function maxCodesPerEntry({maxWindow,minPeriod}){
 if(!integer(maxWindow)||!integer(minPeriod)||!Number.isSafeInteger(maxWindow+minPeriod-1))throw new TypeError('Invalid explicit bound configuration');
 return Math.ceil((maxWindow+minPeriod-1)/minPeriod);
}
export function planCommonHorizon({now,periods,requestedWindow,maxWindow,budget,entryCap,minPeriod,maxPeriod=86400,minUsefulWindow}){
 if(!integer(now,0)||!Array.isArray(periods)||!integer(entryCap)||!integer(minPeriod)||!integer(maxPeriod)||maxPeriod<minPeriod||!integer(requestedWindow)||!integer(maxWindow)||!integer(minUsefulWindow)||minUsefulWindow>maxWindow||!integer(budget)||budget<entryCap)throw new TypeError('Invalid explicit planning configuration');
 if(periods.length>entryCap)throw new RangeError('Entry cap exceeded');
 if(periods.some(p=>!integer(p)||p<minPeriod||p>maxPeriod))throw new TypeError('Unsupported eligible period');
 const worstFloorPerEntry=Math.ceil((minUsefulWindow-1)/minPeriod)+1;
 if(worstFloorPerEntry>Math.floor(budget/entryCap))throw new RangeError('Configuration cannot guarantee useful floor');
 const perEntryMaximum=maxCodesPerEntry({maxWindow,minPeriod});
 const window=Math.min(requestedWindow,maxWindow);
 if(!Number.isSafeInteger(now+window)||!Number.isSafeInteger((now+window)*1000))throw new RangeError('Unsafe horizon');
 if(!periods.length)return {coverageUntil:null,actualWindowSeconds:0,totalCodes:0,counts:[]};
 const starts=periods.map(p=>Math.floor(now/p)*p);
 const countsAt=h=>periods.map((p,i)=>Math.floor((h-starts[i]-1)/p)+1);
 const fits=h=>{let total=0;for(let i=0;i<periods.length;i++){const n=Math.floor((h-starts[i]-1)/periods[i])+1;if(n>budget-total)return false;total+=n;}return true;};
 let low=now+1,high=now+window;
 while(low<high){const mid=low+Math.ceil((high-low)/2);if(fits(mid))low=mid;else high=mid-1;}
 const counts=countsAt(low),totalCodes=counts.reduce((a,b)=>a+b,0);
 if(counts.some(n=>n>perEntryMaximum))throw new RangeError('Derived per-entry bound violated');
 return {coverageUntil:low*1000,actualWindowSeconds:low-now,totalCodes,counts};
}
