// Narrow cleanup only. Uses the existing token, never changes its permissions.
const name=process.env.QUALIFICATION_NAME,account=process.env.CLOUDFLARE_ACCOUNT_ID;
if(!/^otpanda-realtime-qualification-[0-9]+$/.test(name||''))throw Error('isolated name required');
if(account!=='a04834f19f0dfd5dc4eb47515d15478d')throw Error('unexpected account');
const response=await fetch('https://api.cloudflare.com/client/v4/accounts/'+account+'/workers/scripts/'+name+'?force=true',{method:'DELETE',headers:{authorization:'Bearer '+process.env.CLOUDFLARE_API_TOKEN},signal:AbortSignal.timeout(20000)});
if(!response.ok&&response.status!==404)throw Error('Temporary Worker deletion failed '+response.status);
console.log(JSON.stringify({temporaryWorkerDeleteStatus:response.status}));
