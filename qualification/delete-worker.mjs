const root='https://api.cloudflare.com/client/v4/accounts/'+process.env.CLOUDFLARE_ACCOUNT_ID+'/workers/scripts/otpanda-batch-qualification';
const headers={Authorization:'Bearer '+process.env.CLOUDFLARE_API_TOKEN};
const response=await fetch(root,{method:'DELETE',headers});
if(!response.ok&&response.status!==404)throw Error('Temporary Worker delete HTTP '+response.status);
const verify=await fetch(root,{headers});
console.log(JSON.stringify({temporaryWorkerDeleteStatus:response.status,absenceStatus:verify.status}));
if(verify.status!==404)throw Error('Temporary Worker absence not established');
