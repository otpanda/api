// Read-only metadata check. Never writes billing or prints credentials/account data.
const account=process.env.CLOUDFLARE_ACCOUNT_ID,token=process.env.CLOUDFLARE_API_TOKEN;
const r=await fetch(`https://api.cloudflare.com/client/v4/accounts/${account}/subscriptions`,{headers:{Authorization:`Bearer ${token}`}});
const j=await r.json();
if(!r.ok||!j.success){console.log(JSON.stringify({planVerification:'unavailable',httpStatus:r.status}));}
else{const workers=(j.result??[]).filter(x=>/workers/i.test(x.rate_plan?.public_name??x.rate_plan?.id??''));console.log(JSON.stringify({planVerification:workers.length?'subscription-found':'no-workers-subscription-returned',plans:workers.map(x=>({name:x.rate_plan?.public_name??null,id:x.rate_plan?.id??null}))}));}
