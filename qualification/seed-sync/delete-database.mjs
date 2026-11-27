import {readFileSync} from 'node:fs';
const conf=JSON.parse(readFileSync('qualification/seed-sync/wrangler.json','utf8'));
const id=process.argv[2];
if(!/^otpanda-seed-sync-qual-[0-9]+$/.test(conf.name)||conf.d1_databases[0].database_id!==id)throw Error('Refuse non-qualification database');
const root='https://api.cloudflare.com/client/v4/accounts/'+process.env.CLOUDFLARE_ACCOUNT_ID+'/d1/database/'+id;
const headers={Authorization:'Bearer '+process.env.CLOUDFLARE_API_TOKEN};
const before=await fetch(root,{headers});
if(before.ok){const data=await before.json();if(data.result?.name!==conf.name)throw Error('Database name mismatch');}
else if(before.status!==404)throw Error('Database lookup HTTP '+before.status);
const response=await fetch(root,{method:'DELETE',headers});
if(!response.ok&&response.status!==404)throw Error('Database delete HTTP '+response.status);
const verify=await fetch(root,{headers});
console.log(JSON.stringify({temporaryDatabaseDeleteStatus:response.status,absenceStatus:verify.status,databaseId:id}));
if(verify.status!==404)throw Error('Temporary database absence not established');
