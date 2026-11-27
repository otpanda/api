// Deletes the temporary Worker named in qualification/seed-sync-upgrade/wrangler.json and proves absence (404). Needs CLOUDFLARE_* env.
import { readFileSync } from 'node:fs';
const name = JSON.parse(readFileSync('qualification/seed-sync-upgrade/wrangler.json', 'utf8')).name;
if (!/^otpanda-seed-sync-upgrade-qual-[0-9]+$/.test(name)) throw Error('Refusing to delete a Worker that is not a per-run seed-sync-upgrade qualification Worker');
const root = 'https://api.cloudflare.com/client/v4/accounts/' + process.env.CLOUDFLARE_ACCOUNT_ID + '/workers/scripts/' + name;
const headers = { Authorization: 'Bearer ' + process.env.CLOUDFLARE_API_TOKEN };
const response = await fetch(root, { method: 'DELETE', headers });
if (!response.ok && response.status !== 404) throw Error('Temporary Worker delete HTTP ' + response.status);
const verify = await fetch(root, { headers });
console.log(JSON.stringify({ temporaryWorkerDeleteStatus: response.status, absenceStatus: verify.status }));
if (verify.status !== 404) throw Error('Temporary Worker absence not established');
