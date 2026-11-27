// Plan gate: ALWAYS CLOSED until a supported live proof of the Workers/D1 plan exists. Runs before any scratch resource is created.
// Why: the documented Subscriptions API (GET /accounts/{id}/subscriptions, needs Billing Read) documents rate_plan.id (an enum starting free, lite, pro,
// plus free-form strings), rate_plan.public_name, rate_plan.scope, state and frequency, but documents NO identifier that says "Workers Free" or
// "Workers Paid". Inferring a tier from names would be a guess, so this script reports only the documented fields (for the operator) and exits 1.
// Replace it with a supported proof (for example a dashboard-confirmed attestation recorded by the owner) before dispatching. It never creates anything.
const id = process.env.CLOUDFLARE_ACCOUNT_ID, token = process.env.CLOUDFLARE_API_TOKEN;
if (id && token) {
  try {
    const res = await fetch('https://api.cloudflare.com/client/v4/accounts/' + id + '/subscriptions', { headers: { Authorization: 'Bearer ' + token } });
    const body = await res.json().catch(() => undefined);
    if (res.ok && body?.success === true && Array.isArray(body.result)) {
      console.log('Documented subscription fields (diagnostic only): ' + JSON.stringify(body.result.map(s => ({ plan: s?.rate_plan?.id, name: s?.rate_plan?.public_name, scope: s?.rate_plan?.scope, state: s?.state }))));
    } else console.log('Subscriptions API did not answer usably, HTTP ' + res.status);
  } catch { console.log('Subscriptions API unreachable'); }
}
console.error('Plan gate closed: no supported live Workers/D1 plan proof is implemented. No resources were created.');
process.exit(1);
