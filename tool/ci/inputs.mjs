// Validates workflow_dispatch inputs before any Cloudflare call. Env in: IN_CONFIRM, IN_SHA, GITHUB_SHA.
const E=process.env,bad=m=>{console.error('INPUT REJECTED:',m);process.exit(1);};
if(E.IN_CONFIRM!=='read-only-preflight')bad('confirmation must be read-only-preflight');
if(!/^[0-9a-f]{40}$/.test(E.IN_SHA||'')||E.IN_SHA!==E.GITHUB_SHA)bad('expected_sha must equal the dispatched commit');
console.log('inputs ok');
