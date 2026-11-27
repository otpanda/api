// Isolated synthetic Worker for the transfer qualification. Never imported by production.
// One POST /<prefix>/run executes the checks once against the temporary D1 database, then refuses further runs.
import { runChecks } from './checks.js';
let used = false;
export default {
  async fetch(request, env) {
    const u = new URL(request.url), prefix = '/' + env.FIXTURE_PREFIX;
    if (u.pathname !== prefix + '/run' || request.method !== 'POST') return new Response(null, { status: 404 });
    if (used) return new Response(null, { status: 409 });
    used = true;
    try { return Response.json(await runChecks(env.DB)); }
    catch (e) { return Response.json({ synthetic: true, pass: false, fatal: String(e?.message ?? e).slice(0, 400) }, { status: 500 }); }
  }
};
