// Isolated synthetic Worker for the seed-sync qualification. Never imported by production.
// One POST /<prefix>/run executes the checks once against the temporary D1 database, per group, then refuses a replay of that group.
import { runChecks, GROUPS } from './checks.js';
const used = new Set();
export default {
  async fetch(request, env) {
    const u = new URL(request.url), prefix = '/' + env.FIXTURE_PREFIX;
    if (u.pathname === prefix + '/ready' && request.method === 'GET') return Response.json({synthetic:true, ready:true});
    if (u.pathname !== prefix + '/run' || request.method !== 'POST') return new Response(null, { status: 404 });
    const group = u.searchParams.get('group');
    if (!GROUPS.includes(group)) return new Response(null, { status: 400 });
    if (used.has(group)) return new Response(null, { status: 409 });
    used.add(group);
    try { return Response.json(await runChecks(env.DB, group)); }
    catch (e) { return Response.json({ synthetic: true, pass: false, fatal: String(e?.message ?? e).slice(0, 400) }, { status: 500 }); }
  }
};
