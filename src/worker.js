const headers = {
  'Content-Type': 'application/json; charset=utf-8',
  'Cache-Control': 'no-store',
  'X-Content-Type-Options': 'nosniff',
};
// Deliberately inert until authentication, authorization, encryption and rate limits exist.
export default {
  async fetch(request) {
    const url = new URL(request.url);
    if (url.pathname === '/health' && request.method === 'GET') {
      return Response.json({ service: 'otpanda-api', status: 'foundation-only' }, { headers });
    }
    if (url.pathname.startsWith('/v1/')) {
      return Response.json({ error: 'not_implemented' }, { status: 501, headers });
    }
    return Response.json({ error: 'not_found' }, { status: 404, headers });
  },
};
