// Standards-based authorization-code + S256 PKCE sign-in. No mailbox scopes,
// refresh tokens, email-based linking or user-selected identity providers.
import * as oauth from 'oauth4webapi';
import { generateAccessToken } from './tokens.js';
import { ownerForIdentity, hashText, readCookie, cookie, json, LOGIN_COOKIE, LOGIN_TTL, securityHeaders } from './sessions.js';

export function createOidcSignIn({ db, sessions, cipher, server, client, clientAuthentication, clock = Date.now, oauthOptions = {} }) {
  if (!server?.issuer?.startsWith('https://') || !client?.client_id || !server.authorization_endpoint || !server.token_endpoint || !server.jwks_uri) throw new TypeError('Pinned OIDC metadata and registered client required');
  for (const name of ['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri']) if (new URL(server[name]).protocol !== 'https:') throw new TypeError('HTTPS OIDC endpoints required');
  const redirectUri = sessions.origin + '/auth/callback';
  const context = (id, createdAt, expiresAt) => ({ ownerId: 'oauth-transaction', recordId: id, serviceId: server.issuer, receivedAt: createdAt, expiresAt });
  return {
    async start(request) {
      if (request.method !== 'POST' || new URL(request.url).origin !== sessions.origin || request.headers.get('origin') !== sessions.origin) return json({ error: 'forbidden' }, 403);
      const state = oauth.generateRandomState();
      const binding = generateAccessToken().token;
      const verifier = oauth.generateRandomCodeVerifier();
      const nonce = oauth.generateRandomNonce();
      const now = clock();
      const stateDigest = await hashText(state);
      const envelope = await cipher.encrypt(JSON.stringify({ verifier, nonce }), context(stateDigest, now, now + LOGIN_TTL));
      await db.prepare('INSERT INTO oauth_transactions (state_digest, binding_digest, envelope, created_at, expires_at) VALUES (?1, ?2, ?3, ?4, ?5)')
        .bind(stateDigest, await hashText(binding), JSON.stringify(envelope), now, now + LOGIN_TTL).run();
      const target = new URL(server.authorization_endpoint);
      target.search = new URLSearchParams({ client_id: client.client_id, response_type: 'code', redirect_uri: redirectUri, scope: 'openid', state, nonce, code_challenge: await oauth.calculatePKCECodeChallenge(verifier), code_challenge_method: 'S256' }).toString();
      return new Response(null, { status: 303, headers: { ...securityHeaders, Location: target.href, 'Set-Cookie': cookie(LOGIN_COOKIE, binding, LOGIN_TTL / 1000) } });
    },
    async callback(request) {
      const fail = () => json({ error: 'sign_in_failed' }, 400, { 'Set-Cookie': cookie(LOGIN_COOKIE, '', 0) });
      if (request.method !== 'GET' || new URL(request.url).origin !== sessions.origin) return fail();
      const url = new URL(request.url);
      const states = url.searchParams.getAll('state');
      const binding = readCookie(request, LOGIN_COOKIE);
      if (states.length !== 1 || states[0].length > 256 || !binding || binding.length > 256) return fail();
      try {
        const state = states[0];
        const stateDigest = await hashText(state);
        // Atomic one-time claim. A wrong browser cannot consume a valid flow.
        const row = await db.prepare('DELETE FROM oauth_transactions WHERE state_digest = ?1 AND binding_digest = ?2 AND expires_at > ?3 RETURNING envelope, created_at, expires_at')
          .bind(stateDigest, await hashText(binding), clock()).first();
        if (!row) return fail();
        const { verifier, nonce } = JSON.parse(await cipher.decrypt(JSON.parse(row.envelope), context(stateDigest, row.created_at, row.expires_at)));
        const parameters = oauth.validateAuthResponse(server, client, url, state);
        const response = await oauth.authorizationCodeGrantRequest(server, client, clientAuthentication, parameters, redirectUri, verifier, oauthOptions);
        const result = await oauth.processAuthorizationCodeResponse(server, client, response, { expectedNonce: nonce, requireIdToken: true });
        // Require signature validation even though the token arrived over TLS.
        await oauth.validateApplicationLevelSignature(server, response, oauthOptions);
        const claims = oauth.getValidatedIdTokenClaims(result);
        if (!claims || claims.iss !== server.issuer) return fail();
        const ownerId = await ownerForIdentity(db, claims.iss, claims.sub, clock());
        const issued = await sessions.issue(ownerId);
        const headers = new Headers({ ...securityHeaders, Location: sessions.origin + '/' });
        headers.append('Set-Cookie', cookie(LOGIN_COOKIE, '', 0));
        sessions.setCookies(headers, issued);
        return new Response(null, { status: 303, headers });
      } catch {
        // Never log token responses, auth codes, cookies, state or claims.
        return fail();
      }
    },
  };
      }
