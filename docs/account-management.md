> Historical. The legacy OIDC sign-in adapter described here was removed. Google sign-in is `src/google-browser-flow.js`, passkey sign-in is the login routes, per docs/integrated-auth-design.md.

# Account sign-in and management milestone

This adds a configurable OIDC authorization-code sign-in adapter, durable browser sessions, token management and application composition. It does not create an OAuth client, choose a production identity provider, deploy the app or connect a real account.

## Security boundaries

- Uses pinned `oauth4webapi` 3.8.9 (zero transitive dependencies) rather than implementing an OAuth/JWT protocol from scratch. Authorization-code flow uses S256 PKCE, state, nonce, issuer/audience/time checks and required JWKS signature validation. Tests use a synthetic OIDC provider with real generated RSA signatures.
- Login transactions expire after ten minutes. Verifier/nonce are encrypted at rest. A separate Secure/HttpOnly/SameSite browser cookie binds the transaction to the initiating browser. An atomic DELETE RETURNING claims it once before token exchange; callback replay cannot create another session.
- Accounts map exact issuer+subject pairs. Email does not link identities. The code cannot select owner identity from a request body. Adding/linking another provider to an existing account is deliberately not implemented.
- Browser sessions last eight hours, use Secure/HttpOnly `__Host-` cookies and store only credential digests. Session-only mutations require the exact application Origin and a separate CSRF header validated against a digest. Login start is same-origin POST. Logout revokes the server record and clears cookies.
- `/v1/manage/tokens` lists safe metadata or creates a service-bound `codes:read` token and returns the credential once. Unknown body fields are rejected, including caller-selected owners/scopes. DELETE revokes only the signed-in owner's token. Automation bearer tokens cannot access the control plane. Request bodies are bounded even without Content-Length.
- Atomic D1 rate buckets apply to management owners and host-derived request keys. The host adapter must provide a trusted request key; arbitrary forwarded IP headers are not trusted. These are initial fixed-window limits, not a complete distributed-abuse defense or a guarantee of staying within the free tier.
- Composition catches failures without disclosing exception details. Metadata, codes, auth codes, tokens and claims are not logged. Cleanup deletes expired codes, sessions, login transactions and rate buckets in bounded batches.

## Verification

Run `npm ci && npm audit --omit=dev && npm test`. Tests cover signed OIDC success and signature/nonce/audience failures, browser binding, callback replay, session expiry, CSRF/Origin, owner isolation, safe listing, revocation/logout, request-size limits and rate buckets, plus the previous cryptography/storage tests. CI installs the pinned lockfile before testing. No real provider/account was contacted by the tests.

Protocol/library sources reviewed:
- https://www.rfc-editor.org/rfc/rfc9700.html
- https://github.com/panva/oauth4webapi
- https://developers.cloudflare.com/d1/worker-api/d1-database/

## Remaining

The default exported Worker is still inert. `createApplication` requires explicit dependencies. A deployment adapter, configured provider registration and redirect URL, root-key provisioning/recovery, provider email connectors, Android ingestion/enrollment, web/extension account UI and end-to-end real-account verification remain. No public deployment, paid service or real-secret use is authorized by this code. Identity-provider selection and production access will be surfaced before setup. This is development progress, not a security-audit claim.
