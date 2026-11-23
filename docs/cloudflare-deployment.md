# Cloudflare deployment bootstrap

The canonical UI remains https://otpanda.github.io/web/. This Worker serves API hosting only. It is intentionally not the integrated authentication runtime yet: `/health` says `setup-required`, `/ready` checks the migrated DB, and all `/auth` and `/v1` paths fail closed with HTTP 503. No accounts, sources, tokens or encryption keys are created. Do not describe it as the working application.

## Native Git build

Connect only `otpanda/api` to Cloudflare Workers Builds, production branch `main`, root `/`. Build command: `npm run build`. Deploy command: `npm run deploy`. Dependency install uses the committed lockfile. Use Node 22.12 or newer, pinned runtime major 22. No GitHub Actions Cloudflare credential is needed: the native integration manages its deployment authorization. Pull-request preview deploys should remain disabled. The free Workers plan is selected; never enable paid features or billing automatically.

The deploy command applies pending versioned migrations to the approved `otpanda` D1 database, then deploys the Worker. A failed migration prevents deployment. These initial migrations have no user data to transform; future schema changes require backward-compatible review because database schema is not rolled back with a Worker version. Never edit previously applied migrations. Do not run deploy against an arbitrary account or replace the database ID from a copied example.

Run `npm ci`, `npm run build`, and `npm run db:local` before merging. Applying local migrations twice should be a no-op on the second run. `wrangler dev --local` permits health, readiness and closed-route smoke testing with the real local Workers/D1 runtime. Local success is not evidence of remote deployment.

## Deliberate limits

There are no Google credentials, real-source credentials, keyring secrets, asset bindings, custom domains, trusted-IP resolver, or permissive cross-origin headers in this entrypoint. Authentication is held pending reviewed passkey/session design. `environment.js` and the integrated runtime remain tested composition groundwork and are not mounted by this bootstrap. Only change that boundary after the approved browser/native protocol is implemented and tested. All GitHub Pages project paths share an origin, so root, landing and app code are a single client trust boundary.

Logging/observability and workers.dev preview URLs are disabled in the committed configuration. Do not log request headers, query strings, cookies, OAuth responses or credentials when real auth is added. Nonsecret Cloudflare D1 identifiers are configuration, not API credentials.

After the first build, verify the actual workers.dev URL returned by Cloudflare, `/health`, `/ready`, wrong-method behavior and unauthenticated protected routes. Record the deployed commit and build result. A successful native deployment and schema check still leave initial working product incomplete until real authentication and source adapters are delivered.
