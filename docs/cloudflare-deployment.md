# Cloudflare deployment bootstrap

The canonical UI remains https://otpanda.github.io/app/. This Worker serves API hosting only. It is intentionally not the integrated authentication runtime yet: `/health` says `setup-required`, `/ready` checks configured keyring format and the migrated DB, and all `/auth` and `/v1` paths fail closed with HTTP 503. No accounts, sources, tokens or encryption keys are created. Do not describe it as the working application.

## GitHub Actions build and deploy

All CI runs through GitHub Actions. `.github/workflows/test.yml` tests pull requests without deployment credentials. Only a push to `main`, after the test job succeeds, can run the deployment job. No `pull_request_target`, untrusted artifact execution or native Cloudflare Git Builds connection is used. Deployments are serialized without cancelling a migration in progress. Actions are pinned to observed commit SHAs, Wrangler is locked in package-lock.json, and the token is available only during the final deploy step, not install/tests.

Create an account-owned Cloudflare token with only Workers Scripts Edit and D1 Edit on the approved account. Store it as encrypted repository Actions secret `CLOUDFLARE_API_TOKEN`, never in code/chat or build artifacts. Account ID is nonsecret workflow configuration. A missing secret fails with a clear setup message before any mutation. The first Worker does not yet exist for per-Worker selection; review finer scoping after creation. No zone/KV/R2/AI/billing permissions are needed. Token provisioning is a separate secure handoff, not implied by committed workflow. Disable any redundant native-build route rather than creating a second CI system.

The deploy command applies pending versioned migrations to the approved `otpanda` D1 database, then deploys the Worker. A failed migration prevents deployment. These initial migrations have no user data to transform; future schema changes require backward-compatible review because database schema is not rolled back with a Worker version. Never edit previously applied migrations. Do not run deploy against an arbitrary account or replace the database ID from a copied example.

Run `npm ci`, `npm run build`, and `npm run db:local` before merging. Applying local migrations twice should be a no-op on the second run. `wrangler dev --local` permits health, readiness and closed-route smoke testing with the real local Workers/D1 runtime. Local success is not evidence of remote deployment.

## Deliberate limits

Provider-managed Google OAuth and Brevo secrets are installed, with their non-secret client/sender configuration in Wrangler. They are not consumed by this bootstrap for sign-in or email. Initial encryption-key provisioning is unfinished because a supported secure generation-to-recoverable-custody route is unavailable. There are no real-source credentials, asset bindings or custom domains in this entrypoint. Seven approximate rate bindings are deployed but unused by the bootstrap. The public ingress resolver and reviewed browser adapters remain unmounted. Authentication is held for concrete security/configuration/live-flow checks, not a new product-design approval. `environment.js` and the integrated runtime remain tested composition groundwork and are not mounted by this bootstrap. Only change that boundary after the approved browser/native protocol is implemented and tested. All GitHub Pages project paths share an origin, so root, landing and app code are a single client trust boundary.

Logging/observability and workers.dev preview URLs are disabled in the committed configuration. Do not log request headers, query strings, cookies, OAuth responses or credentials when real auth is added. Nonsecret Cloudflare D1 identifiers are configuration, not API credentials.

After the first build, verify the actual workers.dev URL returned by Cloudflare, `/health`, `/ready`, wrong-method behavior and unauthenticated protected routes. Record the deployed commit and build result. A successful Actions deployment and readiness check still leave initial working product incomplete until real authentication and source adapters are delivered.

See [provisional free-tier operations](free-tier-operations.md) for current rate defaults, account-plan evidence, hard-quota outage behavior and cleanup limits. Missing key configuration makes /ready return a generic503; /health stays200 with authentication disabled. A valid-format readiness response would not prove compatibility with existing encrypted rows or clear activation.

Operational state was verified November24,2026 against API65 main de03c4ee2fd4a1080bc3b3136440e9a34a7d77e6, successful deployment https://github.com/otpanda/api/actions/runs/45290741183 and the production Worker settings. This dated observation is not activation clearance.
