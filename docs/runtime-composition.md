# Integrated runtime composition

`createRuntime` in `src/runtime.js` composes the existing entry application:

- injected D1-compatible database with all migrations applied;
- exact approved HTTPS origin and Google web client registration;
- injected non-extractable AES-256-GCM key ring and active key ID;
- browser sessions, service metadata, owner source store and entry permissions;
- live permission checked entry automation tokens;
- Google authorization-code/PKCE browser sign-in.

It creates no accounts until a verified identity signs in, and provisions no
keys, sources, provider connections, domains or billing. It exposes only the
entry application HTTP surface, not the old service-scoped foundation routes.
A deployment host must supply `trustedRequestKey` from authenticated platform
metadata. Do not use an untrusted forwarded header as that key.

## Still required before real deployment

This module is composition preparation, not a deployed backend. `src/worker.js`
still defaults to the old fail-closed foundation handler for historical tests.
Do not point a deployment at that file and call it the integrated product.

A reviewed host entrypoint and deployment configuration must import the runtime,
map approved bindings, serve the real web assets on the same origin, apply all
migrations, arrange bounded scheduled cleanup and verify errors without leaking
secrets. Real OAuth origin/registration, injected keys and database must be
explicitly configured under the owner's approval. No defaults generate keys or
choose an OAuth project. A D1/runtime smoke test is still required, in addition
to the local SQLite tests. Google discovery is an external dependency, so host
initialization must fail closed and retry safely rather than keep a permanently
rejected initialization promise. Do not cache across distinct environment/key
configurations.

Native login, SMS enrollment and mail providers are not mounted by this module.
GitHub Pages remains the isolated fictional-data UI preview, not an auth origin.
