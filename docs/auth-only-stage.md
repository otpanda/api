# Auth-only staged entry candidate

`src/auth-only-worker.js` is **not selected** by `wrangler.jsonc`. Current deployment remains bootstrap-only. This increment does not enable app sign-in or change secrets, flags, origins, production identities or data routes.

The next usable milestone is signup with verified email and a passkey, ordinary passkey sign-in, browser restoration and protected session metadata through the actual Pages app and Worker origins. This is account access, not a working code-ingestion service. Native recovery is independent and is not a prerequisite invented by this candidate.

## Fixed scope

The candidate requires `DEPLOYMENT_STAGE=auth-only` and the exact API origin. It delegates only four signup endpoints, three login endpoints, restore, exchange, device logout and the protected session read. No flag can open additional paths. Entries, codes, sources, organization, assignment, legacy OIDC and all recovery endpoints remain 404 before database or external work, including preflights. Existing direct Cloudflare ingress checks and pre-D1 edge guards remain in force. Pure allowed CORS preflights require no database or key import. Housekeeping remains capped at 100 rows per table. The health response names staged authentication and unavailable sources, codes and recovery. It does not claim tested delivery, working hardware or application readiness. `/ready` checks auth-only configuration and schema, not delivery or cipher custody.

No code-cipher key is needed for this route set. Production key custody remains intact and unrelated encrypted routes are closed rather than represented as empty success.

## Local evidence

- 444 Node tests pass, including six new tests for fixed path scope, explicit stage, production-shaped bindings, genuine resolver metadata checks, wrong origins, pure preflight and scheduled cleanup.
- Local workerd runs all current migrations through 0021, the actual candidate entry, actual configured rate-limit objects and real D1.
- Chromium HTTPS on the exact app/API origins completed synthetic email signup, a virtual authenticator's WebAuthn creation, first-party cookie/CSRF completion, PKCE exchange, protected CORS session read, ordinary passkey login, and first-party restoration with Continue. Callback fragments were cleared. Entries/sources/organization/assignment remain 404 with an issued access token.
- Mail was intercepted locally, no message went to a real recipient. The authenticator was virtual, not user hardware. Provider metadata was injected for the local boundary. These tests are not activation evidence.

## Before activation or a claim that sign-in works

1. Independent review of this fixed route set and app auth-only presentation. The current app still has sign-in disabled and expects broader data paths after authentication. It must show a truthful partial account state rather than failed reads or an empty working codes list.
2. Inspect current deployed binding and mailbox readiness evidence. Validate transactional delivery using a source-authorized test destination without enrolling a real code source. Do not infer permission to use an arbitrary account or recipient from deployment authority.
3. Ground the staged deployment decision and test identity in the owner's actual instructions. Keep genuine unresolved choices separate from engineering prerequisites already satisfied.
4. Enable only the reviewed entrypoint/flags with rollback preserved, then verify live signup/login/restore and session expiry against actual production origins. A hardware ceremony needs the intended person's device participation. Report this distinction rather than substituting synthetic proof.
5. Update issue/project fields and read back actual deployed behavior. No recovery promise, automatic key replacement, source enrollment, destructive reset or account deletion semantics are added here.

## Deployment and rollback boundary

Activation must change the configured entrypoint and `DEPLOYMENT_STAGE` together in one reviewed config diff. This candidate deliberately does not make either change. Reverting that single config diff restores bootstrap routing; reverting only the stage closes the candidate with503, not fallback auth. A rollback does not delete account, passkey, device-session, mail-proof or quota rows created while auth-only was active. Retain those rows and keys; do not reset/migrate away identities or replay provisioning. Re-enabling preserves revocation/generation/session state, with expired records handled by normal bounded cleanup.

`/ready` now has an auth-only contract: migrated identity/signup tables readable, all seven limiter objects present, project sender/reply-to and a nonempty mail binding configured. It consumes no limiter slots and sends no email. It says configured-not-delivery-proof. It does not validate provider mail quota/acceptance, limiter efficacy, cryptographic signup or code-cipher custody. Initial-key provisioning remains intentionally bootstrap-only and must refuse after activation; its verify-only action is not an auth-only health check. Do not alter that safety gate to make it pass during auth-only stage. Retained cipher key verification belongs to the preactivation checkpoint and a separately reviewed future retention check, not readiness success inferred from auth.

Existing database mail caps are5peraddress/hour,3perrecipient/hour and100globally/day, with atomic counters. The four deferred delivery slots are per-isolate. The configured edge10/min is approximate and not the daily cap. Public users can still exhaust the shared cap; that is an availability residual. Confirm the actual provider plan/quota/sender before activation.

Minimum diagnostics proposal: retain disabled provider invocation logs, which may include URL/form/recipient context, until a reviewed redaction boundary exists. Use fixed non-PII status counters by route category and status class only, with no URLs, query strings, IPs, headers, email, owner IDs, request bodies or tokens. No new persistent analytics store is included here. Live HTTP health/readiness and provider aggregate quota/outcome dashboard are current bounded checks, not comprehensive error telemetry. This operational choice remains an activation review item, not silently satisfied by tests.

Reproduction is in `tool/auth-only-browser/README.md`. The full ceremony is implementer-executed until independently reproduced. The Node test named production-shaped signup checks only signup-start and unauthenticated session refusal; it is not the full ceremony proof.

## Owner-address-limited signup candidate

The inactive auth-only entry now requires one canonical `AUTH_ONLY_SIGNUP_EMAIL` value. No wildcard, list or absent-value public mode exists. Do not put a personal address in the public source/config: set it as a deployment binding only after the owner's choice. `/ready` validates its shape without returning the address. Changed/missing/malformed values latch signup closed for that isolate. A fresh deployment resets the latch, not identities.

An injected synchronous policy reaches mail issuance, passkey begin and finish, with rechecks immediately before delivery and account transaction. Non-allowed emails receive the ordinary generic accepted mail page but no email/proof. Direct verify cannot bypass the pending row's email check. Other inactive adapters retain their existing policy defaults; only this stage opts into the narrow policy. Login/restore of existing accounts is not an account allowlist. The stage remains publicly reachable, and an attacker knowing the allowed address can consume its recipient/global mail budget. Existing limits still apply. This is not a secret invite or protection from targeted mail flood.

This candidate does not select the entry, stage, binding, UI flags or first identity. It creates no identity, sends no mail in tests and adds no source/recovery/export authority. Rollback retains any identities created during eventual authorized activation.
