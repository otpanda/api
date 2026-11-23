# Provisional free-tier operational defaults

Authentication is disabled. These bindings are preparation, not an activation or capacity claim.

## Current plan and exhaustion

The account's Workers dashboard showed Free, $0, current plan on November24,2026. Workers Free has100,000 requests/day and10ms CPU/invocation. The documented daily request limit resets at midnight UTC; exhaustion returns1027. D1 Free has5million rows read/day and100,000 rows written/day. D1 rejects queries after those quotas are exhausted. No paid plan or automatic upgrade was enabled.

This is a deliberate availability tradeoff for this free-only project. The defaults below reduce bursts; they cannot promise continuous service or enforce a strict worldwide cap. A future paid-plan change needs separate approval.

## Provisional pre-D1 edge limits

All values are per60seconds, perCloudflarelocation, approximate. Each binding uses a separate project namespace. No internal/service-binding callers are supported at the public-ingress boundary.

| Binding | Limit | Purpose |
| --- | ---: | --- |
| SIGNUP_ADDRESS_LIMIT |10|Best-effort address friction for signup initiation |
| SIGNUP_GLOBAL_LIMIT |10|Shared signup initiation pool in each location |
| SIGNUP_VERIFY_ADDRESS_LIMIT |30|Address pool for outstanding signup proofs |
| SIGNUP_VERIFY_GLOBAL_LIMIT |15|Shared verification pool, separate from initiation |
| IDENTITY_ADDRESS_LIMIT |60|Best-effort identity/management address pool |
| IDENTITY_AUTH_GLOBAL_LIMIT |15|Shared sign-in/exchange/logout pool |
| IDENTITY_READ_GLOBAL_LIMIT |30|Shared management reads and organization changes |

These are tunable engineering defaults for early usage, not product entitlements. Shared networks can hit address limits. Distributed junk can starve the shared management pool, even though it is separate from public auth. Approximate counter propagation permits overshoot. No address value authorizes identity, access or an allowlist.

Atomic D1 mail budgets remain100attempts/day worldwide and3/hour per canonical recipient. The address mail budget is5/hour and best-effort because request-address provenance has a documented untested cross-account residual. A failed delivery consumes an attempt. Per-isolate deferred jobs are limited to4, not globally4.

## D1 write and cleanup pressure

The saturated rate-bucket optimization leaves an exhausted bucket unchanged. Local actual workerd/D1 metadata showed a denied attempt taking2reads/0writes for the UPSERT plus1read/0writes for the reset lookup. An allowed steady attempt still takes2reads/2writes; first insertion1read/3writes. These are local measurements, not production metering or upper bounds on an entire HTTP request.

Distinct fresh keys still insert rows. Cleanup removes at most100expired rate buckets per15-minute run, or9,600/day if every run succeeds. A fresh-key flood can outpace that. Cleanup itself consumes write quota, and other identity/proof/session/organization operations have additional reads and writes. A daily edge-limit multiplication is not a worldwide quota calculation.

The existing public /ready query uses WHERE0. It measured0rows read and0written locally, but still consumes Worker requests/CPU and invokes D1. /health is static and independent of database/key setup. Public health traffic can still exhaust Workers request quota. Redacted observability and real-flow metering remain required before activation.

## Evidence limits

The Free account's Add binding dialog offers Rate Limiter without an upgrade prompt. An accepted deployment of these unused bindings establishes configuration availability, not live counter correctness or a separate pricing guarantee. The binding documentation and Workers pricing pages do not identify a separate rate-binding charge in the material reviewed. Do not claim an explicit price that is not stated.

Cross-account Worker ingress is untested. No extra provider account was created. Internal/service-binding invocation remains unsupported. Recovery readiness is independent, and the durable-device increment remains paused.

Sources checked November24,2026:
- https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/
- https://developers.cloudflare.com/workers/platform/pricing/
- https://developers.cloudflare.com/workers/platform/limits/
- https://developers.cloudflare.com/d1/platform/pricing/

The signup shared pool was raised from the initial5/min proposal to10/min after the actual-limit browser negative-case suite exhausted5 with one legitimate flow plus wrong-browser/CSRF/proof checks. This is a measured provisional usability adjustment, not a capacity promise.
