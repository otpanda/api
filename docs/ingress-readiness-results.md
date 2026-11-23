# Ingress readiness evidence, November 24, 2026

Authentication remains disabled. This is not activation clearance.

The temporary bootstrap probe returned one byte without logging or returning
request addresses, metadata, credentials or binding names. It did not touch
D1, mail or rate limiters. It was removed in the immediate follow-up PR60.

## Observed on the public workers.dev path

An independent IPv4 HTTP/2 TLS caller received:

| Request | Result | Meaning |
| --- | --- | --- |
| Genuine client | 200, 1 | Resolver accepts the ordinary public path |
| Genuine client, expected actual address | 200, 1 | Positive equality control; IPv4 exact, not an IPv6 /64 test |
| Forged client-IP, expected forged address | Cloudflare403, error1000 | Blocked before the probe |
| Forged client-IP, expected actual address | Cloudflare403, error1000 | Blocked before the probe; no overwrite evidence |
| Plain client with forged Worker marker | 200, 1 | Consistent with marker stripping, not a real Worker refusal test |
| Same-account network self-subrequest | 503 | Inconclusive, including possible provider loop protection |

Cross-account Worker behavior remains documented, not tested. No second account
was created for this check. The documentation says Worker fetch subrequests carry
CF-Worker, and cross-zone calls use a fixed Worker IP. The resolver rejects both.
Metadata sanity fields are not proof of provenance. Internal Request objects can
forge metadata: the resolver must not be used behind internal/service-binding
callers without a separate verified boundary.

Address throttling is best-effort abuse friction, never authentication, identity,
permissions or an allowlist. The D1 per-recipient quota and global daily delivery
budget are address-independent caps, with an atomic INSERT/UPDATE RETURNING per
counter. Edge counters are approximate and location-scoped, not strict worldwide
caps. Four deferred delivery slots are per isolate, not a global concurrency cap.

## Still open

- Actual edge binding configuration and confirmed free-plan cost/capability.
- Production composition, redacted observability and operational alerting.
- Live transactional signup delivery and full real-account/hardware flow.
- Cross-account ingress remains an explicit documented, untested residual.
- Recovery readiness is separate. The durable-device increment remains paused.

Sources and code history:
- https://github.com/otpanda/api/pull/59
- https://github.com/otpanda/api/pull/60
- https://developers.cloudflare.com/fundamentals/reference/http-headers/
- https://developers.cloudflare.com/workers/runtime-apis/bindings/rate-limit/

## Inactive composed browser application

`browser-application.js` dispatches exactly four signup routes and thirteen
identity routes, with no legacy OIDC or recovery mount. Identity construction
is lazy and caught. Missing/throwing trusted ingress fails before database work.
The provider resolver returns a validated raw address; consumers canonicalize
once. Composition tests cover IPv4, IPv6 and mapped IPv4 with canonical hashed
edge keys. A real Chromium HTTPS synthetic flow uses that resolver with injected
provider metadata and IPv6, real cookies and a virtual authenticator through
signup into protected reads. That is not a live provider or hardware test.

Open activation issue: signup alone has approximate edge guards. Identity login,
exchange, reads and organization currently have D1 accounting, which can itself
write per request during abuse. Acceptable non-signup request/write budgets and
deployed provider configuration remain unresolved. Current key-import helper is
inactive; configured production format, IDs, cache behavior and workerd/browser
composition still need verification. Never infer activation clearance from these
local results. The production bootstrap remains authentication-disabled.
