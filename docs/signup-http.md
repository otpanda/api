# Signup HTTP boundary

`createSignupHttp` is the first-party browser boundary for passkey signup. It is
deliberately unmounted: no runtime composition, provider credential, real mail
or activation is implied. It mirrors the existing login boundary's rules: exact
origins, trusted-address prelimits, bounded bodies, strict field allowlists and
generic failures. Completion reuses the existing `/auth/login/complete` page and
the shared `__Host-otpanda_login` binding cookie; no second completion surface
is added.

## Flow

1. `GET /auth/signup/start?challenge&state&redirect_uri` validates the exact app
   callback and opaque PKCE/state shapes, then renders a first-party page with a
   mail-request form and a manual proof-entry form. It performs no service call,
   sends no mail and consumes no proof. It preserves valid signup CSRF and login-binding cookie values while refreshing their lifetimes, so retries keep the
   binding their mail proof was issued under (Max-Age 900s covers the ten-minute
   proof plus ceremony and completion).
2. `POST /auth/signup/email` is a same-origin form POST (API Origin, CSRF cookie
   match, binding cookie required, keys exactly `csrf,email`). The address is
   validated, then delivery is handed to the injected `defer` and the response
   is a generic 202 page. The response never awaits account, quota or transport branches. This does not prove full timing indistinguishability. Without a `defer` the endpoint
   is unavailable (503). `defer` must run the task bounded and absorb its errors
   privately; the task gets `{email, clientAddress, cookieBinding}`.
3. `POST /auth/signup/begin` is a same-origin form POST (API Origin, CSRF match,
   keys exactly `challenge,csrf,email,email_token,redirect_uri,state`). Only it
   invokes `handoff.beginBrowser` with the server cookie binding. Success is a
   303 to the exact app callback with the ceremony and state in the fragment
   (data, never script). Any failure, including a missing or foreign binding
   cookie, serves a recovery page with clear same-browser guidance and ordinary
   passkey sign-in guidance for an already-created account. It never mints a
   fresh binding to make a link work, and no error text claims to know whether
   an account exists.
4. `POST /auth/signup/verify` is a cookie-free CORS fetch from the exact app
   origin (preflight allows only POST with Content-Type). Body is JSON with
   exactly `response,token`, capped at 16 KiB. Success returns only
   `{handoff, expiresAt}`; the app posts the handoff through the existing login
   completion page. The Origin is never reflected.

Cancellation retry: the app returns to the start page (binding cookie kept) and
re-posts begin with the same proof. The receipt permits at most five ceremonies
inside the original ten minutes, each with a fresh authenticator challenge.

## Trusted client identity

`canonicalClientAddress` (src/client-address.js) is the single owning boundary
for address normalization, applied before both the HTTP prelimit and the email
service. Input must be provider connection metadata; request headers are never
read. IPv4 is canonicalized strictly (leading zeros rejected). IPv6 folds to its
/64 prefix so rotation inside one prefix cannot multiply quotas; the tradeoff is
that unrelated users behind a shared /64 share one budget. IPv4-mapped IPv6
shares the native IPv4 bucket; other mixed forms are rejected. Malformed, zoned
or oversized input fails closed to 503.

## Limits

- The per-path prelimit (15/min per canonical address) is a prototype safety
  value, not a product setting. The email service's own quotas still apply.
- The 202 defers delivery work but does not make the flow timing-proof against
  an observer who can drive the transport; no such claim is made.
- The shared binding cookie means a concurrent login start and signup in one
  browser overwrite each other, as with two concurrent logins.
- Local tests use virtual authenticators and an injected transport. Real
  browser/device journeys, provider credentials, reviewed mail template and
  runtime composition remain open before any activation.

Integration browser fixes: API pages use same-origin Referrer-Policy so Chrome same-origin form POSTs carry a non-null Origin, while external navigation receives no referrer. Exact Origin checks remain unchanged. form-action allows only self plus the exact app callback for 303 redirects. Standard form UTF-8 charset is accepted. Valid CSRF values survive a second tab; both cookies refresh bounded lifetimes. Browser form errors render recovery HTML, verification exceptions retain fixed CORS and generic errors. Hex-mapped IPv4 canonicalizes to dotted native identity.

Unmounted signup-preparation-runtime composes an injected delivery callback and explicitly trusted address/waitUntil. It caps active deferred jobs at four, has no pending queue, absorbs rejection without logs, and requires the provider adapter to enforce actual abort timeout. Saturation returns account-independent busy503 with Retry-After and says no new email request was accepted. This is per-isolate safety only, not global edge defense. Host trust, live provider test and source-verified free edge abuse controls remain activation checks. Production worker is unchanged/auth disabled.

Signup-mail-transport supplies a fixed plain-text verification template and the existing Brevo adapter with a maximum ten-second AbortSignal-backed timeout, no retries, fixed provider endpoint and generic private errors. Passing plain text does not promise tracking removal, since Brevo may transform it. No real email is sent by tests or unmounted composition. The exact live template and test destination still need approval before an actual verification send.
