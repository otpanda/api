# Cross-origin passkey browser handoff

Status: tested but deliberately unmounted. Production auth remains disabled.

The canonical app and WebAuthn RP remain otpanda.github.io. The API first sets a
short-lived, Secure, host-only, HttpOnly SameSite=Lax browser-binding cookie in a
top-level navigation. It stores the ceremony context server-side, returning only
bounded authentication options and a tab-state fragment to the exact app URL.
The app removes that fragment before asynchronous work or Flutter startup,
validates state/options/expiry and waits for an explicit passkey action.

The assertion is sent to the exact API verification endpoint with exact app
Origin, no cookies and no persistent credentials. It consumes the server-held
ceremony context and stores only verified credential metadata with a hashed
one-use handoff and hashed cookie binding. No session exists at this point.

A top-level API completion page removes its handoff fragment before parsing and
posts it same-origin with CSRF protection. Only the original binding cookie can
complete it. The refresh secret is created here and appears only in the API-host
HttpOnly cookie. The fixed app callback receives only a one-use PKCE code/state.
The app clears it synchronously, redeems without cookies, and holds short access
in memory. Wrong-browser attempts cannot create a session or consume the valid
binding's completion. Expiry/revocation/security-generation changes deny, and
failed grant minting revokes provisional sessions.

Start, verification and completion have separate trusted-address database rate
limits and bounded bodies. CORS permits only exact app Origin, POST and JSON;
credentials are never enabled. Completion uses nonce CSP, same-origin referrer
policy for a non-null POST Origin, exact API Origin checks, no caching, and a
fixed allowed app redirect. The completion page needs that app CSP destination
because the browser applies form-action to the POST redirect too.

Local tests include actual cryptographic passkey verification, real SQLite
transactions, cookie swaps, CSRF, origins, replay, expiry, reset, concurrent
completion and failed-mint cleanup. An isolated local HTTPS browser test uses
real Chromium WebAuthn APIs with a virtual authenticator and the actual app
bootstrap, real navigations, CORS and cookies. This is not hardware verification,
a live account signup or a production-auth readiness claim.

Before mounting: integrate actual Flutter UI/status/error controls, cleanup
scheduling, final runtime encryption and read dependencies, and end-to-end
authorized signup/delivery flow. Email provider/OAuth setup and real sources
remain separate approval gates. Neither this handoff nor the tests provide
email-only full-loss recovery or native recovery enrollment.
