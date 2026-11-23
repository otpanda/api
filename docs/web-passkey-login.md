# Web passkey login composition, not live login

`WebPasskeyLoginService` joins real passkey assertion verification, web device
session issuance and a one-use browser PKCE grant. The ceremony binds a trusted
server browser binding, exact canonical app redirect and tab PKCE challenge.
Changing those values cannot complete the original ceremony. No request-supplied
owner, client kind or verification-proof object is accepted.

Completion returns refresh material only to the future trusted HTTP layer, which
must put it in the API-host HttpOnly cookie, never JSON or a URL. It returns a
PKCE code, not an access token. The HTTP layer must retain the original state and
redirect only to the fixed app callback fragment. Credential/device revocation or
account generation changes before the final session check deny completion.
Failed grant minting revokes the provisional device, including when mint throws.

This module is deliberately unmounted. It does not provide HTTP validation,
CSRF cookies, rate limits, browser challenge transport, a visible login button,
mail verification delivery, signup-to-session issuance or Google OAuth. Existing
signup still atomically enrolls its first passkey without implicitly creating a
session. Login and restoration must be assembled with their correct, distinct
browser-origin boundaries before enabling real authentication.

Tests use actual cryptographic registration/assertion verification and SQLite
transactions. They cover exact context binding, PKCE exchange, replay, bad
assertions, expiration, credential revocation, failure cleanup and a generation
reset during grant minting. They do not establish real device behavior.
