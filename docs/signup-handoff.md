# First-passkey signup session handoff

Internal `SignupHandoffService` connects atomic first-passkey registration to the
existing browser login completion protocol. It is not mounted and does not send
mail, create keys, enroll recovery devices or enable authentication.

`beginBrowser({email,emailToken,cookieBinding,challenge,state,redirectUri})`
requires a server-created first-party binding and exact approved callback. The email proof must match its issuance-time browser receipt before it is consumed. A browser-bound verified mailbox receipt permits at most five fresh registration attempts within the original ten-minute email lifetime. Internal proofs are issued only server-side for those attempts. Registration context is bound
to a purpose-specific digest of cookie binding, PKCE challenge, state and exact
callback. Migration0017 stores only token/cookie digests and bounded context.

`verifyBrowser({token,response})` consumes the server-held context before
attestation verification. Atomic signup returns server-derived account and first
credential metadata. A generation- and revocation-checked insert creates a
one-use handoff, not a session. It expires within a minute after successful registration, even if registration finished near its ceremony deadline. No email verification token or account proof is accepted as a
substitute for attestation.

`completeBrowser({handoff,cookieBinding})` delegates to existing login completion.
The HTTP adapter must use the existing login-binding cookie and completion page.
The top-level API completion verifies cookie binding/CSRF, checks credential and
security generation again, and issues an HttpOnly refresh cookie and a one-use
PKCE code. The app receives no refresh secret. Failed session/exchange setup
revokes any provisional session. A wrong binding cannot consume a valid handoff.

A lost completion response can leave a created account without a browser session.
The passkey is already valid, so the user should restart ordinary passkey login,
not retry signup indefinitely or delete/recreate the account. No account cleanup
on a failed handoff is attempted. Registering a credential and issuing a session
are intentionally separate, fail-closed steps. Expired context cleanup is bounded.

Before activation: the separate HTTP/browser binding and email transport must
pass review and realistic browser tests. Local virtual authenticators do not
prove hardware assurance. Recovery readiness warnings must accurately explain
full-loss risk. This code is independent of paused durable-device recovery work.

Context insertion failure can leave an orphan pending registration, but not burn the browser mailbox receipt. A fresh bounded attempt is allowed. Existing cleanup removes orphan and receipt rows. HTTP must establish cookie binding before requesting mail and never consume emailproof on GET.

After account creation all mailbox receipts for that email are retired. Further signup starts for an existing email do not prompt for a new passkey. The HTTP/UI must not expose existence through this branch. Receipt TTL only bounds when a new ceremony may start; a ceremony started shortly before receipt expiry can complete within its own two-minute TTL, followed by a one-minute completion handoff.

If mail opens in another browser or in-app mail view, binding must fail closed. Show a clear instruction to return to the browser where signup started and enter/open the proof there, or restart in the desired browser. Never silently drop binding to make a link work.
