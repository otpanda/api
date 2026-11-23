# Passkey persistence core, not live auth

Migration 0008 and PasskeyService add internal ceremony orchestration and public-key storage. They do not mount a route, issue a session or establish an HTTP caller's authority.

Ceremonies expire after two minutes. An opaque random token is stored as a digest, bound to a separate server-established browser binding, purpose, owner and exact action. Registration and step-up snapshot the account security generation. Correctly bound attempts consume the ceremony before signature verification, including failed verification. Wrong bindings do not consume a legitimate ceremony. HTTP must use an HttpOnly ceremony binding cookie and apply rate limits before issuance and signature verification; the token alone is not sufficient.

Registration requires an existing verified email-primary account and a trusted, fresh, action-bound enrollment grant at the HTTP boundary. Credential IDs are globally unique, even after revocation, and never overwrite or rebind. Discoverable authentication requires the returned userHandle to exactly match the stored opaque account ID. Step-up binds the original account/action and may omit userHandle when allowCredentials selected the credential.

Revision compare-and-swap serializes counter-zero authenticators too. Revocation or a security-generation change during signature verification prevents success. Credential backup eligibility is immutable; backup state may update on successful assertions. Account deletion cascades credentials and ceremonies.

Remaining gates before mounting anything:

- Atomic email-verification + first credential signup, so signup cannot leave a credential-less account.
- HTTP origin/body/rate/CSRF enforcement and trusted owner/action derivation.
- Session creation and sensitive action execution atomically conditioned on the returned generation/credential still being active. A result from this module is not a transferable step-up ticket, bearer token or session.
- Persistent cross-origin session exchange designed for the approved GitHub Pages UI, with revocation and browser storage limits.
- Recovery enrollment/removal readiness warnings, native recovery key protocol, and provider identity linking.
- Bounded expired-ceremony cleanup and issuance limits before traffic is accepted.
- Actual browser and native ceremonies. Synthetic signed test credentials are not device or hardware assurance.

No production auth endpoint is enabled by this increment. Android origins stay denied by default until release fingerprints are verified.
