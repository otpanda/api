# Atomic email and first-passkey signup

PasskeySignupService first consumes a one-use signup-email proof from AccountIdentityService, bound to the exact mailbox. It creates only a short-lived pending signup, not an account or email reservation. The registration options use a random opaque candidate owner ID as userHandle. The pending token is stored as a digest and bound to a separate browser binding. No delivery provider or HTTP endpoint is mounted.

Finish consumes the correctly bound attempt before cryptographic verification. An invalid attestation or duplicate attempt fails closed. Verified public key material is normalized through the same helper as existing-account registration. The signup must still be unexpired after verification.

A single D1 transaction creates the account, unique verified email, security generation and first passkey. Duplicate email/credential or a storage failure rolls back all candidate rows. A consumed proof is not restored on failure; the user must restart rather than reuse a potentially raced ceremony.

This increment does not issue a session. Session establishment must remain conditional on the account generation and credential still being active. It does not remove the internal createEmailAccount helper, which remains unmounted and may not be used by a first-passkey HTTP signup. Other approved signup paths, including provider-based signup, require their own proof and atomic credential/identity rules.

Before live signup: email service approval/setup, HTTP body/origin/rate checks, browser-binding cookie and CORS enforcement, anti-enumeration delivery responses, request quotas and scheduled bounded cleanup, persistent session integration, recovery-readiness warnings and a real browser ceremony. No synthetic test establishes hardware assurance.
