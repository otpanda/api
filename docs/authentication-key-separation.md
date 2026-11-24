# Separate account authentication from code-encryption readiness

Finding: the current identity Worker imported ENCRYPTION_KEYRING and constructed CodeCipher before processing even passkey login routes. Passkey signup, cryptographic login, browser completion/exchange and session metadata do not need the code-encryption key. Treating custody as a prerequisite for all sign-in was an implementation coupling, not an unavoidable cryptographic dependency.

This increment lazily initializes only encrypted data dependencies after an authorized request reaches active-codes, unassigned or sources. Missing/invalid key configuration gives generic 503 for those paths, with cached failure; it does not enable decryption, fallback encryption, plaintext storage, seed access or ingestion. Session/entry metadata keeps its existing authorization checks. Unauthorized reads never invoke key loading. Key configuration changes still fail closed at the existing Worker configuration snapshot.

No deployment entrypoint, environment, readiness endpoint, login-enabled UI flag, session issuance/rotation/recovery algorithm or production account is changed. Authentication remains disabled in production. This is a composition correction ready for internal review, not permission to bypass activation review.

## Practical path

1. Merge reviewed composition separation and tests, still unmounted.
2. Prepare an authentication-only staged entrypoint and UI. Gate encrypted/source/code operations explicitly and show partial readiness rather than presenting an empty working code service. Review whether source metadata really needs the cipher before widening its availability. Do not return success for unavailable encrypted reads.
3. Verify configured transactional mailbox delivery without real source enrollment, then passkey signup/sign-in through production origins with a deliberately authorized test account and hardware ceremony. Existing local synthetic ceremony proof is not a live test. Provider login still needs its own current linked-identity flow and is not supplied by legacy OIDC.
4. Activate only the reviewed minimal auth route set under an explicit staged deployment decision. Keep code/seed/source routes closed until recoverable key custody and other prerequisites pass. Account authentication progress is useful, but not initial-product completion.

## Custody, still distinct

No production key is generated or provisioned by this increment. Ciphertext must retain access to its versioned key across deployments and key rotation. Independent recovery after loss of the entire provider account is a separate threat-model choice, not an established user requirement and not a prerequisite invented by this change.

A parallel investigation owns provider/CI generation, retained secret custody, token permissions, safe failure and no-cost checks. Authentication separation does not defer that work. It also does not establish that any particular provisioning approach has passed review.

Key binding changes in one live isolate still fail closed under the existing configuration snapshot. Provider secret writes create a new Worker version/isolate; this change does not relax that rule. Owner/shared-entry labels and account/service names remain plaintext metadata under unchanged authorization, not new disclosures caused by key separation.
