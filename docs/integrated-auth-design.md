# Integrated account entry

Status: source-only design and implementation in progress, not review-ready.

## Product contract

One intended finished-product account entry in the app. Google sign-in, passkey sign-in and email-to-passkey signup do not ask the user to choose login versus signup. Google creates a new unique-email account automatically and opens welcome. Existing identity links resolve only by exact issuer/subject. A Google identity with the same email as an unlinked existing account must prove the existing account before linking. No duplicate account and no email-only merge.

Email entry and verification stay in the app. API first-party bridges contain no interactive UI. They set HttpOnly bindings, immediately auto-post bounded fragment data when same-origin POST is necessary, and immediately return to app screens. App callbacks remove fragments synchronously, validate exact state and bound payloads, and expose no secret to Flutter. A verified-email existing-account branch can reveal the appropriate sign-in route only after mailbox proof; the initial email request stays nonenumerating.

Main UI is always the intended finished product. Temporary test controls belong alongside it, clearly marked temporary and to be removed. No restore-cookie/debug actions in the main account entry.

## Google access, final November 24 14:49 direction

Google alone is sufficient by default on any device. Optional passkeys do not make Google harder. One opt-in setting, Require extra verification on new devices, lives only in Security settings, not signup. Enabling needs a working independent verifier and a clear lockout warning. Disabling also needs the enforced proof so a Google-only attacker cannot defeat it. Signed-in-client approval remains supported as an alternative, explicitly scoped and confirmed.

Remember this device defaults checked. Unchecked creates no future recognition; it does not silently change the separately established session lifetime. Recognition is random hash-only, owner/generation-bound and revocable. No invented delay/expiry or notification requirement.

## Unified authorization pipeline

Extend the existing device-session model with passkey and Google proof variants, not a parallel legacy session. Passkey proofs retain active credential and generation checks. Google proofs bind the exact active provider link, verified email, generation, nonce, state, OAuth PKCE, app PKCE and first-party binding. A migration must preserve populated device rows and all refresh/access/exchange/assignment child foreign keys. No reset or re-enrollment of existing data.

At atomic issuance, require an active exact provider link and current generation. With extra verification off, validated Google proof may issue a full session. With it on, require the exact owner recognition record or independent proof consumed for that ceremony. Recheck first-enrollment races, revocation, logout tombstones, account email drift and generation changes in SQL. Pending Google state has zero code-read, source-read, provider-link or credential-enrollment authority. Its only operations are to prepare/finish the exact verification and cancel.

The first Google-only bootstrap may create a remembered client under the same batch gate. A later simultaneous bootstrap from another browser must not evade the newly created eligible-client condition. Nonremembered signed-in clients count as existing clients while their session is active; opt-out is not a bootstrap bypass.

Sensitive mutations still require exact-action fresh strong proof under their established policy. No blanket downgrade from OAuth. No new delays, notification grants, recovery rules, session lifetime or expiry policy are implied by this change.

## App screens

Entry: Continue with Google, Use a passkey, Continue with email; default checked remember option. No login/signup toggle.
Email: one address field, then one verification-code field. Mailbox proof routes existing users to their existing method, new users to passkey creation.
Google: provider redirects, then either welcome or an app-owned verify-new-device screen. Cancellation and errors return to the same app. Welcome offers passkey setup and clear recovery-risk information without making passkeys the only Google-account login method.
Recognized user: return to their account. Pending new device: passkey or explicit signed-in-client approval; never automatic remote approval.

## Required proof before publication

Node, bootstrap and Flutter tests; exact method/proof discrimination; populated migration; OAuth nonce/state/PKCE/replay/cookie checks; Google email authority/subject drift; cross-owner recognition; remember default/opt-out; recognition revoke/generation; simultaneous Google bootstrap and first-passkey enrollment; pending zero authority; request-body and callback limits; full ordinary-main compiled local ceremony; actual mobile pixels. Independent review before effectful activation. Hardware and production-cookie proof stay separate and explicit.
