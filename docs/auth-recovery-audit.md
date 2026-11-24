# Auth and recovery spec audit (base 1f4d9c7)

Spec: Google and passkey are the only sign-in methods. Email codes are never a sign-in method. All passkeys are equal.

## Implemented in this patch
- `/v1/manage/recovery/{status,begin,finish}` (src/recovery-controls*.js). Every change needs a fresh passkey step-up bound to the exact action, owner, generation and device. Kinds: `email-escape-on`, `email-escape-off`, `passkey-revoke` (case 8), `session-revoke` (case 8/12, per device, no automatic wipe).
- Delayed email-only escape hatch setting (table `email_recovery_optin`, migration 0034): off by default, seven days stored and CHECK-enforced, enable needs the lockout warning flag. It is only a setting. Nothing starts or completes a recovery.
- Mutual exclusion with "Require extra verification for Google on new devices", enforced in SQL triggers (both directions) and in the service layer. Neither setting toggles the other.
- Last-passkey guard in `PasskeyService.revoke`: the last passkey stays unless an active Google link remains (case 11 vs case 9). Revoking a passkey needs a different passkey as proof, so one always remains.

## Reachability (auth-only worker, main src/auth-only-worker.js)
Reachable import graph: 57 of 83 src files. Routes allowed: google continue/protection, security settings, passkey add, first passkey, login start/verify/complete, restore/exchange/logout, signup app/verify, session/account reads.
- No route issues a session from an email code alone. Email codes only reach passkey `signup` (non-Google new account, case 2). The ownerless external-Google email continuation exists in code but is disabled at 1f4d9c7: `GoogleContinuation.allowEmailVerification` defaults to false, so create, send, verify and consume all reject it. This patch keeps that default. Case 7 link to an existing account needs a passkey step-up for `link-google`.
- `/auth/signup/start|email|begin`: allowlisted, always 303 to the app.
- Cases 1, 3, 4, 5, 6: already implemented by google-continuation, extra-verification and session-method. Not changed.

## Removed in this patch (proved obsolete)
`google-signin.js`, `oidc.js` (old `/auth/start` + `/auth/callback` Google sign-in on legacy cookie sessions; replaced by `google-browser-flow.js`, which was already the only mounted Google flow), `web-passkey-login.js` (unmounted composition, replaced by `web-login-handoff.js`), their three test files and docs/web-passkey-login.md. The sign-in hooks were stripped from `application.js`, `entry-application.js`, `runtime.js`, `environment.js` (no Google client settings needed any more; `/auth/start` and `/auth/callback` now 404 there). Security coverage ported to `google-browser-flow.test.js`: duplicate state, foreign origin, wrong binding, expired transaction and replay never reach the token call (the signature, nonce, audience, issuer, expiry and PKCE rejections were already covered there).

## Still unmounted, not removed (needs primary/user decision)
The legacy stack `application.js`, `worker.js`, `cloudflare-worker.js`, `host.js`, `environment.js`, `runtime.js`, `browser-application.js`, `entry-application.js`, `entry-management.js`, `management.js`, `token-store.js`, `d1-store.js`, `grants.js` is unreachable from auth-only. It carries the only HTTP surface for entry create/share/token management and the old verify-token API on legacy cookie sessions, with no replacement yet (device-read-http only reads). Deleting it would delete product behavior, not only old sign-in. Future product modules kept: `totp*.js`, `seed-cipher.js`, `service-catalog.js`, `catalog-directory-import.js`, `entry-tokens.js`, `device-key-proof.js`, `durable-device-keys.js`.

## Added after slice 1 (migration 0035)
- Enrolled-client approval for the recovery controls (`recovery_changes`, `request-change`, `approve-change`, `consume-change`): a signed-in client asks, a DIFFERENT-browser client with an active passkey session approves the exact action, the requester consumes it once; revalidated in the consuming write (generation, both sessions, approver passkey still active, expiry, last-passkey guard, exclusion trigger). Stricter than the protection toggle: Google-only sessions cannot approve.
- Email-only recovery request state (`email_recovery_requests`, `src/email-recovery.js`): needs the opt-in, a fresh mailbox proof from the mail path (request credential only), exactly seven days stored and CHECK-enforced, one open request per owner, outbox rows in `recovery_notifications` (requested, canceled). Cancel by any active passkey session (`cancel-request`), or automatically when the opt-in is turned off. There is no completion column or code path.

## Enrolled-client capabilities, grounded (limitation)
Two different things can be called an enrolled client:
1. A signed-in web session. It can request a change (`recovery_changes`) and consume an approved one. It can never approve: a bare browser session is not approval, whatever its login method.
2. An enrolled device KEY (`durable_device_keys`, local ECDSA P-256, no attestation, `platformVerified:false`). Proofs come from `DurableDeviceKeys.beginProof/finish`. They show possession only. `RecoveryControls.apply` REFUSES them for every kind, and approval needs an injected `localVerification` verifier that does not exist today, so approve routes return 503 (see the v5/v6 sections below). No route enrolls keys and no native client exists.

Not covered by this patch:
1. Cases 10/11 independent recovery method beyond the email path: none exists, so the safe result is lockout.
2. "Secure my account" as a single flow and share/app-token review UI.
3. The native client, a real local-verification verifier, and the app UI (see remaining work below).

## Enrolled-client approval and email recovery (v5)

Enrolled-client approval (`/v1/manage/recovery/approve-begin`, `approve-change`)
FAILS CLOSED. DurableDeviceKeys proves possession of a key only
(`platformVerified:false`; no attestation, no OS PIN or biometric proof), and
possession is never accepted as approval or as a step-up for protected changes.
`RecoveryControls` needs an injected `localVerification` verifier that enforces
fresh local user verification; none exists, the runtime does not wire one, and
both routes return 503 `local_verification_unavailable`. A verifier that does not
return exactly `true` cannot approve; a device-key proof is refused by `apply`
for every kind. The remaining machinery (change-bound challenge, action digest
`hash(["recovery-change",changeId,kind,target,ownerId,generation])`, active key
at the current generation, different approver session) is built and tested with a
stand-in verifier so a supported native client can be plugged in later.
Remaining native/UI work: a native client that enrolls a device key through a
platform-verified path (hardware key with required user verification, with
attestation the server can check), a verifier that implements
`localVerification` from that attestation, runtime wiring, and the app UI for the
request/approve/consume steps. Until then protected changes use a fresh passkey
step-up in the same session (`begin`/`finish`).

Email recovery (opt-in, off by default, never a sign-in method), under
`/auth/recovery/email/`:
1. `request` / `verify`: mailbox code (human code, purpose `recovery-request`)
   starts a request that is available exactly seven days later. Grants nothing.
2. `complete-code` / `complete-begin`: only once the wait is over, a fresh
   mailbox code (purpose `recovery-complete`, 30 minutes) yields a single-use
   grant to register a NEW passkey.
3. `complete-finish`: verifies the new passkey, then in one batch inserts it,
   revokes every old passkey, device key and device session, access and entry
   tokens and legacy cookie sessions, bumps the generation, and writes a
   `completed` outbox row. No session is issued; sign in with the new passkey.
   Kept: account, entries, shares, linked Google, the opt-in setting.
Guards: opt-in on, request not canceled, generation unchanged, wait over (also
enforced by a CHECK on `completed_at`), single-use grant. Turning the setting
off or canceling from a passkey session cancels the request.
Binding for codes is a client-held random value (43+ chars) sent with the
email, like a PKCE verifier. Mail goes only through an injected server
`deliver()`; templates are fixed in `recovery-mail-transport.js`. The runtime
mounts delivery from existing BREVO_* env; without it, code requests send no
mail. Outbox rows (`recovery_notifications`) still need a delivery job owned by
the host.

Notice delivery: `recovery_notifications` rows are sent by
`src/recovery-notifier.js` from the auth-only scheduled handler (when BREVO_* is
set): 60 s lease, at most 5 attempts, exponential backoff, delivered only after
the transport accepts. At-least-once: a crash can repeat a notice after the lease.
Code mails are deferred (`waitUntil`, 4 in flight per isolate); accounts without
the opt-in and unknown mailboxes write a decoy code row so timing and writes match.
Completion retires only the owner's own entry tokens (`actor_id`). Entry shares
are not touched and a recipient's own tokens on shared entries stay valid.

Code delivery (v7): every valid request writes a human code (hashed), an AES-GCM
encrypted durable job (`recovery_code_jobs`, wiped on delivery, never logged) and
tries one deferred send. A skipped (saturated or no defer), throwing-defer or
failed send is retried by the 15 minute cron drain while the 30 minute code is
live; 6 attempts max. Terminal failures set `failed_at` and show in the `/ready`
`recoveryDelivery` counts (dead*, pending*). Terminal notices are retried only by
the deliberate `retryFailedRecoveryNotifications`, never automatically.
Missing key configuration is a uniform 503 for every request shape.
Approver liveness: consume re-checks that the approver's device session is still
active (not revoked or expired, method still valid) as well as the approver key,
the requester session and the generation.
