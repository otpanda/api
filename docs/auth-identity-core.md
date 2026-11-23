# Email-primary auth core

This is internal groundwork for the approved authentication replacement, not a working signup endpoint. The deployed Worker continues to serve only setup-required bootstrap responses. The legacy same-origin Google/session runtime is not mounted by the Worker and is not approved as the new sign-in path.

`AccountIdentityService` stores unique verified account email separately from stable owner IDs. Challenges contain hashed secrets and purpose/owner/target binding, expire within15minutes, reject future creation dates and are atomically claimed once. Issuing an email challenge does not reserve an account/email. Duplicate verified signup fails without an orphan account. Provider linking binds exact Google issuer+subject and current email; equal email alone never finds/links a new subject. Provider email drift fails closed. Google ID-token signature/audience/nonce validation remains the caller's responsibility. Gmail and matching hosted-domain claims are distinguished from arbitrary external email_verified claims, which do not establish current mailbox control.

Email support is explicitly limited to ASCII addresses, normalized to lowercase for this product's unique-email policy. Surrounding whitespace, malformed domains/local parts and unsupported internationalized input are rejected, not guessed. Gmail dot and plus aliases are not folded. Sending and final address acceptance still require actual verification delivery. Source mailboxes may have different addresses from the account email.

## Security integration gates

Do not call these internal methods directly from untrusted input without orchestration. No public routes or caller-chosen owner/verified-identity flags are added in this increment.

- Signup finalization must atomically bind the first verified passkey or real app recovery credential before enabling vault access. The internal email-account record alone grants nothing.
- New provider links, email changes, new recovery methods and credential resets need exact-action fresh strong proof, not a remembered session or client assertion that a biometric prompt succeeded.
- Google-only signup cannot label an ordinary web key hardware/local-verification protected. If no existing strong device exists, finish enrollment through a supported passkey or actual native auth-bound key before sensitive/real-vault access.
- Normal web/app/extension sessions, native long-lived recovery signing registrations and automation grants remain distinct. No mandatory manual recovery codes, SMS or new account password.
- Full recovery must revoke old credentials/sessions/automation tokens, freeze shares/source access for review and enforce the approved post-recovery restriction. No email-only full-loss recovery.
- Real mailbox delivery, rate-limit orchestration, passkey verification library, challenge delivery, exact client origin/redirect checks, recovery policy and Android OS signing are not implemented here.
- Existing pre-release accounts/identities are not automatically email-verified or silently migrated.

## Tests

`npm test` includes email syntax/policy, hash-only challenge storage, no preverification reservation, duplicate signup rollback, mailbox/purpose/owner/provider binding, replay/expiry/future-time denial, provider drift and Google email-authority tests. `npm run db:local` checks the additive migration under local D1. A SQLite test is not proof of remote concurrency or provider/mobile behavior.
