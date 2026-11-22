# Foundation boundary

This branch is a testable starting point, not a working OTP service. Do not deploy it with real codes or seeds. No credentials, accounts, cloud bindings or billing are configured. The landing page is separate and deferred.

## Established requirements

- Cloudflare is the initial hosting target; core logic should stay portable. Self-hosting is not an officially supported option yet.
- Android collects SMS codes, with an open-source/F-Droid distribution goal. No iOS app is planned.
- Web, browser extension and API clients access centrally available codes. Automated clients need unattended access through explicit, revocable, narrow grants.
- TOTP seeds are usable in the cloud. This is not end-to-end encrypted sync: the service can access secrets. That trust boundary must be disclosed rather than hidden behind an encryption claim.
- Email ingestion should be event-driven/near-real-time. Gmail and Outlook need provider-specific connectors, not a ten-minute polling loop.

## Implemented here

- HOTP/TOTP primitives using standard Web Crypto HMAC, tested against RFC 4226 and RFC 6238 vectors.
- Strict Base32 parsing and explicit clock input. Secret byte arrays are inputs; nothing stores or logs them.
- A pure grant policy that denies revoked, expired, wrong-owner, wrong-client and wrong-service reads.
- An inert Worker-compatible handler. Only `/health` responds successfully. `/v1/*` returns 501, regardless of headers.

## Required before any real-secret endpoint

1. An authenticated user session and verified device/client registration. Never accept owner identity from an untrusted request body.
2. Random opaque API tokens, stored only as digests. Derive grant records server-side after verification. The policy helper does not authenticate anything.
3. Owner-isolated storage, envelope encryption with a managed root-key lifecycle, rotation/recovery and a documented compromise model. No home-grown cryptography.
4. Rate limits, bounded responses, explicit service binding and protection against replay and cross-tenant access. Test each boundary end-to-end.
5. No secrets/codes/tokens/message bodies in logs or analytics. Metadata-only audit records and short retention for collected codes.
6. Provider OAuth verification, webhook validation, replay handling, idempotency and renewal before Gmail/Outlook delivery. Read current provider docs before implementation.
7. Recovery, deletion/revocation and abuse controls. Email/SMS OTP collection cannot reliably prove site identity from sender text alone.

The product and protocol choices above are requirements and proposed boundaries, not a security audit or a production-readiness claim.
