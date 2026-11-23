# Durable storage milestone

Adds `migrations/0001_storage.sql`, `D1TokenStore`, `D1CodeStore` and `CodeCipher`.

- D1 uses prepared/bound SQL. Tokens store SHA-256 digests, not bearer strings. Token listing excludes digests. Owner-bound revocation is idempotent and stale writes cannot reverse revocation or change token identity/scope.
- Codes are encrypted with Web Crypto AES-256-GCM and fresh 96-bit random nonces. Authentication data binds owner, record ID, service, creation/expiry and key version. Moving ciphertext between tenants or changing its metadata fails authentication. An injected keyring supports reading old keys while writing with a new active key.
- This is authenticated encryption under injected keys, not a completed managed envelope-key lifecycle. No production keys are provisioned. Key storage, backup/recovery, rotation/re-encryption operations and root-key compromise response still require implementation and review. Server access to plaintext is intentional; this is not zero knowledge.
- Storage rejects code lifetimes over 24 hours, excludes expired/future records from retrieval, ignores repeated record IDs instead of overwriting, and provides bounded expiry cleanup. Account deletion cascades tokens and ciphertext. The 24-hour value is a safety ceiling, not an agreed product retention promise.
- With an explicitly injected code store, `GET /v1/codes/latest?service=...` returns the latest unexpired code using only the verified grant's owner and service. Request owner parameters cannot select another account. Without injected stores, the exported default Worker remains closed and inert.

## Verification

`npm test` runs the pre-existing tests plus real on-disk SQLite reopening, encrypted storage, tenant/service isolation, tampering, expiry, replay, revocation, deletion and HTTP retrieval tests. The SQLite helper mirrors only the D1 calls used here, not its complete API.

An additional local Miniflare 4 D1 smoke test passed migrations, BLOB digest binding, mint/verify and encrypted insertion/retrieval. This is an emulator check, not a live Cloudflare deployment. Miniflare was used temporarily and was not added as a dependency because its installed dependency tree had audit advisories. Application and committed tests remain dependency-free.

Cloudflare API contract checked against:
- https://developers.cloudflare.com/d1/worker-api/prepared-statements/
- https://developers.cloudflare.com/d1/sql-api/sql-statements/

## Still not a working service

No account sign-in or session management, client enrollment, management HTTP API, provider ingestion, rate limits, production key lifecycle or deployment is included. No real codes, secrets or accounts were used. No cloud resource or billing setting changed. Apply migrations only to an approved target; no production database binding is configured here.
