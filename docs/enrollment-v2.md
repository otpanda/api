# Seed-sync enrollment v2: API contract addendum (candidate, inactive, nothing deployed)

Base: v4.11 qualified source (api-v411-qualified-source). Patch: api-seed-sync-enroll-v2-fence.patch. Synthetic data only.

## 1. v2 enrollment action digest
actionDigest = lowercase hex SHA-256 of the UTF-8 bytes of
JSON.stringify(["seed-sync-enroll-v2", ownerId, installId, keyId, keyText, generation])
- keyId: native 32-hex id, /^[0-9a-f]{32}$/, directly after installId.
- keyText = JSON.stringify({kty,crv,x,y}), that member order (unchanged from v1).
- generation: JSON number.
- Passkey step-up action text stays "seed-sync-enroll:" + actionDigest.
- ENROLL proof message fields are unchanged: [ownerId, keyId, installId, generation, challenge, actionDigest, expiresAt]. keyId is the same native id.
- Vector for native: test/seed-sync-enroll-v2-vector.json (4 cases, preimage and digest; regenerate with tool/seed-sync-enroll-v2-vector-gen.mjs, synthetic keys).

## 2. Routes (POST /v1/manage/seed-sync/..., android bearer, no Origin, exact key sets)
- stepup-begin {installId, keyId, publicJwk}
- enroll-begin {installId, keyId, publicJwk, response, token}. The challenge returns the same keyId.
- enroll-finish {signature, token}. Unchanged.
- context {} returns {generation}: the caller's current live android session and account generation. A hint only. A wrong or stale value fails closed on the digest, passkey step-up and finish guards.
- A malformed keyId on stepup-begin or enroll-begin gives 400 invalid_request (shape only). Every state failure stays the opaque 409 {error:"unavailable"}.

## 3. Install-state fence (enroll finish)
Challenge columns (migration 0052, unapplied, edited in place): install_key_count, predecessor_key_id. Index seed_sync_keys(owner_id, install_id).
- Begin captures, inside the same INSERT that creates the challenge, n = rows (active or revoked) for (owner, install) and a = the active key id or NULL.
- Finish batch: [supersede UPDATE, key INSERT, notice INSERT].
  - UPDATE: revokes only the stored predecessor, only if n is unchanged, the new key id and (owner, public digest) are free, and the existing guards hold.
  - INSERT: only if n is unchanged, ids free, no active key for the install, (predecessor IS NULL OR changes()=1 from the directly preceding UPDATE), and the existing guards.
  - notice: only if changes()=1 from the key INSERT directly before it.
- Why timestamp-free: key rows are insert-only (nothing in src deletes seed_sync_keys; a test enforces it), so n only grows and revoked_at is only ever set. For equal n only the active key can change, from X to none. (n, a) therefore changes on every enrollment and revoke, from any path, and no revoke statement was touched.
- Retention caveat: a future job deleting old revoked key rows breaks the argument and needs a tombstone design first.
- Unchanged settled behaviour: revoke reasons, own-install revoke, remote revoke paths, status proofs (existing key-signed status, no new purpose), generation handling.

## 4. Reconciliation (adapter policy, for primary)
Existing key-signed status proves the stored key for that keyId is native's key and unrevoked at the pinned generation, because the key row is created only by a finish whose signature covered the full tuple, and no code updates owner, install, generation, jwk or key id. Opaque answers prove nothing (not-committed and transient look identical), so unknown outcomes stay pending. Never-confirmed key: only a verified "active" for the exact keyId confirms. KEPT from native apply is not confirmation.

## 5. Tests and evidence (local only)
- test/seed-sync.test.js: 36 pass (29 prior updated + 7 new): v2 digest binds the id, bad ids, late finish after newer enrollment, predecessor revoked in the same millisecond, no ABA after revoke, same pre-state second finish, id collision at finish, context, vector and no-key-deletion source guard.
- Mutation check: removing the changes() clause fails the same-millisecond test; removing the count check fails the no-ABA test.
- tool/seed-sync-d1-fence-check.mjs: Miniflare local workerd D1 (no network). 7 scenarios pass, including a real db.batch rollback, changes() 0 then 1 inside a batch, same-ms revoke and concurrent finishes (exactly one commits). This is local D1 semantics, not remote D1 or metered behaviour.
- Other suites run: triggered-table-changes-guard 2, totp-seeds 18, native-vector 3, recovery-controls 41, check:cpu-tools PASS. The full node --test suite exceeded the time limit and was not completed.

## 6. Not done or unverified
- No remote D1, deploy, access change or Kotlin or Dart work. Real remote D1 batch rollback and changes() are unproven.
- tool/cpu qualification calibration is tied to source commit; src, migrations and tool changed, so a recalibration is needed before any qualification run. The fence adds indexed reads per enroll begin and finish (CPU and rows-read evidence not re-measured).
- docs/seed-sync.md was not in the tar; this addendum should be merged into it.
