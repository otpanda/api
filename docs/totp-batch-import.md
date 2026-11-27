# TOTP batch import (source only, not registered)

Routes (owner session, POST, JSON, `Cache-Control: no-store`): `/v1/manage/totp/batch-begin`, `/batch-finish`, `/batch-outcome`. Nothing mounts them; primary composes `createTotpBatchImportHttp` in the runtime.

- Items: 1..50 per batch (body cap 64 KiB). Each item has exactly `label, account, secret` and optional `catalogId`, validated with the same rules and parsers as the single add (digits 6 to 8, any period). One bad item rejects the whole request with `400 invalid_request`, no index or secret echoed. Larger reviews are not chunked: the client must show the 50 limit before confirmation.
- `batchNonce`: required, 22 to 64 chars of `[A-Za-z0-9_-]`, owner scoped, kept for the account lifetime, even after the imported entries are deleted.
- Action digest = sha256 of `["totp-batch-import-v1", ownerId, deviceId, generation, batchNonce, [[label, account, catalogId|null, sha256(secret)]...]]` (secrets only as hashes; the nonce is added to the proposed contract so a token is bound to one attempt). One passkey step-up, action `totp-batch-import:<digest>`.
- Finish re-sends the items (stateless). After the proof, every seed is encrypted, then ONE `db.batch` runs: guard (session still live), nonce row, all entries (one `json_each` insert), all seeds (one insert), a count assertion, all through `tx_assert`. Any failure rolls back everything. The statement count does not grow with the item count.
- Result: `201 {status:'saved', entryIds}` in request order.
- Repeated nonce: same digest returns the stored result (`200`, no new rows, no new prompt at begin); a different digest is `409 nonce_reused`. A concurrent double finish loses on the primary key and returns the stored result.
- `batch-outcome {batchNonce}` returns `{status:'saved', entryIds}` or `{status:'none'}` for the calling owner only. A client that lost a reply reads this before telling the user anything. `none` means no committed record was visible at that instant. It is NOT a definitive failed result, even after the client timeout. Keep an unknown outcome visible, reconcile again, and retry only the exact batch with the same nonce. A new ceremony may be required if the old ceremony was consumed; never automatically use a new nonce.
- Replay of a spent ceremony token is the existing step-up behavior, `403 reauthenticate` (the proposal said 409).
- Migration `0064_totp_batch_imports.sql` (additive): `(owner_id, batch_nonce)` primary key, digest, entry ids, time. No secret or label is stored. Nonce records are permanent until account deletion. Do not prune these records without a separate durable replay-prevention design.

Not done here: runtime registration, rate-limit tuning, the web/native client saver, real D1 qualification (tests use node:sqlite, which is not a substitute), export.
