# Initial key provisioning review

Status: reviewed local candidate, not published, no provider changes.

The initial aggregate binding is immutable. Provider custody retains it across deploys; it does not permit reconstructing it for replacement/rotation. A later versioned binding/combining adapter or separately approved per-key custody is separate work. No independent provider-account-disaster backup is claimed.

The migration creates a permanent nonsecret attempt reservation. The script checks bootstrap health, names-only secret metadata, absent reservation and zero rows across code_records, incoming_codes, oauth_transactions and totp_seeds. Its atomic reservation repeats the row-count guard before random generation. Any prior attempt stops a new generation, including after bindings are deleted. No automated repair or rotation exists.

The production boundary will use a manually dispatched main-only workflow, pinned actions and no npm installation in the secret-bearing job. It must share an serialized production concurrency group with cancel-in-progress false with every deploy. The proposed CLI has explicit CI/main/repository/manual-confirmation guards and a fixed production health destination. It must not be dispatched before independent review and fresh live preflight. The intended final native Node process receives only the existing CI token and generates 32 bytes in memory, uploading a single secrets-bulk PATCH with merge-patch content type. It prints no provider bodies/errors, key values, headers or requests. No shell tracing, debug, output/env files, key masking command, cache, artifact or subprocess receives generated material. Native strings cannot be reliably zeroed; the random buffer is wiped on exit from the operation and the process terminates.

Bulk creates one version with supplied changes, not a documented exactly-once/transactional guarantee. No automatic retry is permitted. On uncertainty the attempt marker remains. Read-only metadata/readiness reconciliation determines whether a write landed; missing/partial state is a stopped attempt for deliberate review, never a new random key. Both names already present are preserved; this draft stops for a separate readiness check rather than treating metadata as cryptographic proof.

Before actual execution: recover original owner scope, independently review exact patch and mocked failure/leak tests, verify fixed account/Worker/database, current production bootstrap and token read capability, confirm existing key names absent and counts zero, deploy the reservation schema without provisioning, then permit one reviewed dispatch. After provisioning, verify /ready and auth503, deploy unchanged bootstrap once and verify retention/readiness again. No sign-in activation is bundled.

Sources:
- https://developers.cloudflare.com/workers/configuration/secrets/
- https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/secrets/methods/update/
- https://developers.cloudflare.com/api/resources/workers/subresources/scripts/subresources/secrets/methods/list/
- https://developers.cloudflare.com/api/resources/d1/subresources/database/methods/raw/
- Locked Wrangler4.166.0 source provides the secrets-bulk merge-patch request shape. Source-backed investigator independently confirmed the same shape; bulk transactionality is not assumed.

The marker state `bindings_written` records only reconciled binding metadata, not cryptographic readiness. The CLI then checks /ready and both auth/read route503 gates using fixed destinations. A read-only --verify-only mode repeats those checks without any generation or provider token use. After an unchanged bootstrap redeploy, run that read-only verification again. Full cryptographic nonextractable import is checked by /ready; no ciphertext round-trip or general rotation guarantee is claimed.

Concurrency prevents overlapping lock-bearing jobs and does not cancel an active job automatically. It does not prevent manual cancellation, pending-job replacement, old pre-lock runs or dashboard writes. Wait for the new migration/lock deployment, verify older deploys finished, and freeze other writes for the bounded initial operation. Use the workflow verify-only choice for token-free checks after redeploy, not another provisioning attempt.
