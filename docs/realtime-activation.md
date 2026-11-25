# Realtime staged rollout

The deployed source-only foundation did not add bindings, a new cron or an app client. All realtime routes, including preflight, return404 unless REALTIME_HUB and all three dedicated rate limiters exist. That source-only stage is now followed by the binding increment below.

## Deployment order

The existing main CI runs remote D1 migrations BEFORE deploying the Worker. Never merge0037 onto an old Worker whose guarded writes require exactly one D1meta.changes result.

0. Deploy the count-compatibility precursor first, without0037. Confirm its main deployment completed. This works on both0036 and0037 schemas.
1. Merge this source plus0037 stage. CI creates three realtime tables, indexes and row-writing triggers in productionD1, then deploys the inactive adapter and cleanup. This is a real schema and write-overhead change, not an activation-free/no-cost change. No existing business rows are backfilled or removed by0037.
2. Separately review and add the SQLite Durable Object namespace/class migration and three dedicated rate limiters. Check namespace collisions and current free-plan state before effects. Rate limits are engineering configuration to justify and test, not an arbitrary product-policy questionnaire.
3. Separately add the five-minute drain cron. The existing fifteen-minute identity cleanup remains unchanged in cadence.
4. Separately integrate and verify the app client and automatic reconnect/snapshot behavior.

The public entry must export only handlers and Durable Object classes. Local startup proof is tool/realtime-entry-startup-check.mjs against the dryrun bundle.

## Stage1 actual D1 effect and retention

0037 adds realtime_outbox, realtime_tickets and realtime_activity. Content-free invalidation metadata contains internal account/scope/device identifiers and, for former-share notifications, bounded recipient identifiers. It contains no OTP, label or message content. Calling it content-free does not mean it contains no private identifiers.

Triggers on existing tables add D1 reads/writes to ordinary mutations immediately after migration, even while no realtime routes or hubs are active. Matching unclaimed, unstarted pending rows coalesce. No tickets/activity should be created while routes remain unbound. Existing fifteen-minute cleanup deletes at most100outbox rows older than24hours per run, plus at most100old activity records and bounded expired tickets. This is a per-run work bound, not a hard24hour maximum retention guarantee: a backlog can take longer. There is no universal fixed one-row-per-scope storage bound. Stage1 must not be represented as zero overhead or zero account effect.

## Rollback

Before0037, precursor rollback is an ordinary code rollback. After0037, do not restore pre-precursor code while row-writing triggers remain: exact-count handling would be wrong. The safe source rollback floor is the deployed count-compatibility precursor. If inactive source deploy fails after migration, the precursor remains compatible, but new cleanup is not installed until deployment succeeds. Repair/redeploy promptly rather than assuming retention cleanup exists.

There is no automatic down migration. Disabling realtime bindings later returns routes404 but does not remove0037 triggers or their write overhead. Removing schema effects requires a separately reviewed forward migration that drops the0037 triggers, followed by intentional handling of realtime tables. Never run wrangler D1 time-travel or restore an old database as a routine code rollback.

For later active stages, keep the SQLite class migration declaration; removing a Durable Object class requires a separate deleted_classes migration.

## D1 change counts and local proofs

D1meta.changes includes trigger-written rows. Guarded unique-key mutations use >=1or<1; a failed guard still reports0. Exact affected-device counts use UPDATE...RETURNING and results.length. SQLchanges() in later batch statements excludes trigger rows and remains exact.

The test shim models total_changes deltas. The triggered-table guard test rejects unsafe exact checks near triggered writes, with explicit comments only for verified untriggered exceptions. tool/realtime-changes-parity-check.mjs compares the shim with local workerd D1 on22statements. Local rows_written is not Cloudflare billing evidence.

One authorized isolated platform qualification succeeded on25November2026: https://github.com/otpanda/api/actions/runs/45560194195 . Synthetic writer/outbox/hint, clean4401revocation, clean4408expiry and actual hibernation eviction were observed. Temporary Worker/D1/DO resources were verified absent. This is bounded functional evidence, not broad load/capacity or billing proof, and no further cloud qualification run is part of this stage.

## Binding increment

This increment adds only the SQLite Durable Object class/binding and three
native limiter bindings. It does not add a client or the five-minute drain
cron. Routes become available when all bindings exist, so this is a runtime
activation boundary even without a first-party client.

Limits per 60 seconds: address 30, aggregate 60, authenticated device ticket 12.
Cloudflare native limiters are approximate and per location. The aggregate
binding is not a strict worldwide counter or a spending cap. Namespace IDs
68022008 through 68022010 are separate from existing signup/identity limiters.
The hub retains at most 16 sockets per account and closes sockets at access
expiry. Relevant successful identity writes also begin the existing bounded foreground
drain once the hub is bound. Without the five-minute cron, delayed outbox rows
can wait for a later foreground drain. No mailbox, OAuth, sharing or
data-recipient permission changes.

Rollback: remove the three limiter bindings or the hub binding and deploy to
return guarded routes to 404. Keep the Durable Object class migration history;
do not reuse its tag or attempt to undo it by deleting persisted objects.
Migration0037 and its trigger write costs remain. Code rollback floor is
82ad9aa (the count precursor), not older exact-change-count code.


## Dedicated drain cron increment

Adds only `*/5 * * * *`, separate from the existing fifteen-minute identity
cleanup. Existing scheduled dispatch handles it in its own invocation and
returns before identity work. Each drain allows20D1queries and25hub calls,
combined45maximum. It skips without the hub; inactive accounts receive no hub
call. This adds288 scheduled invocations per day and real bounded D1/DO work,
not a cost-free background task. No new mailbox polling, client or permission.
Remove only this cron to stop periodic draining, foreground delivery remains.
Free plan remains required. Pending hints retry on later drains; no strict
five-minute delivery guarantee or paid capacity is promised.
