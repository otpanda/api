# Realtime activation (HELD, inactive)

The adapter code is inert until ALL of these bindings exist: `REALTIME_HUB` (Durable Object namespace) and three dedicated rate limiters `REALTIME_ADDRESS_LIMIT`, `REALTIME_GLOBAL_LIMIT`, `REALTIME_TICKET_LIMIT`. If any is missing the realtime paths are 404, preflight included, and nothing is charged (tested through the public worker entry).

Held config (not applied here): `HELD-wrangler-realtime-activation.patch` adds the DO binding, a `new_sqlite_classes` migration for `RealtimeHub`, the `*/5 * * * *` cron next to `*/15`, and three limiter bindings. The limiter numbers in that patch (30 per 60 s per address, 60 per 60 s global, 12 per 60 s per ticket key) are PLACEHOLDERS that need an owner decision; they were not derived from any recorded policy. Namespace ids 68022008 to 68022010 continue the existing numbering and must be checked for collisions on the account.

Order: migration 0037 (D1) first, then deploy the code with the new bindings and DO migration, then the cron, then the client. Rolling back means removing the bindings (paths return to 404); the outbox rows then stop draining and age out through retention cleanup.

Overhead, counted through the public entry with synthetic bindings (not platform accounting proof): a relevant identity write spends 2 shared edge limiter binding calls (address and read/auth global), plus D1 queries (request and drain, metered) plus at most 10 hub calls, all under a combined 45 of the 50 subrequests. Ticket mint spends the 2 dedicated edge limiters plus 1 ticket limiter. Google callback paths are cron-only.

Cost and account implications to confirm before activation (Cloudflare Durable Objects pricing page, https://developers.cloudflare.com/durable-objects/platform/pricing/): Durable Objects are available on Workers Free only with SQLite storage, which is what the migration declares. Free limits are 100,000 requests per day and 13,000 GB-s per day, and exceeding them fails further operations instead of billing. Each hub call is one billed request, each socket upgrade is one, and incoming socket messages count 20:1. Duration is billed while a socket object is active and not eligible for hibernation, so the hub must stay on the hibernation API (it does; real hibernation eviction was not verified locally). On the Paid plan the same usage becomes metered billing. This account's plan is not known to this work. A Durable Object spending limit can be configured on the account.

## Staged activation (supersedes any single-PR order; this repo deploys on merge)

Patches live outside the tree (HELD-*.patch). Apply and verify one stage per merge:

1. Migration 0037 plus this code, no new bindings. Inert: realtime paths return 404 and nothing is charged. From here the D1 triggers write content-free outbox rows. Each trigger inserts only when no unclaimed row exists for the same (kind, account, scope), and `cleanupRealtime` (cron */15, 100 rows per run) deletes rows older than 24h. Expected steady state is about one row per active scope per day. Measure `rows_written` on the real D1 before moving on.
2. `HELD-stage2-do-binding-and-limiters.patch`: REALTIME_HUB (SQLite class, migration `realtime-v1`) and the three REALTIME_* limiters. Check the namespace ids against the account first. Run `node tool/realtime-entry-startup-check.mjs <bundle>` on the `wrangler deploy --dry-run --outdir` output.
3. `HELD-stage3-cron-5min.patch`: cron `*/5 * * * *`. The Worker only drains on this cron when REALTIME_HUB is bound.
4. App client.

Rollback: remove the bindings and the paths 404 again. The `realtime-v1` class migration stays declared; removing the class needs a separate `deleted_classes` migration.
The entry module must not export anything but handlers and Durable Object classes: workerd rejects other named exports at startup (REALTIME_CRON now lives in realtime-outbox.js).

## D1 `meta.changes` includes trigger writes

On D1 (workerd and Cloudflare) `meta.changes` is the connection's total_changes delta, so rows a trigger writes are counted. Migration 0037 adds row-writing triggers to incoming_codes, entry_shares, entries, sources, device_sessions, account_security, personal_organization and realtime_tickets.
- Single-key guarded writes on those tables must test `meta.changes>=1` (or `<1`), never `===1`. A failed guard still reports 0 because row triggers only fire for a changed row. For a real count use RETURNING.
- SQL `changes()` inside a later batch statement excludes trigger rows and is safe.
- Guards: `test/sqlite-helper.js` reports the D1-style count; `test/triggered-table-changes-guard.test.js` fails on an exact check following a write to a triggered table (annotate a verified exception with `/*exact-count-ok*/`); `tool/realtime-changes-parity-check.mjs` asserts the shim equals workerd D1 on 22 trigger-firing statements and prints local rows_written (not Cloudflare billing).
- Local rows_written per write after 0037, for sizing only: ticket insert 7, org write with no pending hint 6 (1 when a hint is pending), device revoke 6, entry_shares insert 8, incoming_codes assign 7, sources insert 9.
