// Fail-closed qualification gate. Runs before any scratch resource is created. It trusts nothing stored: it passes only for values supplied at dispatch
// by someone who has just read the authenticated Cloudflare dashboard, and only while they are fresh and bound to this account and this exact commit.
// There is no standing permission: absent, malformed, stale, future-dated, mismatched or over-budget input exits 1 and nothing is created.
// The observed plan is a dashboard reading supplied by the dispatcher. Nothing here proves it, so the dispatcher must have verified it.
// The budget is the run's ENFORCED ceiling (seed-sync/budget.mjs, used by the driver's cumulative metering), not just headroom. Local measured envelope:
// about 400 rows written by the 14 checks plus about 550 for migrations, and under 10k rows read.
import { CEILING } from './seed-sync/budget.mjs';
const BUDGET_WRITES = CEILING.writes, BUDGET_READS = CEILING.reads;
const FREE_WRITES = 100000, FREE_READS = 5000000, FREE_DBS = 10, HEADROOM = 0.5, MAX_AGE_MS = 30 * 60 * 1000, SKEW_MS = 2 * 60 * 1000;
const e = process.env, stop = why => { console.error('Qualification gate closed: ' + why + '. No resources were created.'); process.exit(1); };
const num = (k) => { const v = e[k]; if (!/^\d{1,9}$/.test(v ?? '')) stop(k + ' missing or not a non-negative integer'); return Number(v); };
if (e.GITHUB_EVENT_NAME !== 'workflow_dispatch') stop('only an explicit dispatch may run this');
if (e.GITHUB_RUN_ATTEMPT !== '1') stop('re-runs are refused: dispatch again with fresh observations');
if (e.GATE_PLAN !== 'workers-free') stop('observed plan must be exactly workers-free');
if (!/^[0-9]{6,20}$|^[0-9a-f]{32}$/.test(e.CLOUDFLARE_ACCOUNT_ID ?? '') || e.GATE_ACCOUNT_ID !== e.CLOUDFLARE_ACCOUNT_ID) stop('observed account does not match the account this run will use');
if (!/^[0-9a-f]{40}$/.test(e.GITHUB_SHA ?? '') || e.GATE_COMMIT !== e.GITHUB_SHA) stop('observation is not bound to this exact commit');
if (!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?Z$/.test(e.GATE_OBSERVED_AT ?? '')) stop('observation time must be ISO UTC ending in Z');
const seen = Date.parse(e.GATE_OBSERVED_AT), now = Date.now();
if (!Number.isFinite(seen)) stop('observation time unreadable');
if (seen > now + SKEW_MS) stop('observation time is in the future');
if (now - seen > MAX_AGE_MS) stop('observation is older than 30 minutes');
// Daily counters reset at 00:00 UTC: refuse an observation from a previous UTC day and any run in the last 10 minutes of a day.
const day = t => new Date(t).toISOString().slice(0, 10);
if (day(seen) !== day(now)) stop('observation is from a different UTC day than now (daily counters reset at 00:00 UTC)');
const toMidnight = Date.parse(day(now) + 'T00:00:00Z') + 86400000 - now;
if (toMidnight < 10 * 60 * 1000) stop('too close to the UTC daily reset');
const writes = num('GATE_DAILY_WRITES'), reads = num('GATE_DAILY_READS'), dbs = num('GATE_DB_COUNT');
if (writes + BUDGET_WRITES > FREE_WRITES * HEADROOM) stop('observed daily rows written plus this run budget exceeds 50% of the Free daily cap');
if (reads + BUDGET_READS > FREE_READS * HEADROOM) stop('observed daily rows read plus this run budget exceeds 50% of the Free daily cap');
if (dbs + 1 > FREE_DBS - 2) stop('observed database count leaves less than 2 spare of the Free 10 once the temporary database exists');
console.log('Qualification gate open for this single run: observed ' + e.GATE_OBSERVED_AT + ', commit ' + e.GITHUB_SHA.slice(0, 12) + ', daily writes ' + writes + ', reads ' + reads + ', databases ' + dbs + '. Row budget: ' + BUDGET_WRITES + ' written, ' + BUDGET_READS + ' read.');
