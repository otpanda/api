// Shared row budget for the seed-sync qualification run: used by plan-gate.mjs (headroom), checks.js (per-request cap) and driver.mjs (cumulative ceiling).
// Local measured envelope: migrations 553 written / 8,501 read; the 14 checks about 405 written, under 800 read (largest check: 42 written, 115 read).
export const CEILING = { writes: 5000, reads: 50000 };
// Charged up front for wrangler migrations apply (all files, incl. its own d1_migrations table rows), whose real count the driver cannot see.
export const MIGRATION_ALLOWANCE = { writes: 1500, reads: 20000 };
// Enforced inside each Worker request: after a statement pushes the request past this, later statements throw. A single statement can still overshoot by its own row count.
export const PER_REQUEST_CAP = { writes: 200, reads: 1000 };
// True when one more request, if it used its full cap, still keeps the cumulative total within the ceiling. Stop-before-next rule.
export const mayStartNext = cum => cum.writes + PER_REQUEST_CAP.writes <= CEILING.writes && cum.reads + PER_REQUEST_CAP.reads <= CEILING.reads;
// Bound on how far a run can exceed the ceiling: the last admitted request stays under its cap except for one final statement (a statement here touches at most 3 rows
// of data, each with a few trigger and index rows; 60 is a generous per-statement bound). Beyond that is unverified in-flight overshoot.
export const IN_FLIGHT_OVERSHOOT = { writes: 60, reads: 200 };
