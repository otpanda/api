# Common-horizon production-runtime qualification

This directory is an isolated synthetic fixture. No real users, enrollment or production-host activation. Worker imports actual createIdentityRuntime, seed cipher, planner, generator, session authentication, permission-envelope revalidation and HTTP finalization at this source commit.

The GitHub workflow creates a temporary D1 database, applies repository migrations and synthetic encrypted fixture, deploys an isolated path-prefixed Worker, makes 12 sequential authenticated requests, records request D1 query counts and wall durations, captures Cloudflare tail CPU/wall events, then deletes Worker and database. Cleanup trap executes on failure too. Never interpret wall duration as CPU.

Test policy only: entryCap1, total-code budget32, period20..86400, maxWindow600, minUsefulWindow60, rate24/min, minRemaining1000ms. These numbers are NOT production defaults. Two one-entry fixture groups each run windows600/60 (600 first for cold request) in three rounds. Fixed synthetic clock and keys are only test data.

Run through .github/workflows/common-horizon-qualification.yml, which runs only when release.yml calls it before a production deploy (no push or dispatch trigger). Cloudflare secrets already established in CI. Local equivalent requires Miniflare/wrangler and repository migrations; local timing is functional/wall only, not Cloudflare CPU. Generated bundle and local driver are not the durable remote evidence. Results artifact includes exact workflow source commit, aggregate result and tail events. Check cleanup log confirms absence.
