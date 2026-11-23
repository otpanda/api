# Temporary ingress verification

The one-bit setup probe is bootstrap-only, with no auth, cookies, CORS, data access,
mail, rate-limit calls or logging. The random path is public source, not a secret
or authorization. Its exact workers.dev origin matches the dashboard Visit link.

Remove the probe import and dispatch, probe module, and its temporary mount test
immediately after recording live evidence in the following cleanup PR. Do not
mount signup or change to a live stage while the probe exists. The normal health
response must continue to state authentication disabled throughout this work.

An independent internet caller tests actual genuine-client acceptance, then
forged CF-Connecting-IP plus equality expectations for the documentation address
and its own known egress address. Results never return either address. A forged
CF-Worker header tests refusal but is not a real Worker subrequest. Cross-account
subrequest behavior remains documented, not tested, without a second account.
The optional same-script subrequest has a two-second abort: 1 is unsafe, 0 is
refusal for an unknown reason, and 503 is inconclusive, including provider loops.

The fixed cross-zone IP and CF-Worker behavior come from:
https://developers.cloudflare.com/fundamentals/reference/http-headers/
