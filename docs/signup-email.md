# Signup email preparation

Internal-only `SignupEmailService` accepts a trusted request address, server-created browser cookie binding and an email,
then injects a transport callback. It does not import a provider, mount a route,
register a credential, or send on its own. No production activation is implied.
The callback receives a ten-minute opaque, one-use proof. Only its digest is stored, with the canonical recipient and cookie digest in a ten-minute receipt. A proof cannot initialize registration under another browser binding. The callback must not log this payload or include it in analytics.

The response shape is identical for existing accounts, suppressed requests,
success and transport failure. This does not claim timing indistinguishability:
a deployed HTTP boundary still needs a reviewed scheduling/response strategy.
Existing addresses receive no signup proof and should use sign-in/recovery. The
transactional first-passkey service enforces email uniqueness again at completion.

Quotas are conservative prototype safety limits, not user product settings:
five attempts/hour per trusted network address, three/hour per canonical email,
and 100 attempts/day globally. Address-denied requests stop before recipient/global buckets; recipient-denied requests stop before global. Suppressed requests consume only buckets reached.
This fails closed against mail floods but lets attackers exhaust a shared budget.
All quota keys are hashed by the existing rate-limit helper. There is no raw IP
persistence here, but hashing known addresses does not anonymize low-entropy data.
Existing bounded identity cleanup removes expired quota/proof records.

Rejected delivery consumes the proof and returns no provider error. A transport
may time out after delivering, so a failed request can invalidate an email that
arrives later. The UI must permit a safely rate-limited restart and never promise
that an accepted request means mail arrived. Callback hangs/storage failures are
not hidden by this layer and require bounded host orchestration. There are no
retry loops, resend timers, background queues or implicit billing actions.

Before real use: authorized provider credential and sending scope, reviewed exact
email/template and sender, non-tracking verification links or manual proof entry,
trusted client-address extraction, HTTP origin/body/rate/browser binding, clear
recovery-readiness warning, passkey ceremony and session composition, independent
review and realistic browser tests. New signup proves the mailbox and first
passkey only. This is not account recovery or a change to the paused device work.

Browser receipt allows at most five fresh ceremonies inside its original ten-minute lifetime after the first valid mailbox proof. Failures do not extend the lifetime or permit another browser. Each retry receives a fresh cryptographic challenge. Transport callback remains bounded by the injected adapter; HTTP scheduling is separately reviewed.
