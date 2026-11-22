# Scoped access tokens

Second layer on top of the security-core foundation. It implements how
automation clients authenticate: random opaque bearer tokens, stored only as
digests, verified against expiry, revocation and not-before state, and reduced
to a grant record that the existing pure policy (`src/grants.js`) authorizes.

This is still a foundation. Nothing here touches real codes or secrets, and
there is no production storage or user-facing management API yet.

## Token format

`otpda_` + base64url(id || secret): 9 random bytes of public id followed by 32
random bytes of secret, 61 characters total. The id locates the record; the
secret authenticates it. The charset and length deliberately satisfy the
extension client's bearer acceptance rule (`/^[A-Za-z0-9_-]{32,512}$/`), so the
two codebases agree on one format.

The store keeps only `SHA-256(secret)`. Plain SHA-256 is sufficient because
the secret carries 256 bits of entropy: there is no password-guessing surface
to rate-limit offline. The raw token is returned exactly once at mint time and
must never be logged or persisted.

## Verification rules (`src/verify.js`)

- Malformed input (wrong prefix, bad alphabet, wrong length, oversized,
  non-canonical encoding) is rejected without throwing.
- Unknown id, wrong secret (constant-time digest comparison), revoked,
  expired and not-yet-valid tokens are each rejected with a distinct reason
  code for server-side use. Expiry is inclusive: a token dies the instant
  `now` reaches `expiresAt`.
- Optional `leewayMs` (bounded to 5 minutes) only ever widens acceptance for
  clock skew; it defaults to zero.
- On success the caller gets a frozen grant object derived entirely from the
  verified record: owner, client, service and scopes never come from request
  input.

## Edge behaviour (`src/http.js`, `src/worker.js`)

Every authentication failure, whether the header is missing or the token is
malformed, unknown, tampered, expired or revoked, produces the same 401 with
the same body and headers. Tests assert the bodies are byte-identical so the
edge cannot be used as an oracle.

The Worker wires this in:

- `GET /v1/auth/check` authenticates and echoes the derived grant (scope and
  expiry self-inspection; no codes or secrets reachable).
- `GET /v1/codes/latest?service=...` authenticates, then applies
  `permitsCodeRead` so the grant's service binding must match the requested
  service; mismatches get 403, a full match still gets 501 because code
  storage does not exist yet.
- All other `/v1/*` paths remain 501. The default handler uses an empty
  in-memory store, so out of the box every authenticated route stays closed.

## Deliberately still missing

- A user-authenticated management API for minting, listing and revoking
  tokens. Today records can only be created in tests; never accept owner
  identity from an untrusted request body.
- Durable storage (Cloudflare D1 or KV) implementing the async store contract
  in `src/token-store.js`.
- Rate limiting, metadata-only audit logging, and replay considerations for
  intercepted tokens (short TTLs are the current mitigation).
- Key lifecycle: rotation, recovery and the documented compromise model from
  `docs/security-boundary.md` item 3.

This layer is not a security audit and not production-readiness approval.
