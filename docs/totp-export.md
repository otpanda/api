# Sealed owner-only TOTP export (source only, not registered)

`createTotpExportHttp` in `src/totp-export-http.js`; seal in `src/totp-export-seal.js` (derived from seed-sync-seal at stage commit 2feae7c, which is not on this branch; own label `otpanda-totp-export-seal-v1`, so a sealed export never opens as a seed-sync batch). No migration, no storage, no email or notice, no plaintext fallback. Runtime registration is primary's.

## Wire (POST, JSON, every response `Cache-Control: no-store`, device session, owner only)
`/v1/manage/totp/export-begin` body `{ephemeralKey, entryIds?}`
- `ephemeralKey`: base64url of a 65-byte uncompressed P-256 public key (fresh per attempt).
- `entryIds`: optional explicit selection (1..200, unique). Omitted = every owned entry that has a server seed. An explicit selection that names a missing, foreign, shared-in or seedless id gets the same `400 invalid_request`.
- 200 `{token, options, expiresAt, entries:[{entryId, version, label, account, issuer, catalogId}], unavailable:[entryId]}`. `entries` is the frozen set, sorted by entryId. `version` = sha256 hex of the stored seed envelope (changes on any re-seed). `unavailable` = owned entries with no server seed (for example custody-only), never exported.
- 409 `passkey_required`, 409 `nothing_to_export`, 413 `too_many` (more than 200 usable; select a subset), 429.
- Step-up passkey (user verification required by the existing verifier), action `totp-export:<digest>`, binding `["totp-export", ownerId, deviceId, generation, digest]`. Digest = sha256 of `["totp-export-v1", ownerId, deviceId, generation, [[entryId, version]...sorted], sha256hex(raw ephemeral key bytes)]`.

`/v1/manage/totp/export-finish` body `{ephemeralKey, entries:[{entryId, version}] (exactly as returned, sorted), token, response}`
- Stateless: the server stores nothing at begin. Finish recomputes the digest from what the client echoes, so a swapped key, changed set or changed version fails the ceremony (403 `reauthenticate`, ceremony consumed, start again).
- After the proof the set is re-read with owner-only SQL and must equal the echoed versions exactly, else `409 changed` and nothing is sealed. The session and active credential/provider are checked after decryption. After sealing, one final D1 statement checks the live method/session/generation plus exact envelopes and metadata for the entire frozen set. A concurrent change returns409 with no ciphertext. This final read is the response linearization point, not a claim that later revocation can retract a response already authorized.
- 200 `{serverPublicKey, entries:[{entryId, version, label, account, issuer, algorithm, digits, period, nonce, ciphertext}]}`. Ciphertext = AES-256-GCM of the raw seed bytes under HKDF(ECDH(server ephemeral, client ephemeral)), salt = action digest, info `label|sha256(client key)|sha256(server key)`. AAD (client rebuilds it itself): `["otpanda-totp-export-seal-v1", ownerId, deviceId, generation, entryId, version, algorithm, digits, period, actionDigest, sha256hex(client key), label, account, issuer, catalogId]`. Labels, account, issuer and catalogId remain clear over TLS but are authenticated in AAD; a response substitution fails decryption. The final read refuses metadata changed while sealing. Client validates the begin metadata for display, and must not treat returned metadata as authenticated until open succeeds.
- Rate limit: 6 per owner per hour on each step, 20 per minute per address, counted before parsing.

## Outcome semantics
Export writes nothing, so there is no server outcome to read back. A lost reply is unknown: the client discards state and, only on the user's action, starts a new attempt with a new key and a new passkey prompt. Never auto-retry. A replayed finish gets 403 (ceremony spent) and yields nothing.

## Gates still open
Runtime registration, real D1 and real WebAuthn/Android qualification, client sealed-box opener (the reference opener is `openExport` in the seal module), owner notice (none implemented by request), whether 200 entries and 32 KiB body fit the client, key zeroing on the client.

Primary review:17 focused tests PASS including five during-sealing revocation/delete/reseed/metadata/generation races. Independent Python cryptography opener verified P256 ECDH/HKDF-SHA256/AES-GCM and metadata-tamper refusal against a synthetic Node-sealed vector. Not installed client proof. Bounded readLIMIT201 refuses oversized owned inventory rather than silently truncating.
