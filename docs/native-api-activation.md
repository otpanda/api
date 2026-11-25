# Native Android API: activation and route coverage

## Activation (default OFF)
`NATIVE_AUTH_ENABLED` must be exactly the string `1`. Anything else (unset, `0`, `true`, ` 1`) is off.

Off means:
- All nine native paths return 404 before any limiter, D1 or key access: `/auth/native/{exchange,challenge,renew,logout,approve,google/begin,google/complete}`, `/app-return`, `/.well-known/assetlinks.json`.
- A request with no `Origin` header is refused (403) on every `/v1` route, as before. Android tokens are not accepted anywhere.
- The runtime does not mount the native handler and passes `native:false` to every route factory.

The flag is part of the adapter's latched configuration vector. Changing it on a live isolate makes the host answer 503 until the isolate restarts.

Enabling also needs: migration `0039_native_sessions.sql` applied first, and `NATIVE_ASSET_FINGERPRINTS` set to the final app.otpanda signer(s) (assetlinks is 404 while empty). Native Google uses the adapter JWKS verifier. Set explicit NATIVE_GOOGLE_AUDIENCES to the web server client ID. Optional NATIVE_GOOGLE_AUTHORIZED_PARTIES pins azp only after real release-token semantics are verified. Android OAuth registration must match app.otpanda and the actual persistent release signer. Source tests do not establish provider or device acceptance.

## Routes that accept a native (android) access token when enabled
No `Origin` header, android token only. A web token without Origin, or an android token with any Origin, is refused.

- GET `/v1/manage/account`, `/session`, `/entries`, `/active-codes`, `/sources`, `/unassigned`
- GET and PUT `/v1/manage/organization`; POST `/v1/manage/organization-copy`
- GET `/v1/manage/totp-code?entry=`
- POST `/v1/manage/totp/begin`, POST `/v1/manage/totp` (still needs a user-verifying passkey step-up bound to the device)
- Native own routes above, including bearer logout.

The edge host allows no-Origin only for exactly this list, never for OPTIONS.

## Additional mounted native routes
- Realtime ticket and WebSocket accept the native session without Origin, with strict client-kind segregation. Native must listen, not poll.
- Assignment begin/finish/status support private confirmation and shared enrolled-device proof.
- Entry rename/account and device-key/approval routes are mounted behind the native flag.

## Still excluded for native
- `/v1/manage/totp-codes` is held for both web and native pending CPU qualification. It returns 404 without D1 access.
- Security/recovery and remaining passkey management routes are not made native by this release.

Native activation still requires a working installed release, App Links association, Pages handoff, real provider sign-in and device acceptance. Unit and local synthetic Worker/D1 tests are evidence only for their exercised paths.

## Cookies
`/auth/native/approve` rotates only the web `__Host-otpanda_device` refresh cookie and clears the native CSRF cookie. It reads, sets and clears no recognition/remember cookie. Tested.

## Kill switch
Setting `NATIVE_AUTH_ENABLED` back to anything but `1` stops native at once: native paths 404, no-Origin android tokens are refused on every `/v1` route including TOTP management (the runtime passes `native:false` to every factory, enforced in the runtime and the edge host). Nothing is deleted. Existing android devices and their keys stay in D1, so setting the flag to `1` again revives still-live devices (until their own expiry or revocation). To end native access permanently, revoke the devices.

## Native route added for the device list
POST `/v1/manage/session/describe` is also accepted for an android token (no Origin) when enabled, so a native client can send its device name (Build.MODEL / device name). Native sends `browser:null`; web sends `name:null`.

