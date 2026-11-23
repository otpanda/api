# Persistent-session storage core, not live sessions

DeviceSessionService adds internal storage for the approved persistent-device policy. It is not mounted and does not change legacy same-origin SessionService. It does not set cookies, perform CORS, restore a browser, or connect native/extension storage.

A verified passkey-authentication result, used within two minutes, can create a session only if that credential is still active and the account security generation matches at the final SQL write. The result is an internal object, never a client assertion. Signup must obtain its own trusted completion-to-session path; a step-up result is rejected here. No proof object may be deserialized from a request.

Opaque refresh handles are hashed server-side; access handles expire in five minutes. Successful refresh rotates the handle and renews a 30-day inactivity window. There is no forced monthly reauthentication for a continuously used device. Access and refresh always join the live credential, device and account generation, so revocation/reset wins even after signature verification.

A rotation transaction has one successor. Concurrent requests receive a retry result without the successor secret; the browser must serialize rotation and wait for the winning response. Exact old-handle replay within ten seconds receives no credentials and does not revoke. Later exact replay revokes the device. Wrong secret never revokes. If the winning response is lost and no successor survives, sign-in is required rather than silently accepting an old token. No perfect concurrency recovery is claimed. Spent-handle history is bounded to thirty days; older missing handles deny generically. Cleanup itself is bounded.

Still required before any live session:

- Exact approved web origin/redirect checks, first-party HttpOnly API-host refresh cookie, PKCE one-use top-level restoration, short access only in memory, immediate callback cleanup and CSRF protection.
- Per-request authorization recheck at sensitive/data effects, rates and cleanup scheduling. An access authentication result alone cannot authorize a delayed effect after a security reset.
- Extension-origin nonexportable-key binding, trusted-context storage, fixed operation message boundary, installed-extension redirect verification and native secure-storage adapters. Client-kind labels here prove no platform security and must not enable those clients yet.
- Actual browser persistence/cookie-restriction tests. Browser deletion, tracking mitigation or cleared state can still require sign-in; no promise of permanent browser state.
- Real native recovery signing enrollment remains independent and does not expire with these inactivity sessions.

No raw private keys, refresh/access secrets or location history are stored by this schema. No auth endpoint is enabled by this increment.
