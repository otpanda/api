# Environment composition contract

`src/environment.js` parses provisioned bindings and composes the integrated host. It is not a deployed Worker entrypoint, and does not provision a database, register OAuth, generate keys or trust incoming forwarding headers.

Required bindings:

- `DB`: migrated D1-compatible binding with `prepare` and `batch`.
- `APP_ORIGIN`: exact HTTPS application origin, no path or trailing slash.
- `GOOGLE_CLIENT_ID`: registered Google web-client ID.
- `GOOGLE_CLIENT_SECRET`: OAuth client secret from protected deployment configuration.
- `ACTIVE_KEY_ID`: identifier of the active encryption key.
- `ENCRYPTION_KEYRING`: secret JSON array of objects with exactly `id` and `key`. Each key is canonical unpadded base64url encoding of 32 bytes. One to eight unique keys, including the active identifier. Retain old keys while encrypted records still require them. No example production keys are provided.
- `ASSETS`: optional static asset binding. Reserved API/auth routes never fall through to assets.

The deployment entrypoint must supply `trustedRequestKey`, derived only from verified platform metadata. Never select a client-provided forwarding header as identity. This adapter intentionally has no default resolver. The final platform adapter and its trust assumptions remain to implement and test before deployment.

Configuration is snapshotted when the host is created. Keys are imported as non-extractable AES-256-GCM keys on lazy runtime initialization. Secret fields are closure-held rather than enumerable properties. Runtime initialization is shared across concurrent requests to that host, failed initialization can retry, and separate host instances do not share configuration or key state.

Use a fresh host after rotation/configuration changes. An eventual entrypoint may cache by explicit immutable environment identity, but must not keep one global host across distinct binding/key configurations. Provisioning, key custody, real account connection and registered origins remain owner approval/setup work. This module does not replace those decisions.

`createConfiguredHost(env, {trustedRequestKey})` returns `fetch(request)` and `scheduled()` handlers. Initialization/request failures return a generic unavailable response; scheduled failures propagate so the platform can record a failed cleanup. Never log the environment, raw keyring or OAuth secret.

Synthetic tests cover invalid/missing bindings, origin restrictions, keyring validation, configuration snapshots, concurrent initialization, PKCE redirect creation without accounts/sources, no secret serialization, reserved-route isolation, discovery failure recovery and missing trusted metadata. They do not establish a real Google login, real D1 deployment, native authentication, provider source connection or production readiness.
