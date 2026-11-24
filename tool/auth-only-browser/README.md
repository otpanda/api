# Local synthetic auth-only browser check

Run `npm ci` at the API root first. Use Node22+, OpenSSL and Chromium dependencies. Then:

```sh
cd tool/auth-only-browser
npm ci
npx playwright install chromium
mkdir -p /tmp/otpanda-auth-screens
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -keyout /tmp/otpanda-test.key -out /tmp/otpanda-test.crt -subj /CN=otpanda.github.io
OTPANDA_APP_ROOT=/absolute/path/to/otpanda-app TEST_TLS_KEY=/tmp/otpanda-test.key TEST_TLS_CERT=/tmp/otpanda-test.crt TEST_SCREENSHOT_DIR=/tmp/otpanda-auth-screens node check.mjs
```

App source must include `tool/session-bootstrap.js` from App39 (55344a4). No production network is used for app/API requests: Chromium maps both exact hostnames to the local HTTPS server. Mail is intercepted and synthetic. Local certificate validation is disabled only in this test browser. The virtual authenticator proves the WebAuthn protocol, not real OS/hardware behavior. TLS test keys are local disposable fixture material, never account credentials. The server binds loopback on8443; that port must be free. All migrations run on ephemeral local D1. No real account or delivery is created. The test checks signup, login and restore, session read and excluded route refusals. Screenshots are harness/API-form evidence, not final app UI evidence.
