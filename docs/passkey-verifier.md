# Passkey verifier adapter

Internal verification component only, not a working sign-in route. The deployed bootstrap remains setup-required. Uses pinned SimpleWebAuthn14.1.0 rather than implementing WebAuthn parsing or signature validation ourselves.

## Fixed policy

RP ID is otpanda.github.io; website origin is exactly https://otpanda.github.io. All project paths on this origin share its trust boundary. New credential options require discoverable resident credentials, user verification and presence, attestation none, ES256 or RS256. No hardware-attestation claim is made about passkeys. The provider can sync supported credentials; backup flags are not a guarantee of independently recoverable backup.

Android origins default to none. Add only verified release certificate hash origins after stable package/signing identity and root Digital Asset Links are in place. A caller cannot pass arbitrary web origins. No debug/release fingerprint is fabricated.

Challenges are canonical base64url32random bytes, converted to bytes before giving the library options generator. The library treats string challenges as UTF8, so passing an already encoded challenge directly would double-encode it. Tests explicitly assert exact challenge roundtrip.

Verification requires expected challenge, exact origin, RP hash and user verification through the library. Registration/assertion results return the library's verified credential/metadata. The HTTP orchestrator must not accept verifier dependencies or expected values from requests.

## Integration still required

Store credentials with owner binding, counter, backup/device metadata and revocation. Store challenge/action/session/owner binding server-side with a short expiry and atomic one-use claim. Signup must bind verified email and first credential atomically. Check assertion credential ID and userHandle against intended owner; do not select an account from caller input alone. Update counters using compare-and-swap and recheck revocation before authorization. Synced credentials may have zero counters; one-use server challenges are still required. Credential addition/removal and recovery must enforce action-bound step-up. No plain cookie or client biometric-success flag is equivalent to fresh proof.

## Verification performed

121tests across API. Six adapter tests exercise generated policy/challenge bytes, a real synthetic ES256 attestation-none registration and signed assertion through the actual library, wrongRP/origin/challenge, missingUV, forged signatures, counter replay, Android origin allowlisting and malformed input. Actual local Workers runtime generated options200 with correctRP and UV; dry-run dependency bundle approximately710KiB/130KiB gzip. Audit reported0vulnerabilities. Browser/device ceremonies, RSA assertions, remote Workers verification and final HTTP/storage integration remain unverified. Local synthetic fixtures never represent real user credentials.
