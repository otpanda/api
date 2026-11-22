# Verification references

The tests use published test data only, never real account secrets.

- RFC 4226 Appendix D, HOTP test values: https://www.rfc-editor.org/rfc/rfc4226#appendix-D
- RFC 6238 Appendix B, TOTP vectors for SHA-1/SHA-256/SHA-512: https://www.rfc-editor.org/rfc/rfc6238#appendix-B

Run `npm test` with Node 22 or newer. No package installation is needed. The primitives use Web Crypto, which is also available in Cloudflare Workers. A real Worker integration test and deployment configuration remain future work.
