# Entry-scoped automation grants

Replaces the service-name assumption for the new entry model with a separate entry-token store and read handler. This layer is not wired to a deployed application.

- Tokens name the acting OTPanda account, client and one entry ID. They store only credential digests.
- Owners can grant access to their entries. Recipients can mint an automation token only while the entry owner has separately allowed automation.
- Reads verify token state and current entry permission, then recheck after asynchronous code decryption. Querying a different entry fails, even when its service name matches.
- Revoking sharing or removing automation permission atomically revokes the recipient's existing entry tokens. Granting permission again does not revive old tokens. Owner-only source and entry management remains unchanged.
- No source metadata, message text or sender detail is returned with a code.

Tests cover shared-entry permission, wrong-entry reads, recipient/owner isolation, expiry, token revocation, membership revocation and permission removal/regrant. Existing source/sharing tests still run.

The old `/v1/codes/latest?service=...` foundation handler remains separate and cannot read the new incoming-code table. Before a real deployment, application routing must use the entry-based handler and management UI, not expose both models as if interchangeable. No migration of real tokens is needed because no real service exists.

Google-first sign-in is the selected product direction. Actual Google OAuth registration, callback origin, provider consent configuration and key provisioning remain undone. Mailbox connections stay independent of sign-in identity. This PR does not create registrations or connect accounts.
