# Persistent-device web reads, not live authentication

This deliberately unmounted adapter accepts only short-lived web device access
handles in Authorization at the exact workers.dev API origin and exact approved
app Origin. It does not accept refresh cookies, legacy session cookies, Android
or extension access, or entry-scoped automation tokens as web user sessions.
CORS is explicit and never allows credentials. Read paths require GET with no
query parameters. Preflight permits only GET and Authorization. Trusted runtime
client address supplies rate-limit identity, not forwarding headers.

Entries preserve owner versus recipient capabilities. Shared recipients receive
only selected entry codes, never owner's unassigned codes or source metadata.
Existing source/share/envelope checks still apply. Device expiry, revocation and
security generation are checked again after decryption or database work, and
codes are filtered against the final clock before response.

There are no mutations, session issuance, email delivery, OAuth setup or cookie
changes here. Login orchestration and read runtime composition remain separate.
The deployed bootstrap still returns setup-required and authentication-disabled.
Native, extension, action-bound step-up, logout and sensitive account operations
must not be routed through this read-only browser adapter.
