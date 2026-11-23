# Multiple sources, entries and selected sharing

Implements the decisions confirmed November 23: several mailbox/phone sources, several accounts under one relying service, separate OTPanda identities, selected-entry read-only sharing, owner-only management, explicit assignment and private ambiguous events. Recipient automation needs its own owner-controlled permission.

## Model

- `sources`: owner-private Gmail, Outlook or SMS source records. This is metadata only, not a live connector or a linked account.
- `entries`: separate account entries. Service names are not unique, so personal and work accounts do not collapse.
- `assignment_rules`: owner-bound exact sender/account-discriminator rules behind an internal adapter. There is no public rule editor yet. Matching a sender string does not authenticate it; provider validation is still required.
- `incoming_codes`: source/event provenance, ciphertext, expiry and optional entry assignment. No match or more than one matching entry means unassigned. Manual owner confirmation encrypts the record again with the selected entry bound into AES-GCM authentication data. Replay cannot overwrite or reassign an existing event.
- `entry_shares`: an explicit recipient with read-only access and a distinct owner-set automation permission. No source access, edit, deletion or resharing rights are implied. Access checks query current membership before and after asynchronous decryption; revocation is not cached in tokens.

Tests cover multiple mailboxes/phones, same-service entries, unique and ambiguous rules, owner confirmation, cross-owner denial, replay, source revocation, encrypted storage, entry-substitution tampering, selected-entry sharing, owner-only management, automation permission and revocation during reads.

## Integration boundary

This milestone provides internal stores and authorization helpers, not new public HTTP endpoints, invitations or provider connections. The initial service-only token model remains foundation code and is not sufficient to authorize shared entry access. It must be replaced or adapted to explicit entry grants before the real application exposes these records. No source/entry records are auto-created. No external disclosure, real code connection, deployment or account linking occurred.

Sharing invitations, recipient discovery and acceptance UX remain to be designed. The code accepts an already resolved internal recipient account ID and does not infer identity from an email address. No seed or source export exists. Root-key lifecycle and production operations remain unfinished.
