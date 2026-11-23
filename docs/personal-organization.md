# Private cloud organization

The viewer's authenticated account owns tags, pins and ranking data, even for entries shared by someone else. Entry ownership is not preference ownership. Automation credentials cannot use this adapter. Preferences never grant code/source access.

Tags and pins use an optimistic document revision. Conflicts require a current snapshot, not silent overwrite or automatic retry. Inputs are bounded to100 tags,1000 entries and128KiB. Reads and writes filter/check current owned-or-shared access. A revoked entry is omitted, while private tags remain the viewer's.

Automatic ordering puts manual pins first, then a recent-copy score, then stable catalog order for ties. No count/reset/sort controls are exposed. A copy callback submits a random one-use receipt only after platform clipboard success. This is a client report, not cryptographic proof of a physical clipboard write. The server stores no code values, source labels or clipboard content in organization state. Failed copies and rendering do not count. No offline retry queue is installed.

Daily aggregate copies use a seven-day half-life and a ninety-day horizon. Each entry/day saturates at1000 successful receipts. Receipts are accepted for five minutes with30seconds clock skew, retained ten minutes for deduplication and capped at1000 per viewer. At most1000 recently copied entry identities per viewer are retained. Periodic fixed-batch cleanup removes old receipt/day rows. Server receipt time sets the bucket, not client-supplied time.

The HTTP adapter is composed inside the still-unmounted identity runtime. The deployed bootstrap continues to deny authentication and versioned routes. This feature does not enable sign-in, provider connections or public email sending.
