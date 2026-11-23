# Integrated entry read flow and dynamic services

Unknown services no longer require manual database additions: explicitly creating an entry atomically creates missing service metadata with a generic display name and no external icon URL. Logo availability never gates service support. No icon lookup network, scraper or third-party API is added.

`SourceEntryStore` can now use the typed service/source-origin matcher. With it injected, the old exact sender/account adapter is not consulted as an alternative authority. Missing or ambiguous matches stay unassigned.

`createEntryApplication` composes entry-based browser/API reads with sessions, membership, entry tokens and host-derived ingress rate limits. It deliberately does not mount the legacy service-only read route. Shared entry listings include service/account presentation metadata but not receiving phone/mailbox identities. Provider ingestion remains internal only: no public endpoint accepts unverified source events.

A synthetic integration test creates an unknown service and entry, identifies a phone source, adds an explicit receiver/origin route, encrypts a received code, shares the entry to a separate login, reads from a browser, separately allows automation, reads with an entry token, then revokes access and checks browser/API denial. It also checks no legacy route bypass or source-number disclosure.

This is a runnable test flow, not a completed product UI or a live provider connection. Real Google sign-in, source enrollment, invitation UX, provider validation, TOTP persistence under entries, Android and web/extension interaction still need integration. No deployment, key provisioning, paid resources or real account/code use occurred.
