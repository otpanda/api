# Public service-recognition suggestions

Internal implementation of the requested shared recognition catalog. It does not read users' messages, learn global mappings from private traffic, route a code, select an account, authenticate a sender or make a network request. No live connector or HTTP route is mounted.

`ServiceCatalog` takes bounded public service metadata and separate explicit sender evidence. Service names and website hosts alone never imply an email or SMS sender. A future directory importer may supply service metadata, but must not turn directory domains into sender rules. A future public-source importer must verify and record the evidence itself, not trust a page claiming approval.

Sender records require an HTTPS support-page reference on the service's exact website host or a subdomain, checked/expiry times with at most90days validity, and a stable mapping ID. URL credentials, query strings, fragments, explicit ports and local/numeric hosts are rejected. This validates record structure and provenance boundaries only. A hostname or supplied evidence record does not prove the page contains the claim. Retrieval/review remains the importer's responsibility. External text cannot approve or activate mappings.

Email addresses preserve local-part case and plus tags. Domains are ASCII-normalized, matched exactly, never by arbitrary suffix. SMS E.164 numbers are exact. Short codes and alphanumeric sender names are separate kinds and require an explicit two-letter country context; no country is guessed and case is preserved. One sender may suggest several services. Results keep all matching candidates and report ambiguity. No preferred first candidate silently wins.

Expired/future evidence is ignored. The snapshot is copied so caller mutations cannot change later suggestions. Limits:1000 services,5000 mappings,2MiB serialized UTF-8. Lookup is a bounded scan; results contain only public service metadata and evidence references, never a code, source, receiver, private account or raw observed sender. Matching results are suggestions, including when only one service matches.

## Next integration steps, not activated here

- Acquire a licensed public service-name seed with provenance and update rules.
- Retrieve explicit official support evidence for senders, without private-message training.
- Add review/import persistence and a periodic public refresh under the approved deployment scope.
- Show suggestions in the owner-private unassigned-code workflow, distinct from provider authentication and explicit per-source account routing.

Neither public crawling nor suggestion UI/data collection is enabled by this module. Existing source authentication, account discrimination and selected-entry sharing remain unchanged.

## Offline directory adapter

`importDirectoryV3` consumes a previously fetched UTF-8 JSON snapshot, at most4MiB/5000rows. It extracts only service names and ASCII website hosts. Contact emails, documentation text/URLs, notes and alternate domains are deliberately ignored, so the import creates zero sender mappings. Invalid rows are reported by index without echoing text. Conflicting duplicate identities stop the import. Output uses bounded1000-service shards without dropping overflow records, stable ordering, attribution, fixed source URL and supplied fetch timestamp/SHA-256. The caller must compute the supplied hash from those bytes. It is provenance, not a signature-validation claim; `signatureVerified` remains false.

The official API guidance at https://2fa.directory/api documents supported v3 (names included) and v4 (names removed), MIT attribution, caching and signed datasets. A live unsigned v3 snapshot from https://2fa.directory/api/v3/all.json was locally imported on23November2026:2575 services,0 rejected rows,3shards. This was a development smoke test, not a bundled live catalog, background refresh or signature-verified source. No official-support sender mappings were inferred from it.

SMS format reference: https://www.twilio.com/docs/messaging/services/alphanumeric-sender-ids-in-messaging-services. The engine accepts a conservative ASCII subset rather than guessing carrier rewriting or fuzzy-equivalent names.
