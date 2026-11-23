# Service, account and origin metadata

Adds a service catalog record (name, optional website hostname and local icon asset key), an optional account name separate from entry labels, receiving source email/phone identifiers and typed service origin routes. No logo asset, network lookup or scraper is included.

A route links one service to a particular receiving source and one of: exact email sender, exact email domain or exact E.164 SMS sender. It may select a particular entry and optional account discriminator. Matching several entries/services or any unresolved service-only route leaves the event ambiguous/unassigned. Domain filters do not match suffix lookalikes or automatically include subdomains. Phone numbers must already be in E.164 format. Email local-part case, dots and plus tags are preserved rather than applying provider-specific guesses.

Matching metadata is routing, not proof of authenticity. An email From value or SMS sender can be spoofed. Provider-authenticated metadata and connector validation still need implementation. The receiving address/number must belong to the established source; an arbitrary event cannot select a different source owner. Shared-entry code access does not return receiving-source identity.

This module is an internal matcher and is not yet connected to ingestion HTTP endpoints or a rule editor. The earlier exact-match adapter remains separate foundation code; application integration must use the richer typed routes instead of treating both as competing authorities. No real message or code is processed, no external account is connected, and no sharing disclosure occurs.

The SQLite test helper now records applied migrations so reopen tests exercise ALTER migrations once, not repeat them. Existing tests use explicit insert columns. Tests cover receiver identity, origin types, suffix confusion, account ambiguity, owner isolation and local-only icon keys.
