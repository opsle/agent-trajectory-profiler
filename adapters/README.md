# Adapters

Adapters translate host-specific data into the generic protocol. The core must remain usable by Codex workflows, Claude Code, OpenAI agent systems, CI, GitHub Actions, Temporal, custom orchestrators, and future systems without importing a particular application.

`contextFirewallEventFromPacket` consumes a packet-v1 object, its canonical
bytes when supplied, and an existing Decision Evidence validation result. It
copies measurement and trust-boundary fields; it does not duplicate validation
or claim that a caller-owned raw locator exists.
