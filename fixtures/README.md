# Deterministic fixtures

`context-firewall/` contains 14 public-safe measurement fixtures generated from
Context Firewall revision
`dd34bd9f681314761f1ca87f339648bf611811f3` and validated with Decision Evidence
Protocol revision `cc220abfa27a0bd20d80c481da09f6fe532bdabc`.

The corpus covers high reduction, normal and multiple failure regions, heavy
suppression, `NEEDS_RAW_EVIDENCE`, fulfilled/unavailable/multiple escalation,
exact re-exposure deduplication, zero suppression, exact payload boundary,
paired raw/reduced arms, source-unverified validation, source tamper, and receipt
tamper.

Every wrapper records its source fixture, canonical source-input hash, framed
raw-stream identity, packet identity where applicable, trajectory, and exact
expected profiler result. `context-firewall-manifest.json` binds each filename
to its complete SHA-256 digest. Normal tests and conformance read only these
checked-in artifacts.

The generator and interoperability verifier require exact sibling checkouts.
They are development proofs, not runtime dependencies or model experiments.
These fixtures are measurement results, not AI performance or cost results.
