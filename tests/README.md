# Test strategy

Tests must map to named invariants in SPEC.md, include adversarial failure cases, and separate implementation correctness from evidence for the broader hypothesis.

The packet-v1 suite asserts exact byte/event totals, escalation transitions,
deduplication, invalid-state detection, canonical output, immutable fixture
expectations, and exact-revision interoperability without model/provider runs.
