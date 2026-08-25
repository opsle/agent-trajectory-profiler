# Architecture

```text
raw tool evidence
       ↓
Context Firewall packet + validation
       ↓
initial model-visible exposure
       ↓
zero or more escalation transitions
       ↓
deterministic measurement projection
```

## Ports

- Input adapter: translates raw baseline observations or packet-v1 plus an
  upstream Decision Evidence result into trajectory events.
- Core: validates append-only identities and exact byte/event accounting, then
  derives initial and effective reduction.
- Evidence store: immutable/content-addressed fixtures or caller-owned artifacts.
- Output adapter: canonical machine JSON or a concise human summary.

## Independence

Host adapters are optional. No core module imports Taslos Tasks. Normal runtime
code imports neither Context Firewall nor Decision Evidence Protocol. The
cross-repository development verifier dynamically imports exact sibling
revisions only to regenerate and compare public fixtures.

## Determinism

Canonical semantic results contain no generated timestamp, random identity,
wall-clock latency, ambient filesystem path, or environment state. Event order
is supplied source data; object keys use canonical serialization. Runtime
profiling latency, if measured later, belongs outside semantic results.
