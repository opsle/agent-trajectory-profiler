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
       ↓
opsle.value-receipt.v1 ingestion
       ↓
observational run record
       ↓
per-run or cumulative Opsle Value summary
```

## Ports

- Input adapter: translates raw baseline observations or packet-v1 plus an
  upstream Decision Evidence result into trajectory events.
- Core: validates append-only identities and exact byte/event accounting, then
  derives initial and effective reduction.
- Evidence store: immutable/content-addressed fixtures or caller-owned artifacts.
- Output adapter: canonical machine JSON on stdout.
- Operator adapter: exactly one stably named completion indicator on stderr,
  separate from canonical machine output.

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

Caller-supplied receipt timestamps are retained for display but removed from
receipt, run-record, and summary semantic identity. Receipt and measurement
ordering is canonicalized before summary hashing.

## Visible Value aggregation

The receipt validator is a dependency-free implementation of the normative
program contract, not a runtime import of the research repository. The run
record binds optional ordinary-use telemetry to one or more receipts. The
summary projection retains every operator-displayable measurement and creates
totals only for measurements explicitly marked safe for `SUM`.

Aggregation keys include mechanism revision, configuration, policy,
measurement identity, unit, class, direction, source verification, and material
evidence trust. Result-only measurements retain null baseline and delta totals.
Mixing result-only and baseline/result/delta shapes fails closed. Ordinary run
records reject `EXPERIMENTAL` measurements; controlled experiments remain a
separate evidence surface.
