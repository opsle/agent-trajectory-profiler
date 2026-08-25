# Agent Trajectory Profiler

> Experimental Opsle research. Claims are hypotheses until evidence supports them.

## Problem

Final correctness, latency, token, and cost scores hide how much discarded or repeated work an agent performed.

## Hypothesis

Correctness-gated trajectory metrics can reveal material efficiency differences that final-result metrics miss.

## Mechanism

Reconstruct net and gross mutation, editing payload, semantic-region revisits,
and tool-evidence exposure from observable execution artifacts. Context
Firewall packet-v1 receipts become append-only trajectory events without either
upstream package becoming a runtime dependency.

The profiler also ingests the program-wide `opsle.value-receipt.v1` contract
from Context Firewall, Decision Evidence, and other conforming mechanisms. It
preserves measurement class and trust, builds deterministic per-run or
cumulative Opsle Value summaries, and aggregates only explicitly summable,
compatible observations.

## Why it matters

The Opsle thesis asks: **What if we stopped using intelligence for work that doesn’t require intelligence?** This project isolates one candidate boundary so it can be falsified and measured independently.

## Non-goals

Judging hidden reasoning, treating every revisit as waste, or comparing incorrect runs as if they were efficient.

## Context Firewall measurement profile

The profiler distinguishes raw evidence, the reduced packet initially exposed
to the model, retained and suppressed source evidence, additional evidence from
zero or more raw-evidence escalations, and final model-visible tool evidence.
Suppressed evidence that is never exposed adds zero model-visible bytes. An
unavailable escalation also adds zero bytes.

Initial reduction compares raw bytes with the initial packet. Effective
reduction compares raw available evidence with all tool evidence ultimately
exposed after escalation. Exact re-exposure is deduplicated within an operation
when content identity and byte size match.

Small packet-v1 results can be larger than their source because the packet
contains provenance and receipt overhead. Negative byte reduction reports that
expansion directly.

## CLI

The dependency-free CLI accepts a bare trajectory or a fixture wrapper:

```bash
./bin/agent-trajectory-profiler.js \
  profile \
  fixtures/context-firewall/high-reduction-success.json
```

Canonical machine JSON is always written to stdout. One concise
`[Trajectory Profiler]` completion indicator is written to stderr; `--quiet`
suppresses only that indicator. The legacy `--summary` flag is accepted as a
compatibility alias but no longer replaces machine output.

Profile an observational value record with:

```bash
./bin/agent-trajectory-profiler.js \
  value-summary \
  run-record.json
```

Pass multiple records, or `--cumulative`, for a cumulative summary. Use
`validate-record` for validation without summary projection. `npm test` and
`npm run conformance` require no sibling repository or mutable external state.
`npm run interop` remains the development proof against exact sibling Context
Firewall and Decision Evidence Protocol checkouts.

The package API exports packet/raw adapters, escalation-event construction,
trajectory validation/profiling/comparison, protocol constants, and canonical
measurement serialization from `src/index.js`.

The value API additionally exports receipt validation/identity, observational
run-record validation/identity, deterministic summary functions, and named
operator-indicator formatters. See [Visible Value telemetry](docs/VISIBLE_VALUE.md).

## Units and interpretation

Payload values are exact UTF-8 bytes. Evidence values are event counts. Neither
is a character, line, token, latency, or cost count. Optional token fields are
accepted only when labeled `PROVIDER_RECORDED` and remain separate.

Value-receipt aggregation partitions by mechanism, revision, configuration,
policy, measurement identity, unit, class, direction, and evidence trust.
Ratios, percentages, booleans, states, estimates, models, and experiments are
never directly summed. Missing observational fields remain missing.

**Payload reduction is not equivalent to token reduction unless token usage is
separately measured.**

**Reduced payload does not establish preserved model correctness.**

Those questions require EXP-001, which this repository does not run.

## Decision Evidence trust boundary

The adapter consumes the current Decision Evidence result rather than
duplicating its validator. It preserves source-backed verification,
structurally valid but source-unverified claims, and invalid/tampered states.
Invalid/tampered claims never produce aggregate measurements. A raw locator
means only that a caller supplied a locator; it does not establish existence,
immutability, or cryptographic protection.

## Current maturity

The repository is a verified narrow reference implementation under the
[Opsle lifecycle](https://github.com/opsle/research/blob/main/program/LIFECYCLE.md).
This does not establish comparative benefit or benchmark readiness.

## Existing evidence

A prior read-only execution analysis demonstrated that observable mutation and tool artifacts can be reconstructed. General predictive validity is unverified.

## Evidence still missing

EXP-001 task fixtures, correctness oracle, baseline/arm execution harness,
exact model configuration, randomized/blinded allocation, measured runs,
cross-model replication, semantic-region ground truth, and correlation with
independent quality judgments.

## Benchmark strategy

Correctness gates every comparison. Planned measures:

- correctness gate
- net mutation
- gross mutation
- mutation amplification
- edit payload amplification
- semantic region revisit rate
- revisit cause distribution
- tokens, cost, latency, and tool calls

See [BENCHMARK.md](BENCHMARK.md) for experiment rules. No benchmark numbers are claimed.

## Relationship to other Opsle research

This project is part of [Opsle Research](https://github.com/opsle/research). Opsle Tasks is the future public name of the integrated reference system from which several ideas emerged. Its active development migration to the Opsle organization is intentionally deferred.

## Relationship to future Opsle Tasks

Future Opsle Tasks may consume this project through an adapter only after evidence supports integration. The active predecessor, Taslos Tasks, remains unchanged and has no dependency on this repository.

## Installation status

A small dependency-free reference prototype is included for falsification and interface feedback. It is not production-ready.

## Known limitations

Deduplication is exact only within an operation when exposures share an explicit
content identity and byte size. Overlap with a different identity cannot be
proved safely and is counted in full. The adapter supports Context Firewall
packet-v1 only for trajectory-event construction; the Visible Value path accepts
any conforming Opsle receipt. Correctness preservation, token/cost savings, and
a safe reduction frontier remain unmeasured.

## License

Apache-2.0. See [LICENSE](LICENSE).
