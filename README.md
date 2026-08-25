# Agent Trajectory Profiler

> Experimental Opsle research. Claims are hypotheses until evidence supports them.

## Problem

Final correctness, latency, token, and cost scores hide how much discarded or repeated work an agent performed.

## Hypothesis

Correctness-gated trajectory metrics can reveal material efficiency differences that final-result metrics miss.

## Mechanism

Reconstruct net and gross mutation, editing payload, and semantic-region revisits from observable execution artifacts; classify why revisits occurred.

## Why it matters

The Opsle thesis asks: **What if we stopped using intelligence for work that doesn’t require intelligence?** This project isolates one candidate boundary so it can be falsified and measured independently.

## Non-goals

Judging hidden reasoning, treating every revisit as waste, or comparing incorrect runs as if they were efficient.

## Current maturity

**PROTOTYPE** under the [Opsle maturity model](https://github.com/opsle/research/blob/main/MATURITY.md).

## Existing evidence

A prior read-only execution analysis demonstrated that observable mutation and tool artifacts can be reconstructed. General predictive validity is unverified.

## Evidence still missing

Cross-model replication, semantic-region ground truth, near-zero net-mutation conventions, and correlation with independent quality judgments.

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

Cross-model replication, semantic-region ground truth, near-zero net-mutation conventions, and correlation with independent quality judgments.

## License

Apache-2.0. See [LICENSE](LICENSE).
