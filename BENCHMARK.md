# Benchmark plan

## Rule zero: correctness gate

Efficiency results are comparable only when every candidate passes the same deterministic correctness and safety gates. Incorrect, indeterminate, and policy-violating runs remain visible but are excluded from superiority claims.

## Baselines

1. Current conventional mechanism without this project.
2. The narrowest deterministic alternative.
3. This project at an exact revision and configuration.

## Measurements

- correctness gate
- net mutation
- gross mutation
- mutation amplification
- edit payload amplification
- semantic region revisit rate
- revisit cause distribution
- tokens, cost, latency, and tool calls

## Repetition and reporting

Record model, provider, model version, reasoning effort, tool versions, fixture, prompt, environment/hardware, repetition count, observable tool activity, final result, correctness, cost/tokens when available, and known confounders. Report distributions and raw observations; never invent missing values.

## Adversarial cases

- Attempt to violate: Efficiency comparisons are invalid until every compared result passes the same correctness gate.
- Attempt to violate: Zero and near-zero net mutation are reported as typed states, not misleading infinite scores.
- Attempt to violate: Revisit causes remain explicit: KNOWN_AHEAD, DISCOVERY, TEST_RUNTIME_EVIDENCE, SELF_CORRECTION, FORMATTER, CONFLICT, OTHER_UNKNOWN.

## Result policy

Retain positive, negative, null, and failed experiments. Update maturity only when the actual stated hypothesis has reproducible evidence.
