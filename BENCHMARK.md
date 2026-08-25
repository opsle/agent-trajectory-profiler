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
- raw, initial-visible, escalated-visible, and final-visible evidence bytes
- retained, suppressed, and ambiguous source-event counts
- escalation requested, fulfilled, and unavailable counts
- initial and effective byte reduction

Bytes, tokens, events, lines, characters, latency, and cost are separate units.
Payload reduction is not equivalent to token reduction unless provider-recorded
token usage is separately supplied.

## Observational production telemetry

Ordinary run records may accumulate invocation, exact byte/event, validation,
escalation, failure/recovery, tool-call, child-execution, polling, passive-wait,
provider-token, and outcome observations when those values are actually
available. Missing fields remain missing. This corpus describes normal usage;
it does not establish that a mechanism caused lower cost, fewer tokens, lower
latency, preserved correctness, or an avoided failure.

Measurement classes remain part of every value. Cumulative summaries never
flatten exact, observed, estimated, modeled, or experimental evidence. Ordinary
observational records reject experimental measurements.

## Repetition and reporting

Record model, provider, model version, reasoning effort, tool versions, fixture, prompt, environment/hardware, repetition count, observable tool activity, final result, correctness, cost/tokens when available, and known confounders. Report distributions and raw observations; never invent missing values.

## Adversarial cases

- Attempt to violate: Efficiency comparisons are invalid until every compared result passes the same correctness gate.
- Attempt to violate: Zero and near-zero net mutation are reported as typed states, not misleading infinite scores.
- Attempt to violate: Revisit causes remain explicit: KNOWN_AHEAD, DISCOVERY, TEST_RUNTIME_EVIDENCE, SELF_CORRECTION, FORMATTER, CONFLICT, OTHER_UNKNOWN.

## Result policy

Retain positive, negative, null, and failed experiments. Update maturity only when the actual stated hypothesis has reproducible evidence.

## EXP-001 boundary

The packet-v1 corpus is measurement-conformance evidence, not the EXP-001 task
dataset, correctness oracle, arm harness, or a model result. Reduced payload does
not establish preserved model correctness.
