# Visible Value telemetry

The profiler implements the program contract identified by
`opsle.value-receipt.v1`. Runtime code remains dependency-free: interoperability
is field-based, while exact cross-repository fixture generation remains a
development-only tool.

## Observational run record

`opsle.agent-trajectory-profiler.run-record/v1` binds a stable `run.id` and a
`value_receipts` array. The following surfaces are optional and retained only
when supplied:

- task and work classification;
- repository and project;
- model and reasoning effort;
- enabled mechanisms with exact revision, configuration, and policy;
- raw, initially visible, and finally visible evidence bytes;
- provider-recorded input, output, and total tokens;
- tool-call, child-execution, and polling-turn counts;
- passive-wait duration;
- escalation, failure, and recovery observations;
- acceptance and review outcomes;
- evidence references.

An omitted field is not normalized to zero or `null`. A receipt with a non-null
run identity must match the record. If mechanism declarations are supplied,
their revision/configuration/policy identity must match each receipt exactly.

Ordinary records are observational. They reject `EXPERIMENTAL` measurements even
when a receipt otherwise has controlled-comparison fields. Controlled experiment
records will use a separate future protocol.

## Summary behavior

`summarizeRunRecord` retains all operator-displayable values, evidence, class,
unit, direction, trust, and limitations. `summarizeCumulativeValue` combines
multiple unique runs.

Only measurements satisfying all of these conditions enter totals:

- class is `EXACT` or `OBSERVED`;
- result is numeric;
- `aggregation.safe` is `true`;
- aggregation method is `SUM`;
- the unit is directly summable;
- baseline and delta are both numeric or both null.

Totals are partitioned by every compatibility dimension named in the program
contract. Result-only totals retain null baseline and delta. Mixed result-only
and delta-bearing values in one semantic group fail closed. Unsafe values remain
visible in `excluded_from_aggregation`; they are not relabeled, coerced, or
dropped without explanation.

## CLI channel separation

Machine consumers read newline-terminated canonical JSON from stdout. Operators
receive exactly one concise named line on stderr:

```text
[Trajectory Profiler] run run-001 | 2 receipts ingested | 3 visible measurements | 2 safe aggregates
```

`--quiet` suppresses only the stderr line. It cannot alter canonical stdout.
Invocation errors remain machine-readable errors on stderr and do not emit a
completion indicator.
