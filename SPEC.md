# Specification

Status: verified narrow prototype contract.

Trajectory protocol: `opsle.agent-trajectory-profiler.trajectory/v1`.

Measurement protocol: `opsle.agent-trajectory-profiler.measurement/v1`.

Value receipt protocol: `opsle.value-receipt.v1`.

Observational run-record protocol:
`opsle.agent-trajectory-profiler.run-record/v1`.

Value-summary protocol: `opsle.agent-trajectory-profiler.value-summary/v1`.

## Compatibility boundary

The primitive accepts generic structured input and emits generic structured
output. It requires no Taslos Tasks database, worker, scheduler, private
service, model, provider, or network. Context Firewall and Decision Evidence
compatibility is field-based; normal runtime code imports neither package.

Visible Value compatibility is likewise field-based. The profiler implements
the normative receipt invariants without importing the research repository at
runtime.

## Trajectory input

A trajectory contains an explicit run, task, experimental-arm, and
configuration identity plus an ordered event array. The arm is never inferred
from payload size. Optional `declared_totals` are consistency assertions.

Tool evidence is either:

- `raw_tool_evidence`, where initial visible bytes equal raw bytes; or
- `context_firewall_reduction`, derived from the real
  `opsle.context-firewall.evidence-packet/v1` receipt and an upstream Decision
  Evidence result.

A Context Firewall event records source/run/operation identity, reducer,
policy/configuration identity, raw and initial visible bytes, packet ceiling and
overhead semantics, retained/suppressed/ambiguous event counts, disposition,
sufficiency, raw-locator presence, reason codes, and validation trust state.

Raw escalation is append-only. A unique `escalation_id` first receives a
`REQUESTED` event and may receive exactly one `FULFILLED` or `UNAVAILABLE`
terminal event. Fulfillment contains an exact content identity and exposed byte
count. Multiple escalation identities may coexist.

## Measurement output

Derived exact values include:

- initial and final raw available bytes;
- initial model-visible bytes;
- initial bytes avoided, ratio, and percentage;
- retained, suppressed, and ambiguous source-event counts;
- reducer escalation requirement;
- requested, fulfilled, and unavailable escalation counts;
- per-escalation event, unique model-visible, and deduplicated byte counts;
- final model-visible bytes;
- effective bytes avoided, ratio, and percentage after escalation.

Initial reduction uses only evidence available before escalation. Effective
reduction uses final raw available evidence, including an explicitly described
additional source when applicable. Ratios are signed: a negative result means
packet/exposure bytes exceeded available raw bytes.

## Invariants

- Existing mutation-efficiency comparisons remain correctness-gated.
- Zero and near-zero net mutation remain typed states.
- Revisit causes remain explicit.
- Suppressed but never exposed evidence is not model-visible.
- Fulfilled escalation bytes become model-visible; unavailable requests do not.
- Re-exposure is deduplicated only within an operation when explicit content
  identity and byte size match.
- Separate operations with identical bytes are separate context costs.
- Byte counts and event counts are nonnegative safe integers, and aggregates
  cannot overflow the safe integer range.
- A claim of `PURE_REDUCTION` cannot exceed raw bytes. Context Firewall
  packet-v1 is `PACKET_WITH_OVERHEAD`, regardless of whether it is smaller.
- Invalid/tampered provenance cannot produce aggregate measurements.
- Source-backed and source-unverified validation states remain distinct.

## Trust boundary

The profiler does not duplicate the Decision Evidence validator. It consumes
and coherence-checks the normalized result, distinguishing:

- source-backed validation performed;
- structurally valid packet with unverified source claims;
- invalid/tampered packet;
- evidence sufficient;
- evidence requiring raw escalation.

Canonical packet-byte binding and the upstream result's internal state are
checked at adapter ingestion. A caller-owned locator is never upgraded into a
claim that an external artifact exists, is immutable, or was cryptographically
verified.

## Failure behavior

Invalid trajectories emit no aggregate measurements. Detected states include
negative/unsafe/overflowed values, duplicate event/operation identities,
unknown types/dispositions, contradictory arm/configuration/trust state,
impossible evidence or declared totals, malformed ceiling/locator flags,
invalid escalation transitions, empty fulfilled exposure, subset exposure above
its raw source, and unexplained/unbounded additional source evidence.

## Units

Payload values are UTF-8 bytes. Suppression values are source-event counts.
Bytes, characters, lines, events, tokens, latency, and cost are not
interchangeable. Optional token measurements require source
`PROVIDER_RECORDED` and separate initial, escalated, and final values.

## Visible Value receipts

A receipt must conform to `opsle.value-receipt.v1`. Its deterministic semantic
identity excludes only caller-supplied `observed_at`. All other mechanism,
operation, configuration, policy, measurement, evidence, limitation, and
extension fields remain identity-bearing.

The validator enforces finite typed values, `delta = result - baseline` when a
numeric baseline is present, exact source verification, explicit assumptions
for estimates/models, controlled identity for experimental claims,
evidence-reference resolution, and the contract's counterfactual claim
ceilings. Bytes alone cannot become an estimated monetary value, and exact or
observed `failures_prevented` claims are rejected.

Only numeric-result `EXACT` or `OBSERVED` measurements with
`aggregation.safe = true` and `method = SUM` are aggregated. Baseline and delta
must either both be numeric and coherent or both be null. Ratio, percent,
boolean, state, estimated, modeled, and experimental measurements cannot be
directly summed.

## Observational run records

A run record requires a stable run identity and a value-receipt array. Task,
work, repository, project, model, reasoning effort, enabled mechanism,
telemetry, event, outcome, and evidence-reference fields are optional. Omitted
fields stay omitted in the summary.

When mechanism declarations are supplied, receipt version, revision,
configuration, and policy must match them exactly. Receipt run identities must
match the record. Duplicate semantic receipts and experimental measurements are
rejected. Provider-token telemetry must explicitly say `PROVIDER_RECORDED`.

## Value summaries

Per-run and cumulative summaries preserve displayable values and their quality
class. Safe totals are partitioned by mechanism, version, revision,
configuration, policy, measurement identity, unit, class, direction, source
verification, and referenced-evidence trust. Duplicate run or receipt identity
cannot enter a cumulative total. Result-only totals keep baseline and delta
null; they are never coerced to zero.

Canonical summary JSON is stdout data. A single deterministic
`[Trajectory Profiler]` indicator is stderr operator telemetry and is not part
of model-visible context unless a caller deliberately forwards it.

## Versioning

Breaking semantic changes require a new protocol version. New optional fields
require evidence that they affect a real decision.
