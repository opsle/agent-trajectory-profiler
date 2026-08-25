# Specification

Status: experimental prototype contract.

## Compatibility boundary

The primitive accepts generic structured input and emits generic structured output. It must not require a Taslos Tasks database, worker, scheduler, package, runtime path, or private service.

## Inputs

- `protocol_version`: explicit version.
- `operation_id`: stable idempotency identity.
- `policy_revision`: the exact policy/configuration revision.
- `subject`: vendor-neutral request data required by this concept.
- `evidence`: observable artifacts with provenance.

## Outputs

- `status`: accepted, rejected, deferred, or indeterminate.
- `reason`: durable structured reason.
- `changed_entities`: bounded identities, never ambient state.
- `evidence`: provenance-linked receipts.
- `uncertainty`: explicit unknowns.

## Invariants

- Efficiency comparisons are invalid until every compared result passes the same correctness gate.
- Zero and near-zero net mutation are reported as typed states, not misleading infinite scores.
- Revisit causes remain explicit: KNOWN_AHEAD, DISCOVERY, TEST_RUNTIME_EVIDENCE, SELF_CORRECTION, FORMATTER, CONFLICT, OTHER_UNKNOWN.

## Failure behavior

Missing required authority or evidence fails closed. Unsupported optional data remains explicit and does not silently widen behavior. Implementations must document idempotency, crash consistency, and raw-evidence escalation.

## Versioning

Breaking semantic changes require a new protocol version. New optional fields require evidence that they affect a real decision.
