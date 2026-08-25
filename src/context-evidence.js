import { canonicalBytes, canonicalJson, sha256Bytes } from './canonical.js';

export const TRAJECTORY_PROTOCOL = 'opsle.agent-trajectory-profiler.trajectory/v1';
export const MEASUREMENT_PROTOCOL = 'opsle.agent-trajectory-profiler.measurement/v1';
export const CONTEXT_FIREWALL_EVENT = 'context_firewall_reduction';
export const RAW_BASELINE_EVENT = 'raw_tool_evidence';
export const ESCALATION_EVENT = 'raw_evidence_escalation';

const dispositions = new Set(['SUFFICIENT', 'NEEDS_RAW_EVIDENCE']);
const payloadSemantics = new Set(['PURE_REDUCTION', 'PACKET_WITH_OVERHEAD']);
const escalationStatuses = new Set(['REQUESTED', 'FULFILLED', 'UNAVAILABLE']);
const sourceRelations = new Set(['SUBSET_OF_RAW', 'ADDITIONAL_SOURCE']);

function isPlainObject(value) {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function nonempty(value) {
  return typeof value === 'string' && value.length > 0;
}

function safeCount(value) {
  return Number.isSafeInteger(value) && value >= 0;
}

function safeAdd(left, right, label) {
  const result = left + right;
  if (!Number.isSafeInteger(result)) throw new RangeError(`${label} exceeds safe integer range`);
  return result;
}

function sumObjectCounts(value) {
  return Object.values(value ?? {}).reduce(
    (sum, count) => safeAdd(sum, count, 'evidence count'),
    0,
  );
}

function reduction(rawBytes, visibleBytes) {
  const bytesAvoided = rawBytes - visibleBytes;
  if (rawBytes === 0) {
    return {
      bytes_avoided: bytesAvoided,
      percentage: null,
      ratio: { denominator: 0, kind: 'ZERO_RAW_PAYLOAD', numerator: bytesAvoided, value: null },
    };
  }
  const value = bytesAvoided / rawBytes;
  return {
    bytes_avoided: bytesAvoided,
    percentage: value * 100,
    ratio: { denominator: rawBytes, kind: 'FINITE', numerator: bytesAvoided, value },
  };
}

function validationState(validation, { packetBytesSupplied }) {
  if (!isPlainObject(validation) || typeof validation.valid !== 'boolean') {
    throw new TypeError('Decision Evidence validation result is required');
  }
  if (validation.protocol_version !== 'opsle.context-firewall.evidence-packet/v1') {
    throw new TypeError('Decision Evidence result must target Context Firewall packet-v1');
  }
  const verification = isPlainObject(validation.verification) ? validation.verification : {};
  if (validation.valid && (
    validation.structural_valid !== true
    || validation.internally_consistent !== true
    || !['VALID', 'VALID_WITH_UNVERIFIED_SOURCE'].includes(validation.classification)
    || !Array.isArray(validation.violations)
    || validation.violations.length !== 0
    || (packetBytesSupplied && verification.packet_serialization !== 'VERIFIED')
    || (!packetBytesSupplied
      && !['NOT_SUPPLIED', 'VERIFIED'].includes(verification.packet_serialization))
    || verification.reduced_bytes !== 'VERIFIED'
    || verification.semantic_payload_hash !== 'VERIFIED'
    || verification.configuration_identity !== 'VERIFIED'
  )) {
    throw new TypeError('Decision Evidence valid result is internally incoherent');
  }
  const sourceBacked = validation.valid
    && verification.input_hash === 'VERIFIED'
    && verification.source_accounting === 'VERIFIED';
  const trust = !validation.valid
    ? 'INVALID_OR_TAMPERED'
    : sourceBacked
      ? 'SOURCE_BACKED_VERIFIED'
      : 'STRUCTURALLY_VALID_UNVERIFIED_SOURCE';
  return {
    classification: validation.classification ?? 'UNAVAILABLE',
    cryptographic_verification: validation.cryptographic_verification ?? 'UNAVAILABLE',
    evidence_packet_validated: true,
    evidence_sufficient: validation.evidence_sufficient === true,
    source_backed_verification_performed: sourceBacked,
    structural_valid: validation.structural_valid === true,
    sufficiency: validation.sufficiency ?? 'INVALID',
    trust,
    valid: validation.valid,
    violation_codes: Array.isArray(validation.violations)
      ? validation.violations.map((item) => item.code).filter(nonempty).sort()
      : [],
  };
}

function ambiguousCount(packet) {
  const entries = packet.decision_evidence?.unclassified_evidence;
  if (Array.isArray(entries)) return entries.length;
  const categories = packet.receipt?.suppressed?.categories ?? {};
  return (categories.unclassified ?? 0) + (categories.unclassified_binary ?? 0);
}

export function contextFirewallEventFromPacket({
  eventId,
  packet,
  packetBytes,
  validation,
  armId,
  configurationId,
  payloadSemantics: claimedSemantics,
}) {
  if (!isPlainObject(packet) || !isPlainObject(packet.receipt)) {
    throw new TypeError('Context Firewall packet-v1 object required');
  }
  if (packet.protocol_version !== 'opsle.context-firewall.evidence-packet/v1') {
    throw new TypeError('only Context Firewall packet-v1 is supported');
  }
  const receipt = packet.receipt;
  const measurements = receipt.measurements;
  const evidence = packet.decision_evidence;
  if (!isPlainObject(measurements) || !isPlainObject(evidence)) {
    throw new TypeError('packet-v1 measurements and decision_evidence required');
  }
  const serialized = packetBytes === undefined ? canonicalBytes(packet) : Buffer.from(packetBytes);
  if (!serialized.equals(canonicalBytes(packet))) {
    throw new TypeError('packetBytes must equal canonical packet-v1 serialization');
  }
  const semantics = claimedSemantics
    ?? 'PACKET_WITH_OVERHEAD';
  return {
    arm_id: armId,
    configuration_id: configurationId,
    disposition: evidence.disposition,
    event_id: eventId,
    initial_model_visible: {
      bytes: measurements.reduced_bytes,
      content_identity: sha256Bytes(serialized),
    },
    operation_id: packet.operation_id,
    payload: {
      affected_by_ceiling: receipt.payload_limit?.affected,
      ceiling_bytes: receipt.payload_limit?.requested_bytes ?? null,
      semantics,
    },
    raw_evidence: {
      bytes: measurements.original_bytes,
      content_identity: receipt.input_hash,
      locator_present: receipt.raw_evidence?.reference != null,
    },
    reducer: {
      configuration_identity: receipt.configuration?.identity,
      name: receipt.reducer?.name,
      policy_revision: receipt.configuration?.policy_revision,
      version: receipt.reducer?.version,
    },
    reduction_requires_escalation: receipt.raw_evidence?.escalation_required === true,
    source: {
      id: receipt.source?.id ?? null,
      run_id: receipt.source?.run_id ?? null,
    },
    suppression: {
      ambiguous_evidence_count: ambiguousCount(packet),
      original_evidence_count: measurements.original_event_count,
      retained_evidence_count: measurements.retained_evidence_count,
      suppressed_categories: receipt.suppressed?.categories ?? {},
      suppressed_evidence_count: measurements.suppressed_evidence_count,
    },
    type: CONTEXT_FIREWALL_EVENT,
    validation: validationState(validation, { packetBytesSupplied: packetBytes !== undefined }),
    escalation_reasons: Array.isArray(evidence.reason_codes) ? [...evidence.reason_codes] : [],
  };
}

export function rawBaselineEvent({
  eventId,
  operationId,
  armId,
  configurationId,
  rawBytes,
  contentIdentity,
  evidenceCount = 0,
}) {
  return {
    arm_id: armId,
    configuration_id: configurationId,
    event_id: eventId,
    initial_model_visible: { bytes: rawBytes, content_identity: contentIdentity },
    operation_id: operationId,
    raw_evidence: { bytes: rawBytes, content_identity: contentIdentity, locator_present: true },
    suppression: {
      ambiguous_evidence_count: 0,
      original_evidence_count: evidenceCount,
      retained_evidence_count: evidenceCount,
      suppressed_categories: {},
      suppressed_evidence_count: 0,
    },
    type: RAW_BASELINE_EVENT,
  };
}

export function escalationEvent({
  eventId,
  operationId,
  escalationId,
  status,
  reasonCategory,
  reason,
  exposure,
  sourceRelation = 'SUBSET_OF_RAW',
}) {
  return {
    escalation_id: escalationId,
    event_id: eventId,
    exposure: exposure ?? null,
    operation_id: operationId,
    reason: reason ?? null,
    reason_category: reasonCategory,
    source_relation: sourceRelation,
    status,
    type: ESCALATION_EVENT,
  };
}

function addViolation(violations, code, path, message) {
  violations.push({ code, message, path });
}

function checkIdentity(value, path, violations) {
  if (!nonempty(value)) addViolation(violations, 'IDENTITY_REQUIRED', path, 'nonempty identity required');
}

function checkCount(value, path, violations) {
  if (!safeCount(value)) addViolation(violations, 'INVALID_MEASUREMENT', path, 'nonnegative safe integer required');
}

function registerContent(map, scope, identity, bytes, path, violations) {
  checkIdentity(identity, `${path}/content_identity`, violations);
  checkCount(bytes, `${path}/bytes`, violations);
  if (!nonempty(identity) || !safeCount(bytes)) return false;
  const scopedIdentity = `${scope}\0${identity}`;
  if (map.has(scopedIdentity) && map.get(scopedIdentity) !== bytes) {
    addViolation(
      violations,
      'CONTENT_IDENTITY_SIZE_MISMATCH',
      path,
      'one content identity cannot have contradictory byte sizes',
    );
    return false;
  }
  const isNew = !map.has(scopedIdentity);
  map.set(scopedIdentity, bytes);
  return isNew;
}

function validateEvidenceEvent(event, index, run, state, violations) {
  const path = `/events/${index}`;
  checkIdentity(event.operation_id, `${path}/operation_id`, violations);
  if (event.arm_id !== run.arm_id) {
    addViolation(violations, 'ARM_IDENTITY_MISMATCH', `${path}/arm_id`, 'event arm must match run arm');
  }
  if (event.configuration_id !== run.configuration_id) {
    addViolation(
      violations,
      'CONFIGURATION_IDENTITY_MISMATCH',
      `${path}/configuration_id`,
      'event configuration must match run configuration',
    );
  }
  if (state.operations.has(event.operation_id)) {
    addViolation(violations, 'DUPLICATE_OPERATION_ID', `${path}/operation_id`, 'operation already declared');
    return;
  }
  const raw = event.raw_evidence ?? {};
  const initial = event.initial_model_visible ?? {};
  checkCount(raw.bytes, `${path}/raw_evidence/bytes`, violations);
  checkCount(initial.bytes, `${path}/initial_model_visible/bytes`, violations);
  registerContent(
    state.rawContent,
    event.operation_id,
    raw.content_identity,
    raw.bytes,
    `${path}/raw_evidence`,
    violations,
  );
  const newInitial = registerContent(
    state.visibleContent,
    event.operation_id,
    initial.content_identity,
    initial.bytes,
    `${path}/initial_model_visible`,
    violations,
  );
  if (newInitial && safeCount(initial.bytes)) {
    state.initialVisibleBytes = safeAdd(
      state.initialVisibleBytes,
      initial.bytes,
      'initial visible bytes',
    );
  }
  if (safeCount(raw.bytes)) {
    state.rawAvailableBytes = safeAdd(state.rawAvailableBytes, raw.bytes, 'raw available bytes');
    state.initialRawAvailableBytes = safeAdd(
      state.initialRawAvailableBytes,
      raw.bytes,
      'initial raw available bytes',
    );
  }

  const suppression = event.suppression ?? {};
  for (const field of [
    'ambiguous_evidence_count',
    'original_evidence_count',
    'retained_evidence_count',
    'suppressed_evidence_count',
  ]) checkCount(suppression[field], `${path}/suppression/${field}`, violations);
  if (safeCount(suppression.retained_evidence_count)
    && safeCount(suppression.suppressed_evidence_count)
    && safeCount(suppression.original_evidence_count)) {
    const classified = suppression.retained_evidence_count + suppression.suppressed_evidence_count;
    if (!Number.isSafeInteger(classified)) {
      addViolation(violations, 'INTEGER_OVERFLOW', `${path}/suppression`, 'evidence count total exceeds safe integer range');
    } else if (classified !== suppression.original_evidence_count) {
      addViolation(
        violations,
        'EVIDENCE_ACCOUNTING_MISMATCH',
        `${path}/suppression`,
        'retained plus suppressed must equal original evidence count',
      );
    }
  }
  if (safeCount(suppression.ambiguous_evidence_count)
    && safeCount(suppression.original_evidence_count)
    && suppression.ambiguous_evidence_count > suppression.original_evidence_count) {
    addViolation(
      violations,
      'AMBIGUOUS_COUNT_EXCEEDS_ORIGINAL',
      `${path}/suppression/ambiguous_evidence_count`,
      'ambiguous evidence is a subset of original evidence',
    );
  }
  if (!isPlainObject(suppression.suppressed_categories)) {
    addViolation(violations, 'OBJECT_REQUIRED', `${path}/suppression/suppressed_categories`, 'object required');
  } else {
    for (const [category, count] of Object.entries(suppression.suppressed_categories)) {
      checkCount(count, `${path}/suppression/suppressed_categories/${category}`, violations);
    }
    if (safeCount(suppression.suppressed_evidence_count)
      && Object.values(suppression.suppressed_categories).every(safeCount)
      && sumObjectCounts(suppression.suppressed_categories) !== suppression.suppressed_evidence_count) {
      addViolation(
        violations,
        'SUPPRESSION_CATEGORY_TOTAL_MISMATCH',
        `${path}/suppression/suppressed_categories`,
        'suppression categories must sum to the suppressed count',
      );
    }
  }

  if (event.type === CONTEXT_FIREWALL_EVENT) {
    if (!dispositions.has(event.disposition)) {
      addViolation(violations, 'INVALID_DISPOSITION', `${path}/disposition`, 'unsupported disposition');
    }
    if (!payloadSemantics.has(event.payload?.semantics)) {
      addViolation(violations, 'INVALID_PAYLOAD_SEMANTICS', `${path}/payload/semantics`, 'unsupported semantics');
    }
    if (typeof event.payload?.affected_by_ceiling !== 'boolean') {
      addViolation(violations, 'BOOLEAN_REQUIRED', `${path}/payload/affected_by_ceiling`, 'boolean required');
    }
    if (typeof event.raw_evidence?.locator_present !== 'boolean') {
      addViolation(violations, 'BOOLEAN_REQUIRED', `${path}/raw_evidence/locator_present`, 'boolean required');
    }
    if (typeof event.reduction_requires_escalation !== 'boolean') {
      addViolation(violations, 'BOOLEAN_REQUIRED', `${path}/reduction_requires_escalation`, 'boolean required');
    }
    if (event.payload?.semantics === 'PURE_REDUCTION'
      && safeCount(raw.bytes) && safeCount(initial.bytes) && initial.bytes > raw.bytes) {
      addViolation(
        violations,
        'REDUCED_EXCEEDS_RAW',
        `${path}/initial_model_visible/bytes`,
        'pure reduction cannot exceed raw bytes',
      );
    }
    const ceiling = event.payload?.ceiling_bytes;
    if (ceiling !== null && (!Number.isSafeInteger(ceiling) || ceiling <= 0)) {
      addViolation(violations, 'INVALID_PAYLOAD_CEILING', `${path}/payload/ceiling_bytes`, 'positive safe integer or null required');
    }
    if (safeCount(initial.bytes) && Number.isSafeInteger(ceiling) && initial.bytes > ceiling) {
      addViolation(violations, 'PAYLOAD_CEILING_EXCEEDED', `${path}/payload`, 'initial packet exceeds declared ceiling');
    }
    if (event.payload?.affected_by_ceiling === true && ceiling === null) {
      addViolation(violations, 'MISSING_PAYLOAD_CEILING', `${path}/payload/ceiling_bytes`, 'affected packet requires a ceiling');
    }
    if (event.disposition === 'SUFFICIENT' && event.reduction_requires_escalation) {
      addViolation(violations, 'SUFFICIENCY_CONTRADICTION', path, 'sufficient evidence cannot require escalation');
    }
    if (event.disposition === 'NEEDS_RAW_EVIDENCE' && !event.reduction_requires_escalation) {
      addViolation(violations, 'ESCALATION_CONTRADICTION', path, 'NEEDS_RAW_EVIDENCE must require escalation');
    }
    if (!Array.isArray(event.escalation_reasons)
      || event.escalation_reasons.some((reason) => !nonempty(reason))) {
      addViolation(violations, 'INVALID_ESCALATION_REASONS', `${path}/escalation_reasons`, 'string array required');
    } else if (event.disposition === 'SUFFICIENT' && event.escalation_reasons.length !== 0) {
      addViolation(violations, 'SUFFICIENCY_REASON_CONTRADICTION', `${path}/escalation_reasons`, 'sufficient evidence has no escalation reasons');
    } else if (event.disposition === 'NEEDS_RAW_EVIDENCE' && event.escalation_reasons.length === 0) {
      addViolation(violations, 'ESCALATION_REASON_MISSING', `${path}/escalation_reasons`, 'NEEDS_RAW_EVIDENCE requires a reason');
    }
    const validation = event.validation;
    if (!isPlainObject(validation)) {
      addViolation(violations, 'VALIDATION_REQUIRED', `${path}/validation`, 'normalized validation state required');
    } else {
      const validTrust = ['SOURCE_BACKED_VERIFIED', 'STRUCTURALLY_VALID_UNVERIFIED_SOURCE'];
      const trustClassificationAligned = (
        validation.trust === 'SOURCE_BACKED_VERIFIED'
        && validation.classification === 'VALID'
        && validation.source_backed_verification_performed === true
      ) || (
        validation.trust === 'STRUCTURALLY_VALID_UNVERIFIED_SOURCE'
        && validation.classification === 'VALID_WITH_UNVERIFIED_SOURCE'
        && validation.source_backed_verification_performed === false
      );
      const coherentValid = validation.valid === true
        && validation.evidence_packet_validated === true
        && validation.structural_valid === true
        && validTrust.includes(validation.trust)
        && trustClassificationAligned
        && ['PARTIAL', 'VERIFIED'].includes(validation.cryptographic_verification)
        && validation.sufficiency === event.disposition
        && validation.evidence_sufficient === (event.disposition === 'SUFFICIENT')
        && Array.isArray(validation.violation_codes)
        && validation.violation_codes.length === 0;
      const coherentInvalid = validation.valid === false
        && validation.trust === 'INVALID_OR_TAMPERED'
        && validation.evidence_sufficient === false
        && validation.sufficiency === 'INVALID'
        && !['VALID', 'VALID_WITH_UNVERIFIED_SOURCE'].includes(validation.classification);
      if (!coherentValid && !coherentInvalid) {
        addViolation(violations, 'INCOHERENT_VALIDATION_STATE', `${path}/validation`, 'normalized Decision Evidence state is contradictory');
      }
    }
    if (event.validation?.trust === 'INVALID_OR_TAMPERED' || event.validation?.valid !== true) {
      addViolation(
        violations,
        'UNTRUSTED_EVIDENCE_MEASUREMENTS',
        `${path}/validation`,
        'invalid or tampered packet measurements are not trusted',
      );
      state.untrusted = true;
    }
    if (event.validation?.valid === true
      && event.validation.evidence_sufficient !== (event.disposition === 'SUFFICIENT')) {
      addViolation(violations, 'VALIDATION_SUFFICIENCY_MISMATCH', `${path}/validation`, 'validation contradicts packet disposition');
    }
  }

  const operation = {
    ambiguous_evidence_count: suppression.ambiguous_evidence_count,
    disposition: event.disposition ?? 'RAW_BASELINE',
    escalation_reasons: event.escalation_reasons ?? [],
    initial_model_visible_bytes: initial.bytes,
    operation_id: event.operation_id,
    original_evidence_count: suppression.original_evidence_count,
    payload: event.payload ?? null,
    raw_available_bytes: raw.bytes,
    raw_evidence_locator_present: raw.locator_present,
    reducer: event.reducer ?? null,
    reduction_requires_escalation: event.reduction_requires_escalation ?? false,
    retained_evidence_count: suppression.retained_evidence_count,
    source: event.source ?? null,
    suppressed_evidence_count: suppression.suppressed_evidence_count,
    validation: event.validation ?? null,
  };
  state.operations.set(event.operation_id, operation);
  for (const [field, stateField] of [
    ['retained_evidence_count', 'retainedEvidenceCount'],
    ['suppressed_evidence_count', 'suppressedEvidenceCount'],
    ['ambiguous_evidence_count', 'ambiguousEvidenceCount'],
  ]) {
    if (safeCount(suppression[field])) {
      state[stateField] = safeAdd(state[stateField], suppression[field], field);
    }
  }
}

function validateEscalationEvent(event, index, state, violations) {
  const path = `/events/${index}`;
  checkIdentity(event.operation_id, `${path}/operation_id`, violations);
  checkIdentity(event.escalation_id, `${path}/escalation_id`, violations);
  if (!state.operations.has(event.operation_id)) {
    addViolation(violations, 'UNKNOWN_OPERATION_ID', `${path}/operation_id`, 'escalation operation must already exist');
  }
  if (!escalationStatuses.has(event.status)) {
    addViolation(violations, 'INVALID_ESCALATION_STATUS', `${path}/status`, 'unsupported escalation status');
    return;
  }
  if (!nonempty(event.reason_category)) {
    addViolation(violations, 'ESCALATION_REASON_REQUIRED', `${path}/reason_category`, 'reason category required');
  }
  if (!sourceRelations.has(event.source_relation)) {
    addViolation(violations, 'INVALID_SOURCE_RELATION', `${path}/source_relation`, 'unsupported source relation');
  }
  let escalation = state.escalations.get(event.escalation_id);
  if (event.status === 'REQUESTED') {
    if (escalation) {
      addViolation(violations, 'DUPLICATE_ESCALATION_REQUEST', `${path}/escalation_id`, 'request already exists');
      return;
    }
    if (event.exposure !== null) {
      addViolation(violations, 'REQUEST_HAS_EXPOSURE', `${path}/exposure`, 'request cannot expose evidence');
    }
    escalation = {
      operation_id: event.operation_id,
      request: {
        event_id: event.event_id,
        reason: event.reason,
        reason_category: event.reason_category,
      },
      status: 'REQUESTED',
    };
    state.escalations.set(event.escalation_id, escalation);
    return;
  }
  if (!escalation) {
    addViolation(violations, 'ESCALATION_REQUEST_MISSING', `${path}/escalation_id`, 'terminal escalation requires prior request');
    return;
  }
  if (escalation.operation_id !== event.operation_id) {
    addViolation(violations, 'ESCALATION_OPERATION_MISMATCH', `${path}/operation_id`, 'operation changed during escalation');
  }
  if (escalation.status !== 'REQUESTED') {
    addViolation(violations, 'DUPLICATE_ESCALATION_TERMINAL', `${path}/status`, 'escalation already terminated');
    return;
  }
  escalation.status = event.status;
  escalation.terminal = {
    event_id: event.event_id,
    reason: event.reason,
    reason_category: event.reason_category,
    source_relation: event.source_relation,
  };
  if (event.status === 'UNAVAILABLE') {
    if (event.exposure !== null) {
      addViolation(violations, 'UNAVAILABLE_HAS_EXPOSURE', `${path}/exposure`, 'unavailable evidence cannot be exposed');
    }
    return;
  }
  if (!isPlainObject(event.exposure)) {
    addViolation(violations, 'FULFILLED_EXPOSURE_REQUIRED', `${path}/exposure`, 'fulfilled escalation requires exposure');
    return;
  }
  checkCount(event.exposure.bytes, `${path}/exposure/bytes`, violations);
  if (event.exposure.bytes === 0) {
    addViolation(violations, 'FULFILLED_EXPOSURE_EMPTY', `${path}/exposure/bytes`, 'fulfilled escalation must expose bytes');
  }
  state.escalatedEventBytes = safeCount(event.exposure.bytes)
    ? safeAdd(state.escalatedEventBytes, event.exposure.bytes, 'escalated event bytes')
    : state.escalatedEventBytes;
  const isNew = registerContent(
    state.visibleContent,
    event.operation_id,
    event.exposure.content_identity,
    event.exposure.bytes,
    `${path}/exposure`,
    violations,
  );
  if (isNew && safeCount(event.exposure.bytes)) {
    state.escalatedVisibleBytes = safeAdd(
      state.escalatedVisibleBytes,
      event.exposure.bytes,
      'escalated visible bytes',
    );
  }
  escalation.exposure = {
    content_identity: event.exposure.content_identity,
    deduplicated_bytes: isNew ? 0 : event.exposure.bytes,
    event_bytes: event.exposure.bytes,
    model_visible_bytes: isNew ? event.exposure.bytes : 0,
    source_available_bytes: event.exposure.source_available_bytes ?? null,
    source_identity: event.exposure.source_identity ?? null,
  };
  if (event.source_relation === 'SUBSET_OF_RAW' && state.operations.has(event.operation_id)) {
    const operation = state.operations.get(event.operation_id);
    operation.escalated_subset_bytes = safeAdd(
      operation.escalated_subset_bytes ?? 0,
      isNew ? event.exposure.bytes : 0,
      'operation escalated bytes',
    );
    if (operation.escalated_subset_bytes > operation.raw_available_bytes) {
      addViolation(
        violations,
        'ESCALATION_EXCEEDS_RAW_SOURCE',
        `${path}/exposure/bytes`,
        'unique subset exposure exceeds raw source bytes',
      );
    }
  }
  if (event.source_relation === 'ADDITIONAL_SOURCE' && !nonempty(event.reason)) {
    addViolation(violations, 'ADDITIONAL_SOURCE_EXPLANATION_REQUIRED', `${path}/reason`, 'additional source requires explanation');
  }
  if (event.source_relation === 'ADDITIONAL_SOURCE') {
    checkIdentity(event.exposure.source_identity, `${path}/exposure/source_identity`, violations);
    checkCount(event.exposure.source_available_bytes, `${path}/exposure/source_available_bytes`, violations);
    if (safeCount(event.exposure.source_available_bytes)
      && safeCount(event.exposure.bytes)
      && event.exposure.bytes > event.exposure.source_available_bytes) {
      addViolation(violations, 'EXPOSURE_EXCEEDS_ADDITIONAL_SOURCE', `${path}/exposure/bytes`, 'exposure exceeds additional source bytes');
    }
    const newSource = registerContent(
      state.rawContent,
      event.operation_id,
      event.exposure.source_identity,
      event.exposure.source_available_bytes,
      `${path}/exposure`,
      violations,
    );
    if (newSource && safeCount(event.exposure.source_available_bytes)) {
      state.rawAvailableBytes = safeAdd(
        state.rawAvailableBytes,
        event.exposure.source_available_bytes,
        'raw available bytes',
      );
    }
  }
}

export function validateTrajectory(trajectory) {
  const violations = [];
  if (!isPlainObject(trajectory)) {
    return { valid: false, violations: [{ code: 'OBJECT_REQUIRED', message: 'trajectory object required', path: '/' }] };
  }
  if (trajectory.protocol_version !== TRAJECTORY_PROTOCOL) {
    addViolation(violations, 'UNSUPPORTED_PROTOCOL', '/protocol_version', `only ${TRAJECTORY_PROTOCOL} is supported`);
  }
  const run = trajectory.run;
  if (!isPlainObject(run)) {
    addViolation(violations, 'RUN_REQUIRED', '/run', 'run object required');
    return { valid: false, violations };
  }
  for (const field of ['run_id', 'task_id', 'arm_id', 'configuration_id']) {
    checkIdentity(run[field], `/run/${field}`, violations);
  }
  if (!Array.isArray(trajectory.events)) {
    addViolation(violations, 'EVENTS_REQUIRED', '/events', 'events array required');
    return { valid: false, violations };
  }
  const eventIds = new Set();
  const state = {
    ambiguousEvidenceCount: 0,
    escalatedEventBytes: 0,
    escalatedVisibleBytes: 0,
    escalations: new Map(),
    initialVisibleBytes: 0,
    initialRawAvailableBytes: 0,
    operations: new Map(),
    rawAvailableBytes: 0,
    rawContent: new Map(),
    retainedEvidenceCount: 0,
    suppressedEvidenceCount: 0,
    untrusted: false,
    visibleContent: new Map(),
  };
  for (const [index, event] of trajectory.events.entries()) {
    const path = `/events/${index}`;
    if (!isPlainObject(event)) {
      addViolation(violations, 'EVENT_OBJECT_REQUIRED', path, 'event object required');
      continue;
    }
    checkIdentity(event.event_id, `${path}/event_id`, violations);
    if (eventIds.has(event.event_id)) {
      addViolation(violations, 'DUPLICATE_EVENT_ID', `${path}/event_id`, 'event identity already used');
    }
    eventIds.add(event.event_id);
    try {
      if ([CONTEXT_FIREWALL_EVENT, RAW_BASELINE_EVENT].includes(event.type)) {
        validateEvidenceEvent(event, index, run, state, violations);
      } else if (event.type === ESCALATION_EVENT) {
        validateEscalationEvent(event, index, state, violations);
      } else {
        addViolation(violations, 'UNKNOWN_EVENT_TYPE', `${path}/type`, 'unsupported trajectory event');
      }
    } catch (error) {
      if (!(error instanceof RangeError)) throw error;
      addViolation(violations, 'INTEGER_OVERFLOW', path, error.message);
    }
  }
  if (trajectory.token_measurements !== undefined) {
    const tokens = trajectory.token_measurements;
    if (!isPlainObject(tokens)) {
      addViolation(violations, 'OBJECT_REQUIRED', '/token_measurements', 'object required');
    } else {
      if (tokens.source !== 'PROVIDER_RECORDED') {
        addViolation(
          violations,
          'INVALID_TOKEN_MEASUREMENT_SOURCE',
          '/token_measurements/source',
          'token counts must be explicitly provider-recorded',
        );
      }
      for (const field of ['initial_tool_evidence_tokens', 'escalated_tool_evidence_tokens', 'final_tool_evidence_tokens']) {
        checkCount(tokens[field], `/token_measurements/${field}`, violations);
      }
      if (safeCount(tokens.initial_tool_evidence_tokens)
        && safeCount(tokens.escalated_tool_evidence_tokens)
        && safeCount(tokens.final_tool_evidence_tokens)
        && tokens.initial_tool_evidence_tokens + tokens.escalated_tool_evidence_tokens
          !== tokens.final_tool_evidence_tokens) {
        addViolation(
          violations,
          'TOKEN_COMPONENT_MISMATCH',
          '/token_measurements/final_tool_evidence_tokens',
          'final tokens must equal initial plus escalated tokens',
        );
      }
    }
  }
  let finalVisibleBytes = 0;
  try {
    finalVisibleBytes = safeAdd(
      state.initialVisibleBytes,
      state.escalatedVisibleBytes,
      'final visible bytes',
    );
  } catch (error) {
    if (!(error instanceof RangeError)) throw error;
    addViolation(violations, 'INTEGER_OVERFLOW', '/events', error.message);
  }
  const derived = {
    escalated_model_visible_bytes: state.escalatedVisibleBytes,
    final_model_visible_bytes: finalVisibleBytes,
    initial_model_visible_bytes: state.initialVisibleBytes,
    initial_raw_available_bytes: state.initialRawAvailableBytes,
    raw_available_bytes: state.rawAvailableBytes,
  };
  if (trajectory.declared_totals !== undefined) {
    if (!isPlainObject(trajectory.declared_totals)) {
      addViolation(violations, 'OBJECT_REQUIRED', '/declared_totals', 'object required');
    } else {
      for (const [field, actual] of Object.entries(derived)) {
        if (trajectory.declared_totals[field] !== actual) {
          addViolation(violations, 'DECLARED_TOTAL_MISMATCH', `/declared_totals/${field}`, `must equal ${actual}`);
        }
      }
    }
  }
  return { state, valid: violations.length === 0, violations };
}

export function profileTrajectory(trajectory) {
  const checked = validateTrajectory(trajectory);
  const run = isPlainObject(trajectory?.run) ? trajectory.run : {};
  const base = {
    arm_id: run.arm_id ?? null,
    configuration_id: run.configuration_id ?? null,
    protocol_version: MEASUREMENT_PROTOCOL,
    run_id: run.run_id ?? null,
    task_id: run.task_id ?? null,
    token_measurements: trajectory?.token_measurements ?? null,
    trajectory_identity: isPlainObject(trajectory) ? sha256Bytes(canonicalBytes(trajectory)) : null,
    valid: checked.valid,
    violations: checked.violations,
  };
  if (!checked.state || checked.state.untrusted || !checked.valid) {
    return {
      ...base,
      measurements: null,
      measurement_status: checked.state?.untrusted
        ? 'UNAVAILABLE_UNTRUSTED_EVIDENCE'
        : 'UNAVAILABLE_INVALID_TRAJECTORY',
    };
  }
  const state = checked.state;
  const escalations = [...state.escalations.entries()].map(([escalationId, value]) => ({
    escalation_id: escalationId,
    exposure: value.exposure ?? null,
    operation_id: value.operation_id,
    request: value.request,
    status: value.status,
    terminal: value.terminal ?? null,
  }));
  const finalVisible = safeAdd(state.initialVisibleBytes, state.escalatedVisibleBytes, 'final visible bytes');
  return {
    ...base,
    measurements: {
      ambiguous_evidence_count: state.ambiguousEvidenceCount,
      deduplicated_reexposure_bytes: state.escalatedEventBytes - state.escalatedVisibleBytes,
      effective_reduction: reduction(state.rawAvailableBytes, finalVisible),
      escalated_event_bytes: state.escalatedEventBytes,
      escalated_model_visible_bytes: state.escalatedVisibleBytes,
      escalation_fulfilled: escalations.some((item) => item.status === 'FULFILLED'),
      escalation_fulfilled_count: escalations.filter((item) => item.status === 'FULFILLED').length,
      escalation_requested: escalations.length > 0,
      escalation_requested_count: escalations.length,
      escalation_unavailable: escalations.some((item) => item.status === 'UNAVAILABLE'),
      escalation_unavailable_count: escalations.filter((item) => item.status === 'UNAVAILABLE').length,
      escalations,
      final_model_visible_bytes: finalVisible,
      final_raw_available_bytes: state.rawAvailableBytes,
      initial_model_visible_bytes: state.initialVisibleBytes,
      initial_raw_available_bytes: state.initialRawAvailableBytes,
      initial_reduction: reduction(state.initialRawAvailableBytes, state.initialVisibleBytes),
      operations: [...state.operations.values()],
      raw_available_bytes: state.rawAvailableBytes,
      reducer_requires_escalation: [...state.operations.values()]
        .some((item) => item.reduction_requires_escalation),
      retained_evidence_count: state.retainedEvidenceCount,
      suppressed_evidence_count: state.suppressedEvidenceCount,
    },
    measurement_status: 'MEASURED',
  };
}

export function compareTrajectories(trajectories) {
  if (!Array.isArray(trajectories) || trajectories.length < 2) {
    throw new TypeError('at least two trajectories are required');
  }
  const profiles = trajectories.map(profileTrajectory);
  const taskIdentities = new Set(profiles.map((profile) => profile.task_id));
  const validProfiles = profiles.every((profile) => profile.valid && profile.measurements !== null);
  return {
    comparable: validProfiles && taskIdentities.size === 1,
    reason: !validProfiles
      ? 'invalid-measurement'
      : taskIdentities.size !== 1 ? 'task-identity-mismatch' : null,
    profiles: profiles.sort((left, right) => {
      const leftKey = `${left.arm_id}\0${left.configuration_id}\0${left.run_id}`;
      const rightKey = `${right.arm_id}\0${right.configuration_id}\0${right.run_id}`;
      return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
    }),
    protocol_version: 'opsle.agent-trajectory-profiler.comparison/v1',
  };
}

export function canonicalMeasurement(profile) {
  return `${canonicalJson(profile)}\n`;
}
