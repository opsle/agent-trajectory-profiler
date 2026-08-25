import { canonicalBytes, canonicalize, sha256Bytes } from './canonical.js';
import { ingestValueReceipts } from './value-receipt.js';

export const RUN_RECORD_PROTOCOL = 'opsle.agent-trajectory-profiler.run-record/v1';

const mechanismIdPattern = /^opsle\.[a-z0-9-]+$/;
const eventTypes = new Set(['ESCALATION', 'FAILURE', 'RECOVERY']);
const telemetryCountFields = new Set([
  'raw_evidence_bytes',
  'initial_model_visible_bytes',
  'final_model_visible_bytes',
  'tool_call_count',
  'child_execution_count',
  'polling_turn_count',
  'passive_wait_milliseconds',
  'escalation_event_count',
  'failure_event_count',
  'recovery_event_count',
]);

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function nonempty(value) {
  return typeof value === 'string' && value.length > 0;
}

function add(violations, code, path, message) {
  violations.push({ code, message, path });
}

function rejectUnknown(value, allowed, path, violations) {
  for (const key of Object.keys(value)) {
    if (!allowed.includes(key)) add(violations, 'UNKNOWN_FIELD', `${path}/${key}`, 'unsupported run-record field');
  }
}

function nullableString(value, path, violations) {
  if (value !== null && !nonempty(value)) add(violations, 'INVALID_IDENTITY', path, 'nonempty string or null required');
}

function stringArray(value, path, violations) {
  if (!Array.isArray(value)) {
    add(violations, 'ARRAY_REQUIRED', path, 'array required');
    return;
  }
  value.forEach((item, index) => {
    if (!nonempty(item)) add(violations, 'NONEMPTY_STRING_REQUIRED', `${path}/${index}`, 'nonempty string required');
  });
}

function safeCount(value, path, violations) {
  if (!Number.isSafeInteger(value) || value < 0) {
    add(violations, 'INVALID_MEASUREMENT', path, 'nonnegative safe integer required');
  }
}

function validateRun(run, violations) {
  if (!isPlainObject(run)) {
    add(violations, 'RUN_REQUIRED', '/run', 'run object required');
    return;
  }
  const fields = [
    'id', 'task_classification', 'work_classification', 'repository', 'project',
    'model', 'reasoning_effort',
  ];
  rejectUnknown(run, fields, '/run', violations);
  if (!Object.hasOwn(run, 'id') || !nonempty(run.id)) {
    add(violations, 'RUN_ID_REQUIRED', '/run/id', 'nonempty observational run identity required');
  }
  for (const field of fields.slice(1)) {
    if (Object.hasOwn(run, field)) nullableString(run[field], `/run/${field}`, violations);
  }
}

function validateMechanisms(mechanisms, violations) {
  if (mechanisms === undefined) return;
  if (!Array.isArray(mechanisms)) {
    add(violations, 'ARRAY_REQUIRED', '/mechanisms', 'array required');
    return;
  }
  const identities = new Set();
  mechanisms.forEach((mechanism, index) => {
    const path = `/mechanisms/${index}`;
    if (!isPlainObject(mechanism)) {
      add(violations, 'OBJECT_REQUIRED', path, 'mechanism object required');
      return;
    }
    const fields = ['id', 'name', 'version', 'revision', 'configuration_id', 'policy_id'];
    rejectUnknown(mechanism, fields, path, violations);
    for (const field of fields) {
      if (!Object.hasOwn(mechanism, field)) add(violations, 'REQUIRED_FIELD_MISSING', `${path}/${field}`, 'required field missing');
    }
    if (!nonempty(mechanism.id) || !mechanismIdPattern.test(mechanism.id)) {
      add(violations, 'INVALID_MECHANISM_ID', `${path}/id`, 'Opsle mechanism identity required');
    }
    for (const field of ['name', 'version']) {
      if (!nonempty(mechanism[field])) add(violations, 'NONEMPTY_STRING_REQUIRED', `${path}/${field}`, 'nonempty string required');
    }
    for (const field of ['revision', 'configuration_id', 'policy_id']) {
      nullableString(mechanism[field], `${path}/${field}`, violations);
    }
    const identity = fields.map((field) => mechanism[field] ?? '').join('\0');
    if (identities.has(identity)) add(violations, 'DUPLICATE_MECHANISM', path, 'duplicate mechanism declaration');
    identities.add(identity);
  });
}

function validateProviderTokens(value, violations) {
  const path = '/telemetry/provider_recorded_tokens';
  if (!isPlainObject(value)) {
    add(violations, 'OBJECT_REQUIRED', path, 'provider token object required');
    return;
  }
  const fields = ['source', 'input', 'output', 'total'];
  rejectUnknown(value, fields, path, violations);
  if (value.source !== 'PROVIDER_RECORDED') {
    add(violations, 'INVALID_TOKEN_SOURCE', `${path}/source`, 'provider-recorded source required');
  }
  for (const field of ['input', 'output', 'total']) {
    if (Object.hasOwn(value, field)) safeCount(value[field], `${path}/${field}`, violations);
  }
  if (['input', 'output', 'total'].every((field) => Number.isSafeInteger(value[field]))
    && value.input + value.output !== value.total) {
    add(violations, 'TOKEN_TOTAL_MISMATCH', `${path}/total`, 'total must equal input plus output');
  }
}

function validateTelemetry(telemetry, violations) {
  if (telemetry === undefined) return;
  if (!isPlainObject(telemetry)) {
    add(violations, 'OBJECT_REQUIRED', '/telemetry', 'telemetry object required');
    return;
  }
  const fields = [...telemetryCountFields, 'provider_recorded_tokens'];
  rejectUnknown(telemetry, fields, '/telemetry', violations);
  for (const [field, value] of Object.entries(telemetry)) {
    if (telemetryCountFields.has(field)) safeCount(value, `/telemetry/${field}`, violations);
  }
  if (Object.hasOwn(telemetry, 'provider_recorded_tokens')) {
    validateProviderTokens(telemetry.provider_recorded_tokens, violations);
  }
}

function validateEvents(events, violations) {
  if (events === undefined) return;
  if (!Array.isArray(events)) {
    add(violations, 'ARRAY_REQUIRED', '/events', 'array required');
    return;
  }
  const identities = new Set();
  events.forEach((event, index) => {
    const path = `/events/${index}`;
    if (!isPlainObject(event)) {
      add(violations, 'OBJECT_REQUIRED', path, 'event object required');
      return;
    }
    const fields = ['id', 'type', 'operation_id', 'status', 'evidence_refs'];
    rejectUnknown(event, fields, path, violations);
    if (!nonempty(event.id)) add(violations, 'EVENT_ID_REQUIRED', `${path}/id`, 'nonempty event identity required');
    else if (identities.has(event.id)) add(violations, 'DUPLICATE_EVENT_ID', `${path}/id`, 'duplicate event identity');
    else identities.add(event.id);
    if (!eventTypes.has(event.type)) add(violations, 'INVALID_EVENT_TYPE', `${path}/type`, 'unsupported observational event type');
    for (const field of ['operation_id', 'status']) {
      if (Object.hasOwn(event, field)) nullableString(event[field], `${path}/${field}`, violations);
    }
    if (Object.hasOwn(event, 'evidence_refs')) stringArray(event.evidence_refs, `${path}/evidence_refs`, violations);
  });
}

function validateOutcome(outcome, violations) {
  if (outcome === undefined) return;
  if (!isPlainObject(outcome)) {
    add(violations, 'OBJECT_REQUIRED', '/outcome', 'outcome object required');
    return;
  }
  const fields = ['acceptance', 'review'];
  rejectUnknown(outcome, fields, '/outcome', violations);
  for (const [field, value] of Object.entries(outcome)) nullableString(value, `/outcome/${field}`, violations);
}

function mechanismMatchesReceipt(mechanism, receipt) {
  return mechanism.id === receipt.mechanism.id
    && mechanism.name === receipt.mechanism.name
    && mechanism.version === receipt.mechanism.version
    && mechanism.revision === receipt.mechanism.revision
    && mechanism.configuration_id === receipt.operation.configuration_id
    && mechanism.policy_id === receipt.operation.policy_id;
}

export function validateRunRecord(record) {
  const violations = [];
  if (!isPlainObject(record)) {
    return { valid: false, violations: [{ code: 'OBJECT_REQUIRED', message: 'run record object required', path: '/' }] };
  }
  const fields = [
    'protocol_version', 'run', 'mechanisms', 'telemetry', 'events', 'outcome',
    'value_receipts', 'evidence_refs',
  ];
  rejectUnknown(record, fields, '', violations);
  if (record.protocol_version !== RUN_RECORD_PROTOCOL) {
    add(violations, 'UNSUPPORTED_PROTOCOL', '/protocol_version', `only ${RUN_RECORD_PROTOCOL} is supported`);
  }
  validateRun(record.run, violations);
  validateMechanisms(record.mechanisms, violations);
  validateTelemetry(record.telemetry, violations);
  validateEvents(record.events, violations);
  validateOutcome(record.outcome, violations);
  if (Object.hasOwn(record, 'evidence_refs')) stringArray(record.evidence_refs, '/evidence_refs', violations);

  const ingested = ingestValueReceipts(record.value_receipts, {
    runId: isPlainObject(record.run) && nonempty(record.run.id) ? record.run.id : null,
  });
  violations.push(...ingested.violations);
  if (ingested.valid) {
    for (const [receiptIndex, item] of ingested.receipts.entries()) {
      for (const [measurementIndex, measurement] of item.receipt.measurements.entries()) {
        if (measurement.class === 'EXPERIMENTAL') {
          add(
            violations,
            'EXPERIMENTAL_IN_OBSERVATIONAL_RECORD',
            `/value_receipts/${receiptIndex}/measurements/${measurementIndex}/class`,
            'ordinary observational records cannot contain EXPERIMENTAL measurements',
          );
        }
      }
      if (Array.isArray(record.mechanisms)
        && !record.mechanisms.some((mechanism) => mechanismMatchesReceipt(mechanism, item.receipt))) {
        add(
          violations,
          'MECHANISM_DECLARATION_MISMATCH',
          `/value_receipts/${receiptIndex}/mechanism`,
          'receipt mechanism revision and configuration must match a declared mechanism',
        );
      }
    }
  }
  violations.sort((left, right) => {
    const leftKey = `${left.path}\0${left.code}`;
    const rightKey = `${right.path}\0${right.code}`;
    return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
  });
  return {
    receipts: violations.length === 0 ? ingested.receipts : null,
    valid: violations.length === 0,
    violations,
  };
}

export function canonicalRunRecord(record) {
  const checked = validateRunRecord(record);
  if (!checked.valid) throw new TypeError('valid observational run record required');
  return canonicalize(record);
}

export function runRecordIdentity(record) {
  const semantic = structuredClone(canonicalRunRecord(record));
  for (const receipt of semantic.value_receipts) delete receipt.observed_at;
  return sha256Bytes(canonicalBytes(semantic));
}
