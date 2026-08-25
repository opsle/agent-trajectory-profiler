import { canonicalBytes, canonicalize, sha256Bytes } from './canonical.js';

export const VALUE_RECEIPT_PROTOCOL = 'opsle.value-receipt.v1';

export const MEASUREMENT_CLASSES = Object.freeze([
  'EXACT',
  'OBSERVED',
  'ESTIMATED',
  'MODELED',
  'EXPERIMENTAL',
]);

export const MEASUREMENT_UNITS = Object.freeze([
  'byte',
  'event',
  'count',
  'ratio',
  'percent',
  'boolean',
  'millisecond',
  'token',
  'usd',
  'state',
]);

const classes = new Set(MEASUREMENT_CLASSES);
const units = new Set(MEASUREMENT_UNITS);
const directions = new Set([
  'HIGHER_IS_VALUE',
  'LOWER_IS_VALUE',
  'NEUTRAL',
  'PROTECTION_SIGNAL',
  'NOT_APPLICABLE',
]);
const verificationStates = new Set([
  'VERIFIED',
  'OBSERVED',
  'CALLER_SUPPLIED',
  'UNVERIFIED',
  'NOT_APPLICABLE',
]);
const evidenceKinds = new Set([
  'CONTENT_HASH',
  'JSON_POINTER',
  'RUN_ARTIFACT',
  'PROVIDER_RECORD',
  'URI',
  'CALLER_ASSERTION',
]);
const nonnegativeIntegerUnits = new Set(['byte', 'event', 'count', 'millisecond', 'token']);
const nonsummableUnits = new Set(['ratio', 'percent', 'boolean', 'state']);
const measurementIdPattern = /^[a-z][a-z0-9_]*$/;
const evidenceIdPattern = /^[a-z][a-z0-9._-]*$/;
const mechanismIdPattern = /^opsle\.[a-z0-9-]+$/;
const operationNamePattern = /^[a-z][a-z0-9-]*$/;
const sha256Pattern = /^sha256:[0-9a-f]{64}$/;
const rfc3339Pattern = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$/;

function isPlainObject(value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function isFiniteNumber(value) {
  return typeof value === 'number' && Number.isFinite(value);
}

function nonempty(value) {
  return typeof value === 'string' && value.length > 0;
}

function add(violations, code, path, message) {
  violations.push({ code, message, path });
}

function requiredFields(value, fields, path, violations) {
  for (const field of fields) {
    if (!Object.hasOwn(value, field)) {
      add(violations, 'REQUIRED_FIELD_MISSING', `${path}/${field}`, 'required field missing');
    }
  }
}

function rejectUnknownFields(value, fields, path, violations) {
  for (const field of Object.keys(value)) {
    if (!fields.includes(field)) {
      add(violations, 'UNKNOWN_FIELD', `${path}/${field}`, 'field is not part of value-receipt-v1');
    }
  }
}

function checkNullableString(value, path, violations) {
  if (value !== null && !nonempty(value)) {
    add(violations, 'INVALID_IDENTITY', path, 'nonempty string or null required');
  }
}

function checkStringArray(value, path, violations) {
  if (!Array.isArray(value)) {
    add(violations, 'ARRAY_REQUIRED', path, 'array required');
    return;
  }
  value.forEach((item, index) => {
    if (!nonempty(item)) add(violations, 'NONEMPTY_STRING_REQUIRED', `${path}/${index}`, 'nonempty string required');
  });
}

function checkValue(value, path, violations) {
  if (value === null || ['string', 'boolean'].includes(typeof value)) return;
  if (isFiniteNumber(value)) return;
  add(violations, 'INVALID_VALUE', path, 'finite number, string, boolean, or null required');
}

function validateEvidence(value, index, violations, evidenceIds, evidenceById) {
  const path = `/evidence/${index}`;
  if (!isPlainObject(value)) {
    add(violations, 'OBJECT_REQUIRED', path, 'evidence object required');
    return;
  }
  const fields = ['id', 'kind', 'locator', 'trust'];
  requiredFields(value, fields, path, violations);
  rejectUnknownFields(value, fields, path, violations);
  if (!nonempty(value.id) || !evidenceIdPattern.test(value.id)) {
    add(violations, 'INVALID_EVIDENCE_ID', `${path}/id`, 'lowercase evidence identity required');
  } else if (evidenceIds.has(value.id)) {
    add(violations, 'DUPLICATE_EVIDENCE_ID', `${path}/id`, 'duplicate evidence identity');
  } else {
    evidenceIds.add(value.id);
    evidenceById.set(value.id, value);
  }
  if (!evidenceKinds.has(value.kind)) {
    add(violations, 'INVALID_EVIDENCE_KIND', `${path}/kind`, 'unsupported evidence kind');
  }
  if (!nonempty(value.locator)) {
    add(violations, 'INVALID_EVIDENCE_LOCATOR', `${path}/locator`, 'nonempty locator required');
  } else if (value.kind === 'CONTENT_HASH' && !sha256Pattern.test(value.locator)) {
    add(violations, 'MALFORMED_CONTENT_HASH', `${path}/locator`, 'malformed sha256 content hash');
  }
  if (!verificationStates.has(value.trust)) {
    add(violations, 'INVALID_TRUST_STATE', `${path}/trust`, 'unsupported trust state');
  }
}

function validateDerivation(value, path, violations) {
  if (value === null) return;
  if (!isPlainObject(value)) {
    add(violations, 'INVALID_DERIVATION', path, 'object or null required');
    return;
  }
  const fields = ['method', 'assumptions', 'input_measurement_ids', 'experiment_id', 'comparability'];
  requiredFields(value, fields, path, violations);
  rejectUnknownFields(value, fields, path, violations);
  checkNullableString(value.method, `${path}/method`, violations);
  checkStringArray(value.assumptions, `${path}/assumptions`, violations);
  if (!Array.isArray(value.input_measurement_ids)) {
    add(violations, 'ARRAY_REQUIRED', `${path}/input_measurement_ids`, 'array required');
  } else {
    value.input_measurement_ids.forEach((identity, index) => {
      if (!nonempty(identity) || !measurementIdPattern.test(identity)) {
        add(violations, 'INVALID_MEASUREMENT_ID', `${path}/input_measurement_ids/${index}`, 'lowercase measurement identity required');
      }
    });
  }
  checkNullableString(value.experiment_id, `${path}/experiment_id`, violations);
  if (!['NOT_APPLICABLE', 'NOT_COMPARABLE', 'CONTROLLED'].includes(value.comparability)) {
    add(violations, 'INVALID_COMPARABILITY', `${path}/comparability`, 'unsupported comparability state');
  }
}

function validateMeasurement(value, index, state, violations) {
  const path = `/measurements/${index}`;
  if (!isPlainObject(value)) {
    add(violations, 'OBJECT_REQUIRED', path, 'measurement object required');
    return;
  }
  const fields = [
    'id', 'baseline', 'result', 'delta', 'unit', 'direction', 'class', 'evidence_refs',
    'source_verification', 'operator_display', 'aggregation', 'derivation', 'limitations',
  ];
  requiredFields(value, fields, path, violations);
  rejectUnknownFields(value, fields, path, violations);

  if (!nonempty(value.id) || !measurementIdPattern.test(value.id)) {
    add(violations, 'INVALID_MEASUREMENT_ID', `${path}/id`, 'lowercase measurement identity required');
  } else if (state.measurementIds.has(value.id)) {
    add(violations, 'DUPLICATE_MEASUREMENT_ID', `${path}/id`, 'duplicate measurement identity');
  } else {
    state.measurementIds.add(value.id);
    state.measurementById.set(value.id, value);
  }
  if (!units.has(value.unit)) add(violations, 'INVALID_UNIT', `${path}/unit`, 'unsupported unit');
  if (!classes.has(value.class)) add(violations, 'INVALID_MEASUREMENT_CLASS', `${path}/class`, 'unsupported measurement class');
  if (!directions.has(value.direction)) add(violations, 'INVALID_DIRECTION', `${path}/direction`, 'unsupported value direction');
  if (!verificationStates.has(value.source_verification)) {
    add(violations, 'INVALID_SOURCE_VERIFICATION', `${path}/source_verification`, 'unsupported verification state');
  }
  if (typeof value.operator_display !== 'boolean') {
    add(violations, 'BOOLEAN_REQUIRED', `${path}/operator_display`, 'boolean required');
  }

  for (const field of ['baseline', 'result', 'delta']) checkValue(value[field], `${path}/${field}`, violations);
  if (isFiniteNumber(value.baseline) && isFiniteNumber(value.result)) {
    if (!isFiniteNumber(value.delta) || Math.abs(value.delta - (value.result - value.baseline)) > 1e-12) {
      add(violations, 'DELTA_MISMATCH', `${path}/delta`, 'must equal result minus baseline');
    }
  } else if (value.delta !== null) {
    add(violations, 'DELTA_WITHOUT_NUMERIC_STATE', `${path}/delta`, 'must be null without numeric baseline and result');
  }
  if (nonnegativeIntegerUnits.has(value.unit)) {
    for (const field of ['baseline', 'result']) {
      const item = value[field];
      if (item !== null && (!Number.isSafeInteger(item) || item < 0)) {
        add(violations, 'INVALID_NONNEGATIVE_INTEGER', `${path}/${field}`, `nonnegative safe integer required for ${value.unit}`);
      }
    }
  }
  if (value.unit === 'boolean' && [value.baseline, value.result].some((item) => item !== null && typeof item !== 'boolean')) {
    add(violations, 'INVALID_BOOLEAN_MEASUREMENT', path, 'boolean unit requires boolean baseline and result');
  }
  if (value.unit === 'state' && [value.baseline, value.result].some((item) => item !== null && typeof item !== 'string')) {
    add(violations, 'INVALID_STATE_MEASUREMENT', path, 'state unit requires string baseline and result');
  }

  if (!Array.isArray(value.evidence_refs) || value.evidence_refs.length === 0) {
    add(violations, 'EVIDENCE_REFS_REQUIRED', `${path}/evidence_refs`, 'nonempty array required');
  } else {
    for (const reference of value.evidence_refs) {
      if (!state.evidenceIds.has(reference)) {
        add(violations, 'UNRESOLVED_EVIDENCE_REF', `${path}/evidence_refs`, `unresolved evidence reference ${JSON.stringify(reference)}`);
      }
    }
  }
  checkStringArray(value.limitations, `${path}/limitations`, violations);
  validateDerivation(value.derivation, `${path}/derivation`, violations);

  if (['ESTIMATED', 'MODELED'].includes(value.class)) {
    if (!isPlainObject(value.derivation)
      || !nonempty(value.derivation.method)
      || !Array.isArray(value.derivation.assumptions)
      || value.derivation.assumptions.length === 0) {
      add(violations, 'DERIVATION_REQUIRED', `${path}/derivation`, `${value.class} requires method and assumptions`);
    }
  }
  if (value.class === 'EXPERIMENTAL' && (
    !isPlainObject(value.derivation)
    || !nonempty(value.derivation.experiment_id)
    || value.derivation.comparability !== 'CONTROLLED'
  )) {
    add(violations, 'CONTROLLED_EXPERIMENT_REQUIRED', `${path}/derivation`, 'EXPERIMENTAL requires controlled experiment identity');
  }
  if (['EXACT', 'OBSERVED'].includes(value.class)
    && isPlainObject(value.derivation)
    && Array.isArray(value.derivation.assumptions)
    && value.derivation.assumptions.length > 0) {
    add(violations, 'ASSUMPTIONS_EXCEED_CLASS', `${path}/derivation`, `${value.class} cannot depend on assumptions`);
  }
  if (value.class === 'EXACT' && value.source_verification !== 'VERIFIED') {
    add(violations, 'EXACT_REQUIRES_VERIFIED_SOURCE', `${path}/source_verification`, 'EXACT requires VERIFIED evidence');
  }

  if (!isPlainObject(value.aggregation)) {
    add(violations, 'INVALID_AGGREGATION', `${path}/aggregation`, 'aggregation object required');
  } else {
    const aggregationFields = ['safe', 'method'];
    requiredFields(value.aggregation, aggregationFields, `${path}/aggregation`, violations);
    rejectUnknownFields(value.aggregation, aggregationFields, `${path}/aggregation`, violations);
    if (typeof value.aggregation.safe !== 'boolean' || ![null, 'SUM'].includes(value.aggregation.method)) {
      add(violations, 'INVALID_AGGREGATION', `${path}/aggregation`, 'safe boolean and SUM or null method required');
    }
    const hasCompleteDelta = isFiniteNumber(value.baseline) && isFiniteNumber(value.delta);
    const hasNoDelta = value.baseline === null && value.delta === null;
    if (value.aggregation.safe && (
      !['EXACT', 'OBSERVED'].includes(value.class)
      || value.aggregation.method !== 'SUM'
      || nonsummableUnits.has(value.unit)
      || !isFiniteNumber(value.result)
      || (!hasCompleteDelta && !hasNoDelta)
    )) {
      add(violations, 'UNSAFE_AGGREGATION', `${path}/aggregation`, 'measurement is not safely summable');
    }
    if (!value.aggregation.safe && value.aggregation.method !== null) {
      add(violations, 'UNSAFE_AGGREGATION_METHOD', `${path}/aggregation`, 'unsafe measurement must use null method');
    }
  }

  const loweredId = value.id ?? '';
  if ((loweredId.includes('failure_prevented') || loweredId.includes('failures_prevented'))
    && ['EXACT', 'OBSERVED'].includes(value.class)) {
    add(violations, 'COUNTERFACTUAL_CLASS_MISUSE', `${path}/class`, 'prevented-failure claims require MODELED or EXPERIMENTAL evidence');
  }
}

function validateMechanism(value, violations) {
  const path = '/mechanism';
  if (!isPlainObject(value)) {
    add(violations, 'OBJECT_REQUIRED', path, 'mechanism object required');
    return;
  }
  const fields = ['id', 'name', 'version', 'revision'];
  requiredFields(value, fields, path, violations);
  rejectUnknownFields(value, fields, path, violations);
  if (!nonempty(value.id) || !mechanismIdPattern.test(value.id)) {
    add(violations, 'INVALID_MECHANISM_ID', `${path}/id`, 'Opsle mechanism identity required');
  }
  for (const field of ['name', 'version']) {
    if (!nonempty(value[field])) add(violations, 'NONEMPTY_STRING_REQUIRED', `${path}/${field}`, 'nonempty string required');
  }
  checkNullableString(value.revision, `${path}/revision`, violations);
}

function validateRun(value, violations) {
  const path = '/run';
  if (!isPlainObject(value)) {
    add(violations, 'OBJECT_REQUIRED', path, 'run object required');
    return;
  }
  const fields = ['id', 'task_classification', 'work_classification', 'repository'];
  requiredFields(value, ['id'], path, violations);
  rejectUnknownFields(value, fields, path, violations);
  for (const field of fields) {
    if (Object.hasOwn(value, field)) checkNullableString(value[field], `${path}/${field}`, violations);
  }
}

function validateOperation(value, violations) {
  const path = '/operation';
  if (!isPlainObject(value)) {
    add(violations, 'OBJECT_REQUIRED', path, 'operation object required');
    return;
  }
  const fields = ['id', 'name', 'configuration_id', 'policy_id'];
  requiredFields(value, fields, path, violations);
  rejectUnknownFields(value, fields, path, violations);
  checkNullableString(value.id, `${path}/id`, violations);
  if (!nonempty(value.name) || !operationNamePattern.test(value.name)) {
    add(violations, 'INVALID_OPERATION_NAME', `${path}/name`, 'lowercase operation name required');
  }
  checkNullableString(value.configuration_id, `${path}/configuration_id`, violations);
  checkNullableString(value.policy_id, `${path}/policy_id`, violations);
}

export function validateValueReceipt(receipt) {
  const violations = [];
  if (!isPlainObject(receipt)) {
    return { valid: false, violations: [{ code: 'OBJECT_REQUIRED', message: 'receipt object required', path: '/' }] };
  }
  const fields = ['schema', 'mechanism', 'run', 'operation', 'observed_at', 'measurements', 'evidence', 'limitations', 'extensions'];
  requiredFields(receipt, ['schema', 'mechanism', 'run', 'operation', 'measurements', 'evidence', 'limitations'], '', violations);
  rejectUnknownFields(receipt, fields, '', violations);
  if (receipt.schema !== VALUE_RECEIPT_PROTOCOL) {
    add(violations, 'UNSUPPORTED_SCHEMA', '/schema', `only ${VALUE_RECEIPT_PROTOCOL} is supported`);
  }
  validateMechanism(receipt.mechanism, violations);
  validateRun(receipt.run, violations);
  validateOperation(receipt.operation, violations);
  if (Object.hasOwn(receipt, 'observed_at') && (
    !nonempty(receipt.observed_at)
    || !rfc3339Pattern.test(receipt.observed_at)
    || !Number.isFinite(Date.parse(receipt.observed_at))
  )) {
    add(violations, 'INVALID_OBSERVED_AT', '/observed_at', 'caller-supplied RFC 3339 timestamp required');
  }
  if (Object.hasOwn(receipt, 'extensions') && !isPlainObject(receipt.extensions)) {
    add(violations, 'OBJECT_REQUIRED', '/extensions', 'extensions object required');
  }

  const evidenceIds = new Set();
  const evidenceById = new Map();
  if (!Array.isArray(receipt.evidence) || receipt.evidence.length === 0) {
    add(violations, 'EVIDENCE_REQUIRED', '/evidence', 'nonempty evidence array required');
  } else {
    receipt.evidence.forEach((value, index) => validateEvidence(value, index, violations, evidenceIds, evidenceById));
  }

  const state = { evidenceIds, evidenceById, measurementIds: new Set(), measurementById: new Map() };
  if (!Array.isArray(receipt.measurements) || receipt.measurements.length === 0) {
    add(violations, 'MEASUREMENTS_REQUIRED', '/measurements', 'nonempty measurement array required');
  } else {
    receipt.measurements.forEach((value, index) => validateMeasurement(value, index, state, violations));
  }

  for (const [index, item] of (Array.isArray(receipt.measurements) ? receipt.measurements : []).entries()) {
    if (!isPlainObject(item) || item.unit !== 'usd' || !['ESTIMATED', 'MODELED'].includes(item.class)) continue;
    const inputs = isPlainObject(item.derivation) && Array.isArray(item.derivation.input_measurement_ids)
      ? item.derivation.input_measurement_ids : [];
    const inputUnits = new Set(inputs.map((identity) => state.measurementById.get(identity)?.unit));
    if (!inputUnits.has('token')) {
      add(violations, 'MONETARY_ESTIMATE_WITHOUT_TOKENS', `/measurements/${index}/derivation`, 'monetary estimate requires a token measurement input');
    }
  }
  checkStringArray(receipt.limitations, '/limitations', violations);
  try {
    canonicalize(receipt);
  } catch (error) {
    add(violations, 'INVALID_JSON_VALUE', '/', error.message);
  }
  violations.sort((left, right) => {
    const leftKey = `${left.path}\0${left.code}\0${left.message}`;
    const rightKey = `${right.path}\0${right.code}\0${right.message}`;
    return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
  });
  return { valid: violations.length === 0, violations };
}

export function semanticValueReceipt(receipt) {
  const checked = validateValueReceipt(receipt);
  if (!checked.valid) throw new TypeError('valid opsle.value-receipt.v1 required');
  const semantic = structuredClone(receipt);
  delete semantic.observed_at;
  return canonicalize(semantic);
}

export function valueReceiptIdentity(receipt) {
  return sha256Bytes(canonicalBytes(semanticValueReceipt(receipt)));
}

export function ingestValueReceipts(receipts, { runId = null } = {}) {
  const violations = [];
  if (!Array.isArray(receipts)) {
    return { receipts: null, valid: false, violations: [{ code: 'ARRAY_REQUIRED', message: 'value receipts array required', path: '/value_receipts' }] };
  }
  const accepted = [];
  const identities = new Set();
  receipts.forEach((receipt, index) => {
    const checked = validateValueReceipt(receipt);
    for (const violation of checked.violations) {
      violations.push({ ...violation, path: `/value_receipts/${index}${violation.path === '/' ? '' : violation.path}` });
    }
    if (!checked.valid) return;
    if (runId !== null && receipt.run.id !== null && receipt.run.id !== runId) {
      add(violations, 'RUN_IDENTITY_MISMATCH', `/value_receipts/${index}/run/id`, 'receipt run must match observational run');
      return;
    }
    const identity = valueReceiptIdentity(receipt);
    if (identities.has(identity)) {
      add(violations, 'DUPLICATE_VALUE_RECEIPT', `/value_receipts/${index}`, 'duplicate semantic value receipt');
      return;
    }
    identities.add(identity);
    accepted.push({ identity, receipt: canonicalize(receipt) });
  });
  accepted.sort((left, right) => left.identity < right.identity ? -1 : left.identity > right.identity ? 1 : 0);
  violations.sort((left, right) => {
    const leftKey = `${left.path}\0${left.code}`;
    const rightKey = `${right.path}\0${right.code}`;
    return leftKey < rightKey ? -1 : leftKey > rightKey ? 1 : 0;
  });
  return { receipts: violations.length === 0 ? accepted : null, valid: violations.length === 0, violations };
}
