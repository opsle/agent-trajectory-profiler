import { canonicalBytes, canonicalJson, canonicalize, sha256Bytes } from './canonical.js';
import { runRecordIdentity, validateRunRecord } from './run-record.js';

export const VALUE_SUMMARY_PROTOCOL = 'opsle.agent-trajectory-profiler.value-summary/v1';

const safeIntegerUnits = new Set(['byte', 'event', 'count', 'millisecond', 'token']);

function compareText(left, right) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function addNumeric(left, right, unit) {
  const result = left + right;
  if (!Number.isFinite(result)) throw new RangeError('aggregate exceeds finite numeric range');
  if (safeIntegerUnits.has(unit) && !Number.isSafeInteger(result)) {
    throw new RangeError('aggregate exceeds safe integer range');
  }
  return result;
}

function referencedEvidence(receipt, measurement) {
  const references = new Set(measurement.evidence_refs);
  return receipt.evidence.filter((item) => references.has(item.id)).sort((left, right) => compareText(left.id, right.id));
}

function evidenceTrust(receipt, measurement) {
  return [...new Set(referencedEvidence(receipt, measurement).map((item) => item.trust))].sort(compareText);
}

function mechanismProjection(receipt) {
  return {
    configuration_id: receipt.operation.configuration_id,
    id: receipt.mechanism.id,
    name: receipt.mechanism.name,
    policy_id: receipt.operation.policy_id,
    revision: receipt.mechanism.revision,
    version: receipt.mechanism.version,
  };
}

function aggregateProjection(receipt, measurement) {
  return {
    class: measurement.class,
    configuration_id: receipt.operation.configuration_id,
    direction: measurement.direction,
    evidence_trust: evidenceTrust(receipt, measurement),
    mechanism_id: receipt.mechanism.id,
    mechanism_revision: receipt.mechanism.revision,
    mechanism_version: receipt.mechanism.version,
    measurement_id: measurement.id,
    method: measurement.aggregation.method,
    policy_id: receipt.operation.policy_id,
    source_verification: measurement.source_verification,
    unit: measurement.unit,
  };
}

function flatten(records) {
  const entries = [];
  for (const item of records) {
    for (const accepted of item.checked.receipts) {
      const receipt = accepted.receipt;
      for (const measurement of receipt.measurements) {
        entries.push({
          measurement,
          receipt,
          receiptIdentity: accepted.identity,
          recordIdentity: item.recordIdentity,
          runId: item.record.run.id,
        });
      }
    }
  }
  entries.sort((left, right) => compareText(
    `${left.runId}\0${left.receiptIdentity}\0${left.measurement.id}`,
    `${right.runId}\0${right.receiptIdentity}\0${right.measurement.id}`,
  ));
  return entries;
}

function classCounts(entries) {
  const counts = new Map();
  for (const { measurement } of entries) counts.set(measurement.class, (counts.get(measurement.class) ?? 0) + 1);
  return Object.fromEntries([...counts.entries()].sort(([left], [right]) => compareText(left, right)));
}

function mechanismSummaries(records) {
  const groups = new Map();
  for (const item of records) {
    for (const accepted of item.checked.receipts) {
      const receipt = accepted.receipt;
      const projection = mechanismProjection(receipt);
      const key = canonicalJson(projection);
      const current = groups.get(key) ?? {
        ...projection,
        measurement_count: 0,
        operator_display_measurement_count: 0,
        receipt_identities: [],
        run_ids: new Set(),
      };
      current.measurement_count += receipt.measurements.length;
      current.operator_display_measurement_count += receipt.measurements.filter((measurement) => measurement.operator_display).length;
      current.receipt_identities.push(accepted.identity);
      current.run_ids.add(item.record.run.id);
      groups.set(key, current);
    }
  }
  return [...groups.values()].map((value) => ({
    ...value,
    receipt_count: value.receipt_identities.length,
    receipt_identities: value.receipt_identities.sort(compareText),
    run_count: value.run_ids.size,
    run_ids: [...value.run_ids].sort(compareText),
  })).sort((left, right) => compareText(canonicalJson(left), canonicalJson(right)));
}

function visibleMeasurements(entries) {
  return entries.filter(({ measurement }) => measurement.operator_display).map((entry) => ({
    baseline: entry.measurement.baseline,
    class: entry.measurement.class,
    delta: entry.measurement.delta,
    direction: entry.measurement.direction,
    evidence: referencedEvidence(entry.receipt, entry.measurement),
    limitations: [...entry.measurement.limitations],
    measurement_id: entry.measurement.id,
    mechanism: mechanismProjection(entry.receipt),
    operation_id: entry.receipt.operation.id,
    operation_name: entry.receipt.operation.name,
    receipt_identity: entry.receiptIdentity,
    result: entry.measurement.result,
    run_id: entry.runId,
    source_verification: entry.measurement.source_verification,
    unit: entry.measurement.unit,
  }));
}

function aggregateMeasurements(entries) {
  const groups = new Map();
  const excluded = [];
  const violations = [];
  for (const entry of entries) {
    const { measurement, receipt } = entry;
    if (measurement.aggregation.safe !== true || measurement.aggregation.method !== 'SUM') {
      excluded.push({
        class: measurement.class,
        measurement_id: measurement.id,
        mechanism_id: receipt.mechanism.id,
        reason: 'NOT_MARKED_SAFE',
        receipt_identity: entry.receiptIdentity,
        run_id: entry.runId,
        unit: measurement.unit,
      });
      continue;
    }
    const projection = aggregateProjection(receipt, measurement);
    const key = canonicalJson(projection);
    const stateShape = measurement.baseline === null ? 'RESULT_ONLY' : 'BASELINE_RESULT_DELTA';
    const current = groups.get(key) ?? {
      ...projection,
      baseline_total: stateShape === 'RESULT_ONLY' ? null : 0,
      delta_total: stateShape === 'RESULT_ONLY' ? null : 0,
      receipt_identities: [],
      result_total: 0,
      run_ids: new Set(),
      stateShape,
    };
    if (current.stateShape !== stateShape) {
      violations.push({
        code: 'INCOMPATIBLE_AGGREGATE_STATE',
        message: 'one aggregate group cannot mix result-only and baseline/result/delta measurements',
        path: `/measurements/${measurement.id}`,
      });
      continue;
    }
    try {
      if (stateShape === 'BASELINE_RESULT_DELTA') {
        current.baseline_total = addNumeric(current.baseline_total, measurement.baseline, measurement.unit);
        current.delta_total = addNumeric(current.delta_total, measurement.delta, measurement.unit);
      }
      current.result_total = addNumeric(current.result_total, measurement.result, measurement.unit);
    } catch (error) {
      if (!(error instanceof RangeError)) throw error;
      violations.push({
        code: 'AGGREGATE_OVERFLOW',
        message: error.message,
        path: `/measurements/${measurement.id}`,
      });
      continue;
    }
    current.receipt_identities.push(entry.receiptIdentity);
    current.run_ids.add(entry.runId);
    groups.set(key, current);
  }
  const aggregates = [...groups.values()].map((value) => ({
    baseline_total: value.baseline_total,
    class: value.class,
    configuration_id: value.configuration_id,
    delta_total: value.delta_total,
    direction: value.direction,
    evidence_trust: value.evidence_trust,
    mechanism_id: value.mechanism_id,
    mechanism_revision: value.mechanism_revision,
    mechanism_version: value.mechanism_version,
    measurement_id: value.measurement_id,
    method: value.method,
    policy_id: value.policy_id,
    receipt_count: value.receipt_identities.length,
    receipt_identities: value.receipt_identities.sort(compareText),
    result_total: value.result_total,
    run_count: value.run_ids.size,
    run_ids: [...value.run_ids].sort(compareText),
    source_verification: value.source_verification,
    unit: value.unit,
  })).sort((left, right) => compareText(canonicalJson(left), canonicalJson(right)));
  excluded.sort((left, right) => compareText(canonicalJson(left), canonicalJson(right)));
  violations.sort((left, right) => compareText(`${left.path}\0${left.code}`, `${right.path}\0${right.code}`));
  return { aggregates, excluded, violations };
}

function checkedRecords(records) {
  const violations = [];
  const checked = [];
  const runIds = new Set();
  const recordIds = new Set();
  const receiptIds = new Set();
  records.forEach((record, index) => {
    const result = validateRunRecord(record);
    for (const violation of result.violations) {
      violations.push({ ...violation, path: `/records/${index}${violation.path === '/' ? '' : violation.path}` });
    }
    if (!result.valid) return;
    const identity = runRecordIdentity(record);
    if (runIds.has(record.run.id)) {
      violations.push({ code: 'DUPLICATE_RUN_ID', message: 'cumulative summary requires unique run identities', path: `/records/${index}/run/id` });
    }
    if (recordIds.has(identity)) {
      violations.push({ code: 'DUPLICATE_RUN_RECORD', message: 'duplicate semantic run record', path: `/records/${index}` });
    }
    for (const receipt of result.receipts) {
      if (receiptIds.has(receipt.identity)) {
        violations.push({ code: 'DUPLICATE_VALUE_RECEIPT', message: 'one semantic receipt cannot be counted in multiple runs', path: `/records/${index}/value_receipts` });
      }
      receiptIds.add(receipt.identity);
    }
    runIds.add(record.run.id);
    recordIds.add(identity);
    checked.push({ checked: result, record: canonicalize(record), recordIdentity: identity });
  });
  violations.sort((left, right) => compareText(`${left.path}\0${left.code}`, `${right.path}\0${right.code}`));
  return { records: violations.length === 0 ? checked : null, valid: violations.length === 0, violations };
}

function finalize(base) {
  const canonical = canonicalize(base);
  return { ...canonical, summary_identity: sha256Bytes(canonicalBytes(canonical)) };
}

function invalidSummary(scope, violations) {
  return finalize({
    measurement_status: 'UNAVAILABLE_INVALID_RUN_RECORD',
    protocol_version: VALUE_SUMMARY_PROTOCOL,
    scope,
    valid: false,
    violations,
  });
}

function summaryBody(records, scope) {
  const entries = flatten(records);
  const { aggregates, excluded, violations } = aggregateMeasurements(entries);
  if (violations.length > 0) return { body: null, violations };
  const body = {
    aggregates,
    class_counts: classCounts(entries),
    excluded_from_aggregation: excluded,
    measurement_count: entries.length,
    measurement_status: 'MEASURED',
    mechanisms: mechanismSummaries(records),
    operator_display_measurement_count: entries.filter(({ measurement }) => measurement.operator_display).length,
    protocol_version: VALUE_SUMMARY_PROTOCOL,
    receipt_count: records.reduce((sum, item) => sum + item.checked.receipts.length, 0),
    run_count: records.length,
    scope,
    valid: true,
    violations: [],
    visible_measurements: visibleMeasurements(entries),
  };
  return { body, violations: [] };
}

export function summarizeRunRecord(record) {
  const checked = validateRunRecord(record);
  if (!checked.valid) return invalidSummary('RUN', checked.violations);
  const item = { checked, record: canonicalize(record), recordIdentity: runRecordIdentity(record) };
  const projected = summaryBody([item], 'RUN');
  if (projected.violations.length > 0) return invalidSummary('RUN', projected.violations);
  const { body } = projected;
  body.record_identity = item.recordIdentity;
  body.run = canonicalize(record.run);
  if (Object.hasOwn(record, 'telemetry')) body.telemetry = canonicalize(record.telemetry);
  if (Object.hasOwn(record, 'events')) body.events = canonicalize(record.events);
  if (Object.hasOwn(record, 'outcome')) body.outcome = canonicalize(record.outcome);
  if (Object.hasOwn(record, 'evidence_refs')) body.evidence_refs = canonicalize(record.evidence_refs);
  return finalize(body);
}

export function summarizeCumulativeValue(records) {
  if (!Array.isArray(records) || records.length === 0) {
    return invalidSummary('CUMULATIVE', [{ code: 'RUN_RECORDS_REQUIRED', message: 'nonempty run-record array required', path: '/records' }]);
  }
  const checked = checkedRecords(records);
  if (!checked.valid) return invalidSummary('CUMULATIVE', checked.violations);
  const projected = summaryBody(checked.records, 'CUMULATIVE');
  if (projected.violations.length > 0) return invalidSummary('CUMULATIVE', projected.violations);
  const { body } = projected;
  body.runs = checked.records.map((item) => ({
    record_identity: item.recordIdentity,
    run_id: item.record.run.id,
  })).sort((left, right) => compareText(left.run_id, right.run_id));
  return finalize(body);
}

function countLabel(value, singular, plural = `${singular}s`) {
  return `${value} ${value === 1 ? singular : plural}`;
}

export function trajectoryOperatorIndicator(profile) {
  if (!profile.measurements) {
    return `[Trajectory Profiler] ${profile.run_id ?? 'unknown run'} rejected | ${countLabel(profile.violations.length, 'violation')}\n`;
  }
  const value = profile.measurements;
  return `[Trajectory Profiler] ${profile.run_id} | ${value.initial_model_visible_bytes} B initially visible | ${value.final_model_visible_bytes} B final | ${countLabel(value.escalation_fulfilled_count, 'escalation')} fulfilled\n`;
}

export function valueSummaryOperatorIndicator(summary) {
  if (!summary.valid) {
    return `[Trajectory Profiler] value telemetry rejected | ${countLabel(summary.violations.length, 'violation')}\n`;
  }
  const subject = summary.scope === 'RUN' ? `run ${summary.run.id}` : `${summary.run_count} runs`;
  return `[Trajectory Profiler] ${subject} | ${countLabel(summary.receipt_count, 'receipt')} ingested | ${countLabel(summary.operator_display_measurement_count, 'visible measurement')} | ${countLabel(summary.aggregates.length, 'safe aggregate')}\n`;
}
