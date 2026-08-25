import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { canonicalJson } from '../src/canonical.js';
import { validateRunRecord } from '../src/run-record.js';
import {
  summarizeCumulativeValue,
  summarizeRunRecord,
  valueSummaryOperatorIndicator,
} from '../src/value-summary.js';
import { receipt as contextFirewallReceipt } from './helpers/value-fixtures.js';

function decisionEvidenceReceipt(runId = 'run-synthetic') {
  return contextFirewallReceipt({
    measurements: [
      {
        aggregation: { method: 'SUM', safe: true },
        baseline: 0,
        class: 'EXACT',
        delta: 12,
        derivation: null,
        direction: 'HIGHER_IS_VALUE',
        evidence_refs: ['result'],
        id: 'invariants_checked',
        limitations: ['Checks performed do not establish a prevented failure.'],
        operator_display: true,
        result: 12,
        source_verification: 'VERIFIED',
        unit: 'count',
      },
      {
        aggregation: { method: null, safe: false },
        baseline: null,
        class: 'OBSERVED',
        delta: null,
        derivation: null,
        direction: 'PROTECTION_SIGNAL',
        evidence_refs: ['result'],
        id: 'source_backed_verification',
        limitations: [],
        operator_display: true,
        result: true,
        source_verification: 'OBSERVED',
        unit: 'boolean',
      },
    ],
    mechanism: {
      id: 'opsle.decision-evidence-protocol',
      name: 'Decision Evidence',
      revision: 'dep-revision',
      version: '0.3.0',
    },
    operation: {
      configuration_id: 'validation/v1',
      id: 'validate-synthetic',
      name: 'evidence-validation',
      policy_id: null,
    },
    run: { id: runId },
  });
}

function mechanism(receipt) {
  return {
    configuration_id: receipt.operation.configuration_id,
    id: receipt.mechanism.id,
    name: receipt.mechanism.name,
    policy_id: receipt.operation.policy_id,
    revision: receipt.mechanism.revision,
    version: receipt.mechanism.version,
  };
}

function runRecord(runId = 'run-synthetic') {
  const firewall = contextFirewallReceipt({ run: { id: runId } });
  const evidence = decisionEvidenceReceipt(runId);
  return {
    mechanisms: [mechanism(firewall), mechanism(evidence)],
    protocol_version: 'opsle.agent-trajectory-profiler.run-record/v1',
    run: {
      id: runId,
      project: 'Opsle Prompt 005',
      repository: 'opsle/agent-trajectory-profiler',
      task_classification: 'implementation',
      work_classification: 'public-synthetic',
    },
    telemetry: {
      child_execution_count: 1,
      tool_call_count: 7,
    },
    value_receipts: [firewall, evidence],
  };
}

test('observational record accepts optional fields and preserves missingness', () => {
  const record = runRecord();
  assert.equal(validateRunRecord(record).valid, true);
  const summary = summarizeRunRecord(record);
  assert.equal(summary.valid, true);
  assert.deepEqual(summary.telemetry, { child_execution_count: 1, tool_call_count: 7 });
  assert.equal(Object.hasOwn(summary.telemetry, 'polling_turn_count'), false);
  assert.equal(Object.hasOwn(summary.run, 'model'), false);
});

test('observational record binds available everyday telemetry and outcomes', () => {
  const record = runRecord();
  Object.assign(record.run, {
    model: 'known-model',
    reasoning_effort: 'known-effort',
  });
  Object.assign(record.telemetry, {
    escalation_event_count: 1,
    failure_event_count: 1,
    final_model_visible_bytes: 120,
    initial_model_visible_bytes: 100,
    passive_wait_milliseconds: 250,
    polling_turn_count: 2,
    provider_recorded_tokens: {
      input: 10,
      output: 5,
      source: 'PROVIDER_RECORDED',
      total: 15,
    },
    raw_evidence_bytes: 500,
    recovery_event_count: 1,
  });
  record.events = [
    { evidence_refs: ['artifact://escalation'], id: 'event-1', operation_id: 'op-synthetic', status: 'FULFILLED', type: 'ESCALATION' },
    { id: 'event-2', type: 'FAILURE' },
    { id: 'event-3', type: 'RECOVERY' },
  ];
  record.outcome = { acceptance: 'ACCEPTED', review: 'PASSED' };
  record.evidence_refs = ['artifact://run'];
  const summary = summarizeRunRecord(record);
  assert.equal(summary.valid, true);
  assert.deepEqual(summary.telemetry.provider_recorded_tokens, {
    input: 10,
    output: 5,
    source: 'PROVIDER_RECORDED',
    total: 15,
  });
  assert.equal(summary.events.length, 3);
  assert.deepEqual(summary.outcome, { acceptance: 'ACCEPTED', review: 'PASSED' });
  assert.equal(summary.run.model, 'known-model');
});

test('provider tokens require recorded provenance and coherent totals', () => {
  const record = runRecord();
  record.telemetry.provider_recorded_tokens = {
    input: 10,
    output: 5,
    source: 'ESTIMATED',
    total: 14,
  };
  const result = validateRunRecord(record);
  assert.ok(result.violations.some((item) => item.code === 'INVALID_TOKEN_SOURCE'));
  assert.ok(result.violations.some((item) => item.code === 'TOKEN_TOTAL_MISMATCH'));
});

test('multiple mechanisms preserve classes and produce unit-aware safe aggregates', () => {
  const summary = summarizeRunRecord(runRecord());
  assert.equal(summary.receipt_count, 2);
  assert.equal(summary.mechanisms.length, 2);
  assert.deepEqual(summary.class_counts, { EXACT: 2, OBSERVED: 1 });
  assert.equal(summary.aggregates.length, 2);
  assert.deepEqual(summary.aggregates.map((item) => item.unit), ['byte', 'count']);
  assert.equal(summary.excluded_from_aggregation.length, 1);
  assert.equal(summary.visible_measurements.find((item) => item.measurement_id === 'source_backed_verification').class, 'OBSERVED');
});

test('result-only measurements aggregate without inventing baseline or delta totals', () => {
  const record = runRecord();
  const measurement = record.value_receipts[0].measurements[0];
  measurement.baseline = null;
  measurement.delta = null;
  const summary = summarizeRunRecord(record);
  assert.equal(summary.valid, true);
  const aggregate = summary.aggregates.find((item) => item.measurement_id === 'raw_bytes');
  assert.equal(aggregate.result_total, 100);
  assert.equal(aggregate.baseline_total, null);
  assert.equal(aggregate.delta_total, null);
});

test('mixed result-only and delta-bearing values in one aggregate group fail closed', () => {
  const record = runRecord();
  const duplicate = contextFirewallReceipt({
    operation: {
      ...record.value_receipts[0].operation,
      id: 'op-result-only',
    },
    run: { id: record.run.id },
  });
  duplicate.measurements[0].baseline = null;
  duplicate.measurements[0].delta = null;
  record.value_receipts.push(duplicate);
  const summary = summarizeRunRecord(record);
  assert.equal(summary.valid, false);
  assert.ok(summary.violations.some((item) => item.code === 'INCOMPATIBLE_AGGREGATE_STATE'));
});

test('aggregation partitions incompatible units, classes, revisions, configurations, and trust', () => {
  const record = runRecord();
  const variants = [];
  for (const [suffix, mutate] of [
    ['unit', (value) => { value.measurements[0].unit = 'count'; }],
    ['class', (value) => { value.measurements[0].class = 'OBSERVED'; value.measurements[0].source_verification = 'OBSERVED'; }],
    ['revision', (value) => { value.mechanism.revision = 'other-revision'; }],
    ['configuration', (value) => { value.operation.configuration_id = 'other-configuration'; }],
    ['trust', (value) => { value.measurements[0].class = 'OBSERVED'; value.measurements[0].source_verification = 'CALLER_SUPPLIED'; value.evidence[0].trust = 'CALLER_SUPPLIED'; }],
  ]) {
    const value = contextFirewallReceipt({ run: { id: record.run.id } });
    mutate(value);
    value.operation.id = `op-${suffix}`;
    variants.push(value);
    const declaration = mechanism(value);
    if (!record.mechanisms.some((item) => canonicalJson(item) === canonicalJson(declaration))) {
      record.mechanisms.push(declaration);
    }
  }
  record.value_receipts.push(...variants);
  const summary = summarizeRunRecord(record);
  assert.equal(summary.valid, true);
  assert.equal(summary.aggregates.length, 7);
});

test('unsafe modeled measurements remain visible by class but are never aggregated', () => {
  const record = runRecord();
  const modeled = record.value_receipts[0].measurements[0];
  Object.assign(modeled, {
    aggregation: { method: null, safe: false },
    class: 'MODELED',
    derivation: {
      assumptions: ['future policy remains unchanged'],
      comparability: 'NOT_COMPARABLE',
      experiment_id: null,
      input_measurement_ids: [],
      method: 'counterfactual model',
    },
  });
  const summary = summarizeRunRecord(record);
  assert.equal(summary.valid, true);
  assert.equal(summary.visible_measurements.find((item) => item.measurement_id === 'raw_bytes').class, 'MODELED');
  assert.equal(summary.aggregates.some((item) => item.measurement_id === 'raw_bytes'), false);
});

test('ordinary observational records reject EXPERIMENTAL measurements', () => {
  const record = runRecord();
  const experimental = record.value_receipts[0].measurements[0];
  Object.assign(experimental, {
    aggregation: { method: null, safe: false },
    class: 'EXPERIMENTAL',
    derivation: {
      assumptions: [],
      comparability: 'CONTROLLED',
      experiment_id: 'EXP-SYNTHETIC',
      input_measurement_ids: [],
      method: 'controlled comparison',
    },
  });
  const result = validateRunRecord(record);
  assert.equal(result.valid, false);
  assert.ok(result.violations.some((item) => item.code === 'EXPERIMENTAL_IN_OBSERVATIONAL_RECORD'));
});

test('mechanism declarations bind exact receipt revision and configuration', () => {
  const record = runRecord();
  record.mechanisms[0].revision = 'wrong-revision';
  const result = validateRunRecord(record);
  assert.equal(result.valid, false);
  assert.ok(result.violations.some((item) => item.code === 'MECHANISM_DECLARATION_MISMATCH'));
});

test('cumulative summary combines compatible values but preserves per-run identities', () => {
  const first = runRecord('run-a');
  const second = runRecord('run-b');
  const summary = summarizeCumulativeValue([second, first]);
  assert.equal(summary.valid, true);
  assert.equal(summary.run_count, 2);
  assert.deepEqual(summary.runs.map((item) => item.run_id), ['run-a', 'run-b']);
  assert.equal(summary.aggregates.find((item) => item.measurement_id === 'raw_bytes').result_total, 200);
  assert.equal(summary.aggregates.find((item) => item.measurement_id === 'invariants_checked').result_total, 24);
});

test('cumulative aggregation fails closed on safe-integer overflow', () => {
  const first = runRecord('run-overflow-a');
  const second = runRecord('run-overflow-b');
  for (const record of [first, second]) {
    const measurement = record.value_receipts[0].measurements[0];
    measurement.baseline = null;
    measurement.delta = null;
  }
  first.value_receipts[0].measurements[0].result = Number.MAX_SAFE_INTEGER;
  second.value_receipts[0].measurements[0].result = 1;
  const summary = summarizeCumulativeValue([first, second]);
  assert.equal(summary.valid, false);
  assert.ok(summary.violations.some((item) => item.code === 'AGGREGATE_OVERFLOW'));
});

test('per-run and cumulative Opsle Value summaries are byte-for-byte deterministic', () => {
  const record = runRecord();
  assert.equal(canonicalJson(summarizeRunRecord(record)), canonicalJson(summarizeRunRecord(structuredClone(record))));
  const records = [runRecord('run-a'), runRecord('run-b')];
  assert.equal(canonicalJson(summarizeCumulativeValue(records)), canonicalJson(summarizeCumulativeValue([...records].reverse())));
});

test('caller timestamp does not alter run or summary semantic identity', () => {
  const first = runRecord();
  const second = structuredClone(first);
  first.value_receipts[0].observed_at = '2026-08-25T12:00:00Z';
  second.value_receipts[0].observed_at = '2026-08-25T12:01:00Z';
  assert.equal(summarizeRunRecord(first).record_identity, summarizeRunRecord(second).record_identity);
  assert.equal(summarizeRunRecord(first).summary_identity, summarizeRunRecord(second).summary_identity);
});

test('operator indicator is stable and names Trajectory Profiler', () => {
  const indicator = valueSummaryOperatorIndicator(summarizeRunRecord(runRecord()));
  assert.equal(indicator, '[Trajectory Profiler] run run-synthetic | 2 receipts ingested | 3 visible measurements | 2 safe aggregates\n');
});

test('CLI writes canonical summary to stdout and exactly one named indicator to stderr', () => {
  const directory = mkdtempSync(join(tmpdir(), 'opsle-value-summary-'));
  try {
    const path = join(directory, 'run.json');
    writeFileSync(path, `${canonicalJson(runRecord())}\n`, 'utf8');
    const args = ['bin/agent-trajectory-profiler.js', 'value-summary', path];
    const first = spawnSync(process.execPath, args, { encoding: 'utf8' });
    const second = spawnSync(process.execPath, args, { encoding: 'utf8' });
    assert.equal(first.status, 0, first.stderr);
    assert.equal(first.stdout, second.stdout);
    assert.doesNotThrow(() => JSON.parse(first.stdout));
    assert.equal(first.stderr, '[Trajectory Profiler] run run-synthetic | 2 receipts ingested | 3 visible measurements | 2 safe aggregates\n');
    const quiet = spawnSync(process.execPath, [...args, '--quiet'], { encoding: 'utf8' });
    assert.equal(quiet.status, 0, quiet.stderr);
    assert.equal(quiet.stdout, first.stdout);
    assert.equal(quiet.stderr, '');
  } finally {
    rmSync(directory, { recursive: true });
  }
});
