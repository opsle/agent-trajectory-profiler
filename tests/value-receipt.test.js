import test from 'node:test';
import assert from 'node:assert/strict';
import {
  ingestValueReceipts,
  validateValueReceipt,
  valueReceiptIdentity,
} from '../src/value-receipt.js';
import { exactMeasurement, receipt } from './helpers/value-fixtures.js';
import * as publicApi from '../src/index.js';

function codes(value) {
  return validateValueReceipt(value).violations.map((item) => item.code);
}

test('valid opsle.value-receipt.v1 is accepted', () => {
  assert.deepEqual(validateValueReceipt(receipt()), { valid: true, violations: [] });
});

test('public API exposes Visible Value primitives', () => {
  for (const name of [
    'validateValueReceipt',
    'valueReceiptIdentity',
    'ingestValueReceipts',
    'validateRunRecord',
    'runRecordIdentity',
    'summarizeRunRecord',
    'summarizeCumulativeValue',
    'valueSummaryOperatorIndicator',
  ]) assert.equal(typeof publicApi[name], 'function');
  assert.equal(publicApi.VALUE_RECEIPT_PROTOCOL, 'opsle.value-receipt.v1');
});

test('semantic receipt identity is deterministic and excludes caller timestamp', () => {
  const first = receipt({ observed_at: '2026-08-25T12:00:00Z' });
  const second = receipt({ observed_at: '2026-08-25T12:01:00Z' });
  assert.equal(valueReceiptIdentity(first), valueReceiptIdentity(second));
  assert.equal(valueReceiptIdentity(first), valueReceiptIdentity(structuredClone(first)));
});

test('unsupported schema and unknown fields are rejected', () => {
  const value = receipt({ schema: 'opsle.value-receipt.v2', surprise: true });
  assert.ok(codes(value).includes('UNSUPPORTED_SCHEMA'));
  assert.ok(codes(value).includes('UNKNOWN_FIELD'));
});

test('invalid units and measurement classes are rejected', () => {
  const value = receipt();
  value.measurements[0].unit = 'vibe';
  value.measurements[0].class = 'MARKETING';
  assert.ok(codes(value).includes('INVALID_UNIT'));
  assert.ok(codes(value).includes('INVALID_MEASUREMENT_CLASS'));
});

test('impossible values and delta sign misuse are rejected', () => {
  const value = receipt();
  value.measurements[0].result = -1;
  value.measurements[0].delta = 1;
  assert.ok(codes(value).includes('INVALID_NONNEGATIVE_INTEGER'));
  assert.ok(codes(value).includes('DELTA_MISMATCH'));
});

test('malformed and unresolved evidence references are rejected', () => {
  const value = receipt();
  value.evidence[0].locator = 'sha256:not-a-hash';
  value.measurements[0].evidence_refs = ['missing'];
  assert.ok(codes(value).includes('MALFORMED_CONTENT_HASH'));
  assert.ok(codes(value).includes('UNRESOLVED_EVIDENCE_REF'));
});

test('EXACT measurements require verified sources', () => {
  const value = receipt();
  value.measurements[0].source_verification = 'CALLER_SUPPLIED';
  assert.ok(codes(value).includes('EXACT_REQUIRES_VERIFIED_SOURCE'));
});

test('estimated and modeled measurements require inspectable derivation and cannot aggregate', () => {
  const value = receipt();
  value.measurements[0].class = 'MODELED';
  assert.ok(codes(value).includes('DERIVATION_REQUIRED'));
  assert.ok(codes(value).includes('UNSAFE_AGGREGATION'));
  value.measurements[0].aggregation = { method: null, safe: false };
  value.measurements[0].derivation = {
    assumptions: ['the alternate policy remains unchanged'],
    comparability: 'NOT_COMPARABLE',
    experiment_id: null,
    input_measurement_ids: [],
    method: 'counterfactual simulation',
  };
  assert.equal(validateValueReceipt(value).valid, true);
});

test('EXPERIMENTAL requires controlled experiment identity', () => {
  const value = receipt();
  value.measurements[0].class = 'EXPERIMENTAL';
  value.measurements[0].aggregation = { method: null, safe: false };
  value.measurements[0].derivation = {
    assumptions: [],
    comparability: 'NOT_COMPARABLE',
    experiment_id: null,
    input_measurement_ids: [],
    method: 'comparison',
  };
  assert.ok(codes(value).includes('CONTROLLED_EXPERIMENT_REQUIRED'));
});

test('ratio and modeled values cannot be marked summable', () => {
  const value = receipt();
  Object.assign(value.measurements[0], {
    baseline: 0,
    delta: 0.5,
    result: 0.5,
    unit: 'ratio',
  });
  assert.ok(codes(value).includes('UNSAFE_AGGREGATION'));
});

test('safe SUM accepts a numeric result with absent baseline and delta', () => {
  const value = receipt();
  Object.assign(value.measurements[0], {
    baseline: null,
    delta: null,
    result: 100,
  });
  assert.equal(validateValueReceipt(value).valid, true);
});

test('byte-only evidence cannot produce an estimated monetary claim', () => {
  const value = receipt();
  value.measurements.push(exactMeasurement({
    aggregation: { method: null, safe: false },
    baseline: 0,
    class: 'ESTIMATED',
    delta: 0.42,
    derivation: {
      assumptions: ['published price applies'],
      comparability: 'NOT_APPLICABLE',
      experiment_id: null,
      input_measurement_ids: ['raw_bytes'],
      method: 'price times input',
    },
    id: 'estimated_cost_usd',
    result: 0.42,
    unit: 'usd',
  }));
  assert.ok(codes(value).includes('MONETARY_ESTIMATE_WITHOUT_TOKENS'));
});

test('prevented-failure claims cannot be emitted as exact observations', () => {
  const value = receipt();
  value.measurements[0].id = 'failures_prevented_count';
  assert.ok(codes(value).includes('COUNTERFACTUAL_CLASS_MISUSE'));
});

test('ingestion binds run identity and rejects duplicate semantic receipts', () => {
  const mismatch = ingestValueReceipts([receipt()], { runId: 'other-run' });
  assert.equal(mismatch.valid, false);
  assert.ok(mismatch.violations.some((item) => item.code === 'RUN_IDENTITY_MISMATCH'));
  const duplicate = ingestValueReceipts([receipt(), receipt()], { runId: 'run-synthetic' });
  assert.equal(duplicate.valid, false);
  assert.ok(duplicate.violations.some((item) => item.code === 'DUPLICATE_VALUE_RECEIPT'));
});
