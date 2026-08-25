import test from 'node:test'; import assert from 'node:assert/strict'; import { compare, profile, ratio } from '../src/metrics.js';

test('types zero and near-zero denominators', () => {
  assert.equal(ratio(0, 0).kind, 'zero-over-zero');
  assert.equal(ratio(4, 1e-12).kind, 'near-zero-denominator');
});

test('profiles gross/net mutation and region revisit without calling every revisit waste', () => {
  const result = profile({ correctness: true, editPayloadBytes: 300, semanticResultBytes: 100, mutations: [
    { region: 'auth', bytes: 120, retained: false, cause: 'DISCOVERY' },
    { region: 'auth', bytes: 100, retained: true, cause: 'TEST_RUNTIME_EVIDENCE' },
    { region: 'docs', bytes: 20, retained: true, cause: 'KNOWN_AHEAD' },
  ] });
  assert.equal(result.grossMutation, 240); assert.equal(result.netMutation, 120);
  assert.equal(result.mutationAmplification.value, 2); assert.equal(result.semanticRegionRevisitRate, 0.5);
});

test('correctness gates comparisons', () => { assert.deepEqual(compare({ correctness: false }, { correctness: true }), { comparable: false, reason: 'correctness-gate' }); });
