export function exactMeasurement(overrides = {}) {
  return {
    aggregation: { method: 'SUM', safe: true },
    baseline: 0,
    class: 'EXACT',
    delta: 100,
    derivation: null,
    direction: 'NEUTRAL',
    evidence_refs: ['result'],
    id: 'raw_bytes',
    limitations: [],
    operator_display: true,
    result: 100,
    source_verification: 'VERIFIED',
    unit: 'byte',
    ...overrides,
  };
}

export function receipt(overrides = {}) {
  return {
    evidence: [{
      id: 'result',
      kind: 'CONTENT_HASH',
      locator: `sha256:${'a'.repeat(64)}`,
      trust: 'VERIFIED',
    }],
    limitations: ['No token, cost, latency, correctness, or causal claim is made.'],
    measurements: [exactMeasurement()],
    mechanism: {
      id: 'opsle.context-firewall',
      name: 'Context Firewall',
      revision: 'cf-revision',
      version: '0.3.0',
    },
    operation: {
      configuration_id: 'sha256:configuration',
      id: 'op-synthetic',
      name: 'test-output-reduction',
      policy_id: 'tap-subset-policy/v1',
    },
    run: { id: 'run-synthetic' },
    schema: 'opsle.value-receipt.v1',
    ...overrides,
  };
}
