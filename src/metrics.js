export const REVISIT_CAUSES = Object.freeze(['KNOWN_AHEAD','DISCOVERY','TEST_RUNTIME_EVIDENCE','SELF_CORRECTION','FORMATTER','CONFLICT','OTHER_UNKNOWN']);

export function ratio(numerator, denominator, epsilon = 1e-9) {
  if (numerator === 0 && denominator === 0) return { kind: 'zero-over-zero', value: null };
  if (Math.abs(denominator) < epsilon) return { kind: 'near-zero-denominator', value: null };
  return { kind: 'finite', value: numerator / denominator };
}

export function profile({ correctness, mutations, editPayloadBytes, semanticResultBytes }) {
  const grossMutation = mutations.reduce((sum, item) => sum + Math.abs(item.bytes), 0);
  const netMutation = mutations.filter((item) => item.retained).reduce((sum, item) => sum + item.bytes, 0);
  const visits = new Map();
  for (const item of mutations) {
    if (!REVISIT_CAUSES.includes(item.cause)) throw new Error('unknown revisit cause');
    visits.set(item.region, (visits.get(item.region) ?? 0) + 1);
  }
  const revisited = [...visits.values()].filter((count) => count > 1).length;
  return {
    correctness, grossMutation, netMutation,
    mutationAmplification: ratio(grossMutation, Math.abs(netMutation)),
    editPayloadAmplification: ratio(editPayloadBytes, semanticResultBytes),
    semanticRegionRevisitRate: visits.size ? revisited / visits.size : 0,
  };
}

export function compare(left, right) {
  if (!left.correctness || !right.correctness) return { comparable: false, reason: 'correctness-gate' };
  return { comparable: true };
}
