import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import {
  compareTrajectories,
  contextFirewallEventFromPacket,
  profileTrajectory,
  rawBaselineEvent,
  validateTrajectory,
} from '../src/context-evidence.js';
import { canonicalBytes, canonicalJson } from '../src/canonical.js';
import { conformanceReport } from '../src/cli.js';
import * as publicApi from '../src/index.js';

const fixtureDirectory = resolve('fixtures/context-firewall');

function load(name) {
  return JSON.parse(readFileSync(resolve(fixtureDirectory, `${name}.json`), 'utf8'));
}

function trajectory(name) {
  return structuredClone(load(name).trajectory);
}

function codes(result) {
  return result.violations.map((item) => item.code);
}

test('measurement output is byte-for-byte deterministic', () => {
  const input = trajectory('high-reduction-success');
  assert.equal(JSON.stringify(profileTrajectory(input)), JSON.stringify(profileTrajectory(input)));
});

test('public API exposes trajectory ingestion and measurement primitives', () => {
  for (const name of [
    'contextFirewallEventFromPacket',
    'rawBaselineEvent',
    'escalationEvent',
    'validateTrajectory',
    'profileTrajectory',
    'compareTrajectories',
    'canonicalMeasurement',
  ]) assert.equal(typeof publicApi[name], 'function');
});

test('canonical JSON rejects non-JSON and non-finite values', () => {
  assert.throws(() => canonicalJson({ value: undefined }), /plain JSON/);
  assert.throws(() => canonicalJson({ value: Number.POSITIVE_INFINITY }), /finite numbers/);
  assert.throws(() => canonicalJson({ value: 1n }), /plain JSON/);
  assert.throws(() => canonicalJson(new Date(0)), /plain JSON/);
});

test('high-reduction fixture has exact raw and reduced byte accounting', () => {
  const value = profileTrajectory(trajectory('high-reduction-success')).measurements;
  assert.equal(value.raw_available_bytes, 28_981);
  assert.equal(value.initial_model_visible_bytes, 1_846);
  assert.equal(value.final_model_visible_bytes, 1_846);
});

test('initial reduction uses exact byte units', () => {
  const value = profileTrajectory(trajectory('high-reduction-success')).measurements.initial_reduction;
  assert.equal(value.bytes_avoided, 27_135);
  assert.deepEqual(value.ratio, {
    denominator: 28_981,
    kind: 'FINITE',
    numerator: 27_135,
    value: 27_135 / 28_981,
  });
  assert.equal(value.percentage, (27_135 / 28_981) * 100);
});

test('retained, suppressed, and ambiguous evidence counts remain distinct', () => {
  const failure = profileTrajectory(trajectory('normal-failure')).measurements;
  const ambiguous = profileTrajectory(trajectory('needs-raw-evidence')).measurements;
  assert.equal(failure.retained_evidence_count, 4);
  assert.equal(failure.suppressed_evidence_count, 7);
  assert.equal(failure.ambiguous_evidence_count, 0);
  assert.equal(ambiguous.ambiguous_evidence_count, 2);
});

test('ambiguous evidence count cannot exceed original events', () => {
  const input = trajectory('high-reduction-success');
  input.events[0].suppression.ambiguous_evidence_count = 1_508;
  assert.ok(codes(validateTrajectory(input)).includes('AMBIGUOUS_COUNT_EXCEEDS_ORIGINAL'));
  input.events[0].suppression.ambiguous_evidence_count = 1_507;
  assert.equal(codes(validateTrajectory(input)).includes('AMBIGUOUS_COUNT_EXCEEDS_ORIGINAL'), false);
});

test('no-escalation reduction has equal initial and effective reduction', () => {
  const value = profileTrajectory(trajectory('high-reduction-success')).measurements;
  assert.equal(value.escalation_requested, false);
  assert.equal(value.escalated_model_visible_bytes, 0);
  assert.deepEqual(value.effective_reduction, value.initial_reduction);
});

test('NEEDS_RAW_EVIDENCE records reducer need and pending request', () => {
  const value = profileTrajectory(trajectory('needs-raw-evidence')).measurements;
  assert.equal(value.reducer_requires_escalation, true);
  assert.equal(value.escalation_requested, true);
  assert.equal(value.escalation_requested_count, 1);
  assert.equal(value.escalation_fulfilled_count, 0);
  assert.equal(value.escalated_model_visible_bytes, 0);
});

test('fulfilled escalation adds exact visible bytes and recomputes effective reduction', () => {
  const value = profileTrajectory(trajectory('escalation-fulfilled')).measurements;
  assert.equal(value.initial_model_visible_bytes, 2_130);
  assert.equal(value.escalated_model_visible_bytes, 16);
  assert.equal(value.final_model_visible_bytes, 2_146);
  assert.equal(value.initial_reduction.bytes_avoided, -2_094);
  assert.equal(value.effective_reduction.bytes_avoided, -2_110);
  assert.equal(value.escalation_fulfilled, true);
});

test('unavailable escalation consumes zero additional bytes', () => {
  const value = profileTrajectory(trajectory('escalation-unavailable')).measurements;
  assert.equal(value.escalation_requested_count, 1);
  assert.equal(value.escalation_unavailable_count, 1);
  assert.equal(value.escalation_fulfilled_count, 0);
  assert.equal(value.escalated_model_visible_bytes, 0);
  assert.equal(value.final_model_visible_bytes, value.initial_model_visible_bytes);
});

test('multiple escalations deduplicate repeated content identities', () => {
  const value = profileTrajectory(trajectory('multiple-escalations-deduplicated')).measurements;
  assert.equal(value.escalation_requested_count, 3);
  assert.equal(value.escalation_fulfilled_count, 3);
  assert.equal(value.escalated_event_bytes, 52);
  assert.equal(value.escalated_model_visible_bytes, 36);
  assert.equal(value.deduplicated_reexposure_bytes, 16);
  assert.equal(value.final_model_visible_bytes, 2_166);
});

test('tampered validation state is preserved and its measurements are unavailable', () => {
  const value = profileTrajectory(trajectory('tampered-invalid-receipt'));
  assert.equal(value.valid, false);
  assert.equal(value.measurement_status, 'UNAVAILABLE_UNTRUSTED_EVIDENCE');
  assert.equal(value.measurements, null);
  assert.deepEqual(codes(value), ['UNTRUSTED_EVIDENCE_MEASUREMENTS']);
});

test('source-backed and receipt-only validation states are distinguishable', () => {
  const backed = trajectory('normal-failure').events[0].validation;
  const receiptOnly = trajectory('validated-unverified-source').events[0].validation;
  assert.equal(backed.trust, 'SOURCE_BACKED_VERIFIED');
  assert.equal(backed.source_backed_verification_performed, true);
  assert.equal(receiptOnly.trust, 'STRUCTURALLY_VALID_UNVERIFIED_SOURCE');
  assert.equal(receiptOnly.source_backed_verification_performed, false);
  assert.equal(receiptOnly.evidence_packet_validated, true);
});

test('raw baseline represents zero suppression and zero reduction', () => {
  const value = profileTrajectory(trajectory('raw-baseline-zero-suppression')).measurements;
  assert.equal(value.raw_available_bytes, 104);
  assert.equal(value.initial_model_visible_bytes, 104);
  assert.equal(value.suppressed_evidence_count, 0);
  assert.equal(value.initial_reduction.bytes_avoided, 0);
  assert.equal(value.effective_reduction.bytes_avoided, 0);
});

test('exact payload boundary retains exact ceiling identity', () => {
  const input = trajectory('exact-payload-boundary');
  assert.equal(input.events[0].payload.ceiling_bytes, 1_846);
  assert.equal(input.events[0].initial_model_visible.bytes, 1_846);
  assert.equal(profileTrajectory(input).valid, true);
});

test('negative measurements are rejected', () => {
  const input = trajectory('high-reduction-success');
  input.events[0].raw_evidence.bytes = -1;
  const result = validateTrajectory(input);
  assert.equal(result.valid, false);
  assert.ok(codes(result).includes('INVALID_MEASUREMENT'));
});

test('unsafe integer measurements are rejected without overflow', () => {
  const input = trajectory('high-reduction-success');
  input.events[0].suppression.suppressed_categories.successful_test = Number.MAX_SAFE_INTEGER + 1;
  const result = validateTrajectory(input);
  assert.equal(result.valid, false);
  assert.ok(codes(result).includes('INVALID_MEASUREMENT'));
});

test('safe component values that overflow aggregate totals are flagged', () => {
  const input = trajectory('raw-baseline-zero-suppression');
  input.events[0].raw_evidence.bytes = Number.MAX_SAFE_INTEGER;
  input.events[0].initial_model_visible.bytes = Number.MAX_SAFE_INTEGER;
  input.events.push(rawBaselineEvent({
    armId: input.run.arm_id,
    configurationId: input.run.configuration_id,
    contentIdentity: 'sha256:second-overflow',
    evidenceCount: 0,
    eventId: 'overflow-second:evidence',
    operationId: 'op-overflow-second',
    rawBytes: 1,
  }));
  const result = validateTrajectory(input);
  assert.equal(result.valid, false);
  assert.ok(codes(result).includes('INTEGER_OVERFLOW'));
  assert.equal(profileTrajectory(input).measurements, null);
});

test('pure reduction cannot claim reduced bytes greater than raw bytes', () => {
  const input = trajectory('high-reduction-success');
  input.events[0].payload.semantics = 'PURE_REDUCTION';
  input.events[0].initial_model_visible.bytes = 30_000;
  const result = validateTrajectory(input);
  assert.ok(codes(result).includes('REDUCED_EXCEEDS_RAW'));
});

test('fulfilled escalation requires nonempty exposed evidence', () => {
  const input = trajectory('escalation-fulfilled');
  input.events[2].exposure = null;
  assert.ok(codes(validateTrajectory(input)).includes('FULFILLED_EXPOSURE_REQUIRED'));
  input.events[2].exposure = { bytes: 0, content_identity: 'sha256:empty' };
  assert.ok(codes(validateTrajectory(input)).includes('FULFILLED_EXPOSURE_EMPTY'));
});

test('subset escalation cannot exceed plausible raw source bytes', () => {
  const input = trajectory('escalation-fulfilled');
  input.events[2].exposure.bytes = 37;
  const result = validateTrajectory(input);
  assert.ok(codes(result).includes('ESCALATION_EXCEEDS_RAW_SOURCE'));
});

test('additional source changes only the effective raw denominator', () => {
  const input = trajectory('escalation-fulfilled');
  const terminal = input.events[2];
  terminal.source_relation = 'ADDITIONAL_SOURCE';
  terminal.reason = 'public deterministic auxiliary evidence';
  terminal.exposure.source_available_bytes = 100;
  terminal.exposure.source_identity = 'sha256:auxiliary-source';
  const value = profileTrajectory(input).measurements;
  assert.equal(value.initial_raw_available_bytes, 36);
  assert.equal(value.final_raw_available_bytes, 136);
  assert.equal(value.initial_reduction.bytes_avoided, -2_094);
  assert.equal(value.effective_reduction.bytes_avoided, -2_010);
});

test('contradictory declared final totals are rejected', () => {
  const input = trajectory('escalation-fulfilled');
  input.declared_totals = {
    escalated_model_visible_bytes: 16,
    final_model_visible_bytes: 1,
    initial_model_visible_bytes: 2_130,
    raw_available_bytes: 36,
  };
  assert.ok(codes(validateTrajectory(input)).includes('DECLARED_TOTAL_MISMATCH'));
});

test('unknown Context Firewall disposition is rejected', () => {
  const input = trajectory('normal-failure');
  input.events[0].disposition = 'MAYBE';
  assert.ok(codes(validateTrajectory(input)).includes('INVALID_DISPOSITION'));
});

test('duplicate event identities are rejected', () => {
  const input = trajectory('escalation-fulfilled');
  input.events[2].event_id = input.events[1].event_id;
  assert.ok(codes(validateTrajectory(input)).includes('DUPLICATE_EVENT_ID'));
});

test('contradictory arm and configuration identities are rejected', () => {
  const input = trajectory('normal-failure');
  input.events[0].arm_id = 'raw-baseline';
  input.events[0].configuration_id = 'other';
  const result = validateTrajectory(input);
  assert.ok(codes(result).includes('ARM_IDENTITY_MISMATCH'));
  assert.ok(codes(result).includes('CONFIGURATION_IDENTITY_MISMATCH'));
});

test('provider-recorded token measurements remain separate from byte metrics', () => {
  const input = trajectory('high-reduction-success');
  input.token_measurements = {
    escalated_tool_evidence_tokens: 5,
    final_tool_evidence_tokens: 105,
    initial_tool_evidence_tokens: 100,
    source: 'PROVIDER_RECORDED',
  };
  const result = profileTrajectory(input);
  assert.deepEqual(result.token_measurements, input.token_measurements);
  assert.equal(result.measurements.initial_model_visible_bytes, 1_846);
});

test('token counts cannot be inferred or contradict their components', () => {
  const input = trajectory('high-reduction-success');
  input.token_measurements = {
    escalated_tool_evidence_tokens: 5,
    final_tool_evidence_tokens: 100,
    initial_tool_evidence_tokens: 100,
    source: 'ESTIMATED',
  };
  const result = validateTrajectory(input);
  assert.ok(codes(result).includes('INVALID_TOKEN_MEASUREMENT_SOURCE'));
  assert.ok(codes(result).includes('TOKEN_COMPONENT_MISMATCH'));
});

test('comparison uses explicit arm identities for the same task', () => {
  const compared = compareTrajectories([
    trajectory('high-reduction-success'),
    trajectory('raw-baseline-large-all-pass'),
  ]);
  assert.equal(compared.comparable, true);
  assert.equal(compared.reason, null);
  assert.deepEqual(compared.profiles.map((item) => item.arm_id), ['raw-baseline', 'reduced-firewalled']);
});

test('comparison rejects different task identities', () => {
  const compared = compareTrajectories([
    trajectory('high-reduction-success'),
    trajectory('raw-baseline-zero-suppression'),
  ]);
  assert.equal(compared.comparable, false);
  assert.equal(compared.reason, 'task-identity-mismatch');
});

test('identical bytes from distinct operations are counted independently', () => {
  const input = trajectory('raw-baseline-zero-suppression');
  const first = input.events[0];
  input.events.push(rawBaselineEvent({
    armId: input.run.arm_id,
    configurationId: input.run.configuration_id,
    contentIdentity: first.raw_evidence.content_identity,
    evidenceCount: first.suppression.original_evidence_count,
    eventId: 'second-operation:evidence',
    operationId: 'op-second',
    rawBytes: first.raw_evidence.bytes,
  }));
  const value = profileTrajectory(input).measurements;
  assert.equal(value.raw_available_bytes, 208);
  assert.equal(value.initial_model_visible_bytes, 208);
});

function mockPacketAndValidation() {
  const packet = {
    decision_evidence: { disposition: 'SUFFICIENT', reason_codes: [], unclassified_evidence: [] },
    operation_id: 'op-mock',
    protocol_version: 'opsle.context-firewall.evidence-packet/v1',
    receipt: {
      configuration: { identity: 'sha256:configuration', policy_revision: 'tap-subset-policy/v1' },
      input_hash: 'sha256:input',
      measurements: {
        original_bytes: 10,
        original_event_count: 1,
        reduced_bytes: 10,
        retained_evidence_count: 0,
        suppressed_evidence_count: 1,
      },
      payload_limit: { affected: false, requested_bytes: null },
      raw_evidence: { escalation_required: false, reference: 'artifact://raw' },
      reducer: { name: '@opsle/context-firewall/test-output', version: '0.2.0' },
      source: { id: 'public', run_id: 'run' },
      suppressed: { categories: { structure: 1 } },
    },
  };
  const validation = {
    classification: 'VALID_WITH_UNVERIFIED_SOURCE',
    cryptographic_verification: 'PARTIAL',
    evidence_sufficient: true,
    internally_consistent: true,
    protocol_version: packet.protocol_version,
    structural_valid: true,
    sufficiency: 'SUFFICIENT',
    valid: true,
    verification: {
      configuration_identity: 'VERIFIED',
      packet_serialization: 'VERIFIED',
      reduced_bytes: 'VERIFIED',
      semantic_payload_hash: 'VERIFIED',
    },
    violations: [],
  };
  return { packet, validation };
}

test('adapter binds packet identity to canonical packet bytes', () => {
  const { packet, validation } = mockPacketAndValidation();
  assert.throws(() => contextFirewallEventFromPacket({
    armId: 'arm',
    configurationId: 'config',
    eventId: 'event',
    packet,
    packetBytes: Buffer.alloc(canonicalBytes(packet).length, 1),
    validation,
  }), /canonical packet-v1/);
});

test('adapter rejects forged incoherent valid validation state', () => {
  const { packet, validation } = mockPacketAndValidation();
  validation.structural_valid = false;
  assert.throws(() => contextFirewallEventFromPacket({
    armId: 'arm',
    configurationId: 'config',
    eventId: 'event',
    packet,
    packetBytes: canonicalBytes(packet),
    validation,
  }), /internally incoherent/);
});

test('direct trajectory ingestion rejects contradictory normalized trust state', () => {
  const input = trajectory('normal-failure');
  input.events[0].validation.classification = 'CRYPTOGRAPHIC_MISMATCH';
  assert.ok(codes(validateTrajectory(input)).includes('INCOHERENT_VALIDATION_STATE'));
});

test('all valid normalized validation fields must remain coherent', () => {
  const mutations = [
    (validation) => { validation.classification = 'VALID_WITH_UNVERIFIED_SOURCE'; },
    (validation) => { validation.source_backed_verification_performed = false; },
    (validation) => { validation.cryptographic_verification = 'MISMATCH'; },
    (validation) => { validation.sufficiency = 'INVALID'; },
  ];
  for (const mutate of mutations) {
    const input = trajectory('normal-failure');
    mutate(input.events[0].validation);
    assert.ok(codes(validateTrajectory(input)).includes('INCOHERENT_VALIDATION_STATE'));
  }
});

test('payload and locator flags require booleans', () => {
  const input = trajectory('normal-failure');
  input.events[0].payload.affected_by_ceiling = 'false';
  input.events[0].raw_evidence.locator_present = 'true';
  const result = validateTrajectory(input);
  assert.equal(codes(result).filter((code) => code === 'BOOLEAN_REQUIRED').length, 2);
});

test('malformed top-level input is rejected', () => {
  assert.deepEqual(validateTrajectory(null), {
    valid: false,
    violations: [{ code: 'OBJECT_REQUIRED', message: 'trajectory object required', path: '/' }],
  });
});

test('all content-addressed fixtures match exact expected measurements', async () => {
  const report = await conformanceReport(fixtureDirectory);
  assert.equal(report.conformance, 'PASS');
  assert.equal(report.fixture_count, 14);
  assert.equal(report.results.every((item) => item.pass), true);
});

test('CLI profile output is canonical and deterministic', () => {
  const path = resolve(fixtureDirectory, 'escalation-fulfilled.json');
  const args = ['bin/agent-trajectory-profiler.js', 'profile', path];
  const first = spawnSync(process.execPath, args, { encoding: 'utf8' });
  const second = spawnSync(process.execPath, args, { encoding: 'utf8' });
  assert.equal(first.status, 0, first.stderr);
  assert.equal(first.stdout, second.stdout);
  assert.equal(first.stdout.endsWith('\n'), true);
});
