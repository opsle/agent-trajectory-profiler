import { execFileSync } from 'node:child_process';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { canonicalBytes, canonicalJson, sha256Bytes } from '../src/canonical.js';
import {
  TRAJECTORY_PROTOCOL,
  contextFirewallEventFromPacket,
  escalationEvent,
  profileTrajectory,
  rawBaselineEvent,
} from '../src/context-evidence.js';

export const EXPECTED_CONTEXT_FIREWALL_REVISION = 'dd34bd9f681314761f1ca87f339648bf611811f3';
export const EXPECTED_DECISION_EVIDENCE_REVISION = 'cc220abfa27a0bd20d80c481da09f6fe532bdabc';

function revision(path) {
  return execFileSync('git', ['-C', path, 'rev-parse', 'HEAD'], { encoding: 'utf8' }).trim();
}

function content(bytes) {
  return { bytes: Buffer.byteLength(bytes, 'utf8'), content_identity: sha256Bytes(Buffer.from(bytes, 'utf8')) };
}

function trajectory({ id, taskId, armId, configurationId, evidenceEvent, escalations = [] }) {
  return {
    events: [evidenceEvent, ...escalations],
    protocol_version: TRAJECTORY_PROTOCOL,
    run: { arm_id: armId, configuration_id: configurationId, run_id: id, task_id: taskId },
  };
}

function expected(profile) {
  return {
    measurement_status: profile.measurement_status,
    measurements: profile.measurements,
    valid: profile.valid,
    violation_codes: profile.violations.map((item) => item.code).sort(),
  };
}

export async function buildFixtureCorpus({ contextFirewallPath, decisionEvidencePath }) {
  const cfRevision = revision(contextFirewallPath);
  const depRevision = revision(decisionEvidencePath);
  if (cfRevision !== EXPECTED_CONTEXT_FIREWALL_REVISION) {
    throw new Error(`Context Firewall revision mismatch: ${cfRevision}`);
  }
  if (depRevision !== EXPECTED_DECISION_EVIDENCE_REVISION) {
    throw new Error(`Decision Evidence revision mismatch: ${depRevision}`);
  }
  const reducer = await import(pathToFileURL(resolve(contextFirewallPath, 'src/reducer.js')));
  const fixtures = await import(pathToFileURL(resolve(contextFirewallPath, 'fixtures/corpus.js')));
  const validator = await import(pathToFileURL(resolve(decisionEvidencePath, 'src/context-firewall-v1.js')));
  const byName = new Map(fixtures.corpus.map((item) => [item.name, item]));

  function upstream(name, { receiptOnly = false, tamperPacket = false, tamperSource = false } = {}) {
    const fixture = byName.get(name);
    if (!fixture) throw new Error(`missing Context Firewall fixture ${name}`);
    const result = fixtures.executeFixture(fixture);
    if (!result.pass || !result.packet) throw new Error(`upstream fixture failed: ${name}`);
    const packet = structuredClone(result.packet);
    if (tamperPacket) packet.receipt.semantic_payload_hash = `sha256:${'0'.repeat(64)}`;
    const packetBytes = reducer.serializePacket(packet);
    const sourceInput = structuredClone(fixture.input);
    if (tamperSource) sourceInput.streams[0].data += 'WARNING: deterministic tamper\n';
    const validation = validator.validateContextFirewallPacket(
      packet,
      receiptOnly ? { packetBytes } : { packetBytes, sourceInput },
    );
    return { fixture, packet, packetBytes, validation };
  }

  function firewallFixture({
    id,
    source,
    armId = 'reduced-firewalled',
    configurationId = 'packet-v1/default',
    escalations = [],
    receiptOnly = false,
    tamperPacket = false,
    tamperSource = false,
  }) {
    const value = upstream(source, { receiptOnly, tamperPacket, tamperSource });
    const event = contextFirewallEventFromPacket({
      armId,
      configurationId,
      eventId: `${id}:reduction`,
      packet: value.packet,
      packetBytes: value.packetBytes,
      validation: value.validation,
    });
    const record = trajectory({
      armId,
      configurationId,
      escalations,
      evidenceEvent: event,
      id,
      taskId: `public:${source}`,
    });
    const profile = profileTrajectory(record);
    return {
      expected: expected(profile),
      fixture: id,
      protocol_version: 'opsle.agent-trajectory-profiler.fixture/v1',
      provenance: {
        context_firewall_revision: cfRevision,
        decision_evidence_revision: depRevision,
        evidence_validation_state: event.validation.trust,
        fixture_source_identity: `context-firewall:${source}`,
        packet_identity: event.initial_model_visible.content_identity,
        source_input_identity: sha256Bytes(Buffer.from(canonicalJson(value.fixture.input), 'utf8')),
        source_stream_identity: value.packet.receipt.input_hash,
      },
      trajectory: record,
    };
  }

  const needsRawSource = upstream('edge/malformed-output');
  const needsRawBase = {
    armId: 'reduced-with-escalation',
    configurationId: 'packet-v1/default',
    operationId: needsRawSource.packet.operation_id,
  };
  const request = (id, reason = 'UNCLASSIFIED_EVIDENCE') => escalationEvent({
    escalationId: id,
    eventId: `${id}:requested`,
    operationId: needsRawBase.operationId,
    reasonCategory: reason,
    status: 'REQUESTED',
  });
  const fulfilled = (id, bytes, relation = 'SUBSET_OF_RAW') => escalationEvent({
    escalationId: id,
    eventId: `${id}:fulfilled`,
    exposure: content(bytes),
    operationId: needsRawBase.operationId,
    reason: relation === 'ADDITIONAL_SOURCE' ? 'public deterministic auxiliary evidence' : null,
    reasonCategory: 'UNCLASSIFIED_EVIDENCE',
    sourceRelation: relation,
    status: 'FULFILLED',
  });

  const output = [
    firewallFixture({ id: 'high-reduction-success', source: 'normal/large-all-pass' }),
    firewallFixture({ id: 'normal-failure', source: 'failure/one' }),
    firewallFixture({ id: 'multiple-failure-regions', source: 'failure/several' }),
    firewallFixture({ id: 'heavy-suppression', source: 'normal/repetitive-success' }),
    firewallFixture({
      ...needsRawBase,
      id: 'needs-raw-evidence',
      source: 'edge/malformed-output',
      escalations: [request('needs-raw-1')],
    }),
    firewallFixture({
      ...needsRawBase,
      id: 'escalation-fulfilled',
      source: 'edge/malformed-output',
      escalations: [request('fulfilled-1'), fulfilled('fulfilled-1', 'this is not TAP\n')],
    }),
    firewallFixture({
      ...needsRawBase,
      id: 'escalation-unavailable',
      source: 'provenance/raw-reference-absent',
      escalations: [
        escalationEvent({
          escalationId: 'unavailable-1',
          eventId: 'unavailable-1:requested',
          operationId: needsRawBase.operationId,
          reasonCategory: 'RAW_EVIDENCE_REFERENCE_MISSING',
          status: 'REQUESTED',
        }),
        escalationEvent({
          escalationId: 'unavailable-1',
          eventId: 'unavailable-1:terminal',
          operationId: needsRawBase.operationId,
          reasonCategory: 'RAW_EVIDENCE_REFERENCE_MISSING',
          status: 'UNAVAILABLE',
        }),
      ],
    }),
    firewallFixture({
      ...needsRawBase,
      id: 'multiple-escalations-deduplicated',
      source: 'edge/malformed-output',
      escalations: [
        request('multi-1'),
        fulfilled('multi-1', 'this is not TAP\n'),
        request('multi-2'),
        fulfilled('multi-2', 'not okay maybe FAIL\n'),
        request('multi-3'),
        fulfilled('multi-3', 'this is not TAP\n'),
      ],
    }),
    firewallFixture({ id: 'tampered-invalid-receipt', source: 'normal/small-all-pass', tamperPacket: true }),
    firewallFixture({ id: 'tampered-source-evidence', source: 'normal/small-all-pass', tamperSource: true }),
    firewallFixture({ id: 'validated-unverified-source', source: 'normal/small-all-pass', receiptOnly: true }),
    firewallFixture({ id: 'exact-payload-boundary', source: 'payload/exact-boundary', configurationId: 'packet-v1/exact-boundary' }),
  ];

  const baselineSource = upstream('normal/small-all-pass');
  const rawBytes = baselineSource.packet.receipt.measurements.original_bytes;
  const baselineEvent = rawBaselineEvent({
    armId: 'raw-baseline',
    configurationId: 'raw/v1',
    contentIdentity: baselineSource.packet.receipt.input_hash,
    evidenceCount: baselineSource.packet.receipt.measurements.original_event_count,
    eventId: 'raw-baseline-zero-suppression:evidence',
    operationId: baselineSource.packet.operation_id,
    rawBytes,
  });
  const baselineTrajectory = trajectory({
    armId: 'raw-baseline',
    configurationId: 'raw/v1',
    evidenceEvent: baselineEvent,
    id: 'raw-baseline-zero-suppression',
    taskId: 'public:normal/small-all-pass',
  });
  output.push({
    expected: expected(profileTrajectory(baselineTrajectory)),
    fixture: 'raw-baseline-zero-suppression',
    protocol_version: 'opsle.agent-trajectory-profiler.fixture/v1',
    provenance: {
      context_firewall_revision: cfRevision,
      decision_evidence_revision: depRevision,
      evidence_validation_state: 'NOT_APPLICABLE_RAW_BASELINE',
      fixture_source_identity: 'context-firewall:normal/small-all-pass',
      packet_identity: null,
      source_input_identity: sha256Bytes(Buffer.from(canonicalJson(baselineSource.fixture.input), 'utf8')),
      source_stream_identity: baselineSource.packet.receipt.input_hash,
    },
    trajectory: baselineTrajectory,
  });
  const largeBaselineSource = upstream('normal/large-all-pass');
  const largeRawBytes = largeBaselineSource.packet.receipt.measurements.original_bytes;
  const largeBaselineEvent = rawBaselineEvent({
    armId: 'raw-baseline',
    configurationId: 'raw/v1',
    contentIdentity: largeBaselineSource.packet.receipt.input_hash,
    evidenceCount: largeBaselineSource.packet.receipt.measurements.original_event_count,
    eventId: 'raw-baseline-large-all-pass:evidence',
    operationId: largeBaselineSource.packet.operation_id,
    rawBytes: largeRawBytes,
  });
  const largeBaselineTrajectory = trajectory({
    armId: 'raw-baseline',
    configurationId: 'raw/v1',
    evidenceEvent: largeBaselineEvent,
    id: 'raw-baseline-large-all-pass',
    taskId: 'public:normal/large-all-pass',
  });
  output.push({
    expected: expected(profileTrajectory(largeBaselineTrajectory)),
    fixture: 'raw-baseline-large-all-pass',
    protocol_version: 'opsle.agent-trajectory-profiler.fixture/v1',
    provenance: {
      context_firewall_revision: cfRevision,
      decision_evidence_revision: depRevision,
      evidence_validation_state: 'NOT_APPLICABLE_RAW_BASELINE',
      fixture_source_identity: 'context-firewall:normal/large-all-pass',
      packet_identity: null,
      source_input_identity: sha256Bytes(Buffer.from(canonicalJson(largeBaselineSource.fixture.input), 'utf8')),
      source_stream_identity: largeBaselineSource.packet.receipt.input_hash,
    },
    trajectory: largeBaselineTrajectory,
  });
  return output.sort((left, right) => (
    left.fixture < right.fixture ? -1 : left.fixture > right.fixture ? 1 : 0
  ));
}
