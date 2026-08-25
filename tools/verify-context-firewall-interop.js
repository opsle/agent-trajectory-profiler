#!/usr/bin/env node
import { readFile, readdir } from 'node:fs/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { canonicalJson, sha256Bytes } from '../src/canonical.js';
import { buildFixtureCorpus } from './context-firewall-fixture-corpus.js';

const contextFirewallPath = resolve(process.env.CONTEXT_FIREWALL_PATH ?? '../context-firewall');
const decisionEvidencePath = resolve(process.env.DECISION_EVIDENCE_PATH ?? '../decision-evidence-protocol');
const fixturePath = resolve('fixtures/context-firewall');
const generated = await buildFixtureCorpus({ contextFirewallPath, decisionEvidencePath });
const stored = await Promise.all(
  (await readdir(fixturePath)).filter((name) => name.endsWith('.json')).sort()
    .map(async (name) => JSON.parse(await readFile(resolve(fixturePath, name), 'utf8'))),
);
const storedByName = new Map(stored.map((item) => [item.fixture, item]));
const corpusExact = canonicalJson(generated) === canonicalJson(stored);

const reducer = await import(pathToFileURL(resolve(contextFirewallPath, 'src/reducer.js')));
const producerFixtures = await import(pathToFileURL(resolve(contextFirewallPath, 'fixtures/corpus.js')));
const validator = await import(pathToFileURL(resolve(decisionEvidencePath, 'src/context-firewall-v1.js')));
const upstreamByName = new Map(producerFixtures.corpus.map((item) => [item.name, item]));

function upstream(name, { tamperReceipt = false } = {}) {
  const fixture = upstreamByName.get(name);
  const executed = producerFixtures.executeFixture(fixture);
  if (!executed.pass || !executed.packet) throw new Error(`upstream fixture failed: ${name}`);
  const packet = structuredClone(executed.packet);
  if (tamperReceipt) packet.receipt.semantic_payload_hash = `sha256:${'0'.repeat(64)}`;
  const packetBytes = reducer.serializePacket(packet);
  const validation = validator.validateContextFirewallPacket(packet, {
    packetBytes,
    sourceInput: fixture.input,
  });
  return { packet, packetBytes, validation };
}

function packetAssertions(storedName, upstreamName) {
  const item = storedByName.get(storedName);
  const value = upstream(upstreamName);
  const event = item.trajectory.events[0];
  const measurements = value.packet.receipt.measurements;
  return event.raw_evidence.bytes === measurements.original_bytes
    && event.initial_model_visible.bytes === measurements.reduced_bytes
    && event.initial_model_visible.bytes === value.packetBytes.length
    && event.initial_model_visible.content_identity === sha256Bytes(value.packetBytes)
    && event.suppression.retained_evidence_count === measurements.retained_evidence_count
    && event.suppression.suppressed_evidence_count === measurements.suppressed_evidence_count
    && event.disposition === value.packet.decision_evidence.disposition
    && event.validation.valid === value.validation.valid;
}

const high = storedByName.get('high-reduction-success');
const normalFailure = storedByName.get('normal-failure');
const needsRaw = storedByName.get('needs-raw-evidence');
const fulfilled = storedByName.get('escalation-fulfilled');
const tampered = storedByName.get('tampered-invalid-receipt');

const fulfilledExposures = fulfilled.trajectory.events
  .filter((event) => event.type === 'raw_evidence_escalation' && event.status === 'FULFILLED');
const uniqueFulfilledBytes = [...new Map(fulfilledExposures.map((event) => [
  `${event.operation_id}\0${event.exposure.content_identity}`,
  event.exposure.bytes,
])).values()].reduce((sum, bytes) => sum + bytes, 0);
const tamperedUpstream = upstream('normal/small-all-pass', { tamperReceipt: true });

const independent = {
  'high-reduction-success': packetAssertions('high-reduction-success', 'normal/large-all-pass')
    && high.expected.measurements.effective_reduction.bytes_avoided
      === high.expected.measurements.initial_reduction.bytes_avoided,
  'normal-failure': packetAssertions('normal-failure', 'failure/one')
    && normalFailure.trajectory.events[0].suppression.retained_evidence_count === 4,
  'needs-raw-evidence': packetAssertions('needs-raw-evidence', 'edge/malformed-output')
    && needsRaw.trajectory.events[0].reduction_requires_escalation === true
    && needsRaw.expected.measurements.escalation_requested_count === 1,
  'escalation-fulfilled': packetAssertions('escalation-fulfilled', 'edge/malformed-output')
    && fulfilled.expected.measurements.escalated_model_visible_bytes === uniqueFulfilledBytes
    && fulfilled.expected.measurements.final_model_visible_bytes
      === fulfilled.trajectory.events[0].initial_model_visible.bytes + uniqueFulfilledBytes,
  'tampered-invalid-receipt': tamperedUpstream.validation.valid === false
    && tampered.trajectory.events[0].validation.trust === 'INVALID_OR_TAMPERED'
    && tampered.expected.measurements === null,
};

const cases = Object.entries(independent).map(([fixture, independentlyVerified]) => ({
  fixture,
  independent_arithmetic: independentlyVerified ? 'PASS' : 'FAIL',
  pass: corpusExact && independentlyVerified,
}));
const report = {
  cases,
  conformance: corpusExact && cases.every((item) => item.pass) ? 'PASS' : 'FAIL',
  fixture_count: generated.length,
  protocol_version: 'opsle.agent-trajectory-profiler.context-firewall-interop/v1',
  stored_corpus_exact: corpusExact,
};
process.stdout.write(`${canonicalJson(report)}\n`);
process.exitCode = report.conformance === 'PASS' ? 0 : 1;
