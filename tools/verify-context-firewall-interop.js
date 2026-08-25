#!/usr/bin/env node
import { readFile, readdir } from 'node:fs/promises';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { canonicalJson, sha256Bytes } from '../src/canonical.js';
import { validateValueReceipt } from '../src/value-receipt.js';
import { summarizeRunRecord } from '../src/value-summary.js';
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
const decisionValue = await import(pathToFileURL(resolve(decisionEvidencePath, 'src/context-firewall-value.js')));
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

const valueFixture = upstreamByName.get('normal/large-all-pass');
const { packet: valuePacket, valueReceipt: contextValueReceipt } = reducer.reduceWithValueReceipt(
  valueFixture.input,
  { mechanismRevision: generated[0].provenance.context_firewall_revision },
);
const valueValidation = validator.validateContextFirewallPacket(valuePacket, {
  packetBytes: reducer.serializePacket(valuePacket),
  sourceInput: valueFixture.input,
});
const decisionValueReceipt = decisionValue.createValidationValueReceipt(
  valuePacket,
  valueValidation,
  { mechanismRevision: generated[0].provenance.decision_evidence_revision },
);
const mechanism = (receipt) => ({
  configuration_id: receipt.operation.configuration_id,
  id: receipt.mechanism.id,
  name: receipt.mechanism.name,
  policy_id: receipt.operation.policy_id,
  revision: receipt.mechanism.revision,
  version: receipt.mechanism.version,
});
const valueRunRecord = {
  mechanisms: [mechanism(contextValueReceipt), mechanism(decisionValueReceipt)],
  protocol_version: 'opsle.agent-trajectory-profiler.run-record/v1',
  run: {
    id: contextValueReceipt.run.id,
    project: 'Opsle Prompt 005',
    repository: 'opsle/agent-trajectory-profiler',
    task_classification: 'conformance',
    work_classification: 'public-synthetic',
  },
  telemetry: {
    initial_model_visible_bytes: valuePacket.receipt.measurements.reduced_bytes,
    raw_evidence_bytes: valuePacket.receipt.measurements.original_bytes,
  },
  value_receipts: [contextValueReceipt, decisionValueReceipt],
};
const valueSummary = summarizeRunRecord(valueRunRecord);
const valueChain = {
  context_receipt_valid: validateValueReceipt(contextValueReceipt).valid,
  decision_receipt_valid: validateValueReceipt(decisionValueReceipt).valid,
  initial_model_visible_bytes: valuePacket.receipt.measurements.reduced_bytes,
  measurement_count: valueSummary.measurement_count,
  raw_bytes: valuePacket.receipt.measurements.original_bytes,
  receipt_count: valueSummary.receipt_count,
  safe_aggregate_count: valueSummary.aggregates?.length ?? 0,
  summary_identity: valueSummary.summary_identity,
  summary_valid: valueSummary.valid,
};
valueChain.pass = valueChain.context_receipt_valid
  && valueChain.decision_receipt_valid
  && valueChain.summary_valid
  && valueChain.receipt_count === 2;

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
  conformance: corpusExact && cases.every((item) => item.pass) && valueChain.pass ? 'PASS' : 'FAIL',
  fixture_count: generated.length,
  profiler_revision: execFileSync('git', ['rev-parse', 'HEAD'], { encoding: 'utf8' }).trim(),
  protocol_version: 'opsle.agent-trajectory-profiler.context-firewall-interop/v1',
  stored_corpus_exact: corpusExact,
  visible_value_chain: valueChain,
};
process.stdout.write(`${canonicalJson(report)}\n`);
process.exitCode = report.conformance === 'PASS' ? 0 : 1;
