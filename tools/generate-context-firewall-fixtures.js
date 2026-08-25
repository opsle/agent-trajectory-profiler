#!/usr/bin/env node
import { mkdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { canonicalJson, sha256Bytes } from '../src/canonical.js';
import {
  EXPECTED_CONTEXT_FIREWALL_REVISION,
  EXPECTED_DECISION_EVIDENCE_REVISION,
  buildFixtureCorpus,
} from './context-firewall-fixture-corpus.js';

const args = process.argv.slice(2);
function option(name, fallback) {
  const index = args.indexOf(name);
  return index === -1 ? fallback : args[index + 1];
}

const contextFirewallPath = resolve(option('--context-firewall', '../context-firewall'));
const decisionEvidencePath = resolve(option('--decision-evidence', '../decision-evidence-protocol'));
const outputPath = resolve(option('--output', 'fixtures/context-firewall'));
const corpus = await buildFixtureCorpus({ contextFirewallPath, decisionEvidencePath });
await mkdir(outputPath, { recursive: true });
const manifestEntries = [];
for (const fixture of corpus) {
  const file = `${fixture.fixture}.json`;
  const bytes = Buffer.from(`${canonicalJson(fixture)}\n`, 'utf8');
  await writeFile(resolve(outputPath, file), bytes);
  manifestEntries.push({
    file,
    fixture: fixture.fixture,
    packet_identity: fixture.provenance.packet_identity,
    sha256: sha256Bytes(bytes),
    source_input_identity: fixture.provenance.source_input_identity,
  });
}
const manifest = {
  context_firewall_revision: EXPECTED_CONTEXT_FIREWALL_REVISION,
  decision_evidence_revision: EXPECTED_DECISION_EVIDENCE_REVISION,
  fixture_count: manifestEntries.length,
  fixtures: manifestEntries,
  protocol_version: 'opsle.agent-trajectory-profiler.fixture-manifest/v1',
};
await writeFile(
  resolve(outputPath, '../context-firewall-manifest.json'),
  `${canonicalJson(manifest)}\n`,
  'utf8',
);
process.stdout.write(`${canonicalJson({ fixture_count: corpus.length, output: outputPath, status: 'GENERATED' })}\n`);
