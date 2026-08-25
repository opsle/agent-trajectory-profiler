import { readFile, readdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson, sha256Bytes } from './canonical.js';
import { compareTrajectories, profileTrajectory, validateTrajectory } from './context-evidence.js';

function parseJson(bytes, label) {
  try {
    return JSON.parse(bytes);
  } catch {
    throw new Error(`${label} must contain valid JSON`);
  }
}

async function readJson(path) {
  return parseJson(await readFile(path, 'utf8'), path);
}

function line(value) {
  return `${canonicalJson(value)}\n`;
}

export function humanSummary(profile) {
  if (!profile.measurements) {
    return `${profile.run_id ?? '(unknown run)'}: ${profile.measurement_status}; ${profile.violations.length} violation(s)\n`;
  }
  const value = profile.measurements;
  return [
    `${profile.run_id} [${profile.arm_id}/${profile.configuration_id}]`,
    `raw ${value.raw_available_bytes} bytes`,
    `initial ${value.initial_model_visible_bytes} bytes`,
    `escalated ${value.escalated_model_visible_bytes} bytes`,
    `final ${value.final_model_visible_bytes} bytes`,
    `requested ${value.escalation_requested_count}`,
    `fulfilled ${value.escalation_fulfilled_count}`,
  ].join(' | ') + '\n';
}

export async function conformanceReport(directory) {
  const names = (await readdir(directory)).filter((name) => name.endsWith('.json')).sort();
  const manifest = await readJson(resolve(dirname(directory), 'context-firewall-manifest.json'));
  const manifestByFile = new Map(manifest.fixtures.map((item) => [item.file, item]));
  const results = [];
  for (const name of names) {
    const bytes = await readFile(resolve(directory, name));
    const fixture = parseJson(bytes, resolve(directory, name));
    const profile = profileTrajectory(fixture.trajectory);
    const actual = {
      measurement_status: profile.measurement_status,
      measurements: profile.measurements,
      valid: profile.valid,
      violation_codes: profile.violations.map((item) => item.code).sort(),
    };
    const manifestEntry = manifestByFile.get(name);
    const pass = canonicalJson(actual) === canonicalJson(fixture.expected)
      && manifestEntry?.fixture === fixture.fixture
      && manifestEntry?.sha256 === sha256Bytes(bytes)
      && manifestEntry?.packet_identity === fixture.provenance.packet_identity
      && manifestEntry?.source_input_identity === fixture.provenance.source_input_identity;
    results.push({
      actual: profile.measurements == null ? null : {
        effective_reduction_bytes: profile.measurements.effective_reduction.bytes_avoided,
        escalated_bytes: profile.measurements.escalated_model_visible_bytes,
        escalation_state: profile.measurements.escalation_unavailable
          ? 'UNAVAILABLE'
          : profile.measurements.escalation_fulfilled
            ? 'FULFILLED'
            : profile.measurements.escalation_requested
              ? 'REQUESTED'
              : 'NOT_REQUESTED',
        final_visible_bytes: profile.measurements.final_model_visible_bytes,
        initial_reduction_bytes: profile.measurements.initial_reduction.bytes_avoided,
        initial_visible_bytes: profile.measurements.initial_model_visible_bytes,
        raw_bytes: profile.measurements.raw_available_bytes,
      },
      evidence_validation_state: fixture.provenance.evidence_validation_state,
      fixture: fixture.fixture,
      pass,
    });
  }
  return {
    conformance: results.every((item) => item.pass)
      && manifest.fixture_count === names.length
      && manifest.fixtures.length === names.length
      ? 'PASS' : 'FAIL',
    fixture_count: results.length,
    protocol_version: 'opsle.agent-trajectory-profiler.conformance/v1',
    results,
  };
}

export async function runCli(argv, io = process) {
  const [command, ...args] = argv;
  const summary = args.includes('--summary');
  const positional = args.filter((arg) => arg !== '--summary');
  try {
    if (command === 'profile' || command === 'validate') {
      if (positional.length !== 1) throw new Error(`${command} requires one trajectory file`);
      const input = await readJson(positional[0]);
      const trajectory = input.trajectory ?? input;
      const result = command === 'profile' ? profileTrajectory(trajectory) : validateTrajectory(trajectory);
      io.stdout.write(summary && command === 'profile' ? humanSummary(result) : line(result));
      return result.valid ? 0 : 1;
    }
    if (command === 'compare') {
      if (positional.length < 2) throw new Error('compare requires at least two trajectory files');
      const inputs = await Promise.all(positional.map(readJson));
      const result = compareTrajectories(inputs.map((input) => input.trajectory ?? input));
      io.stdout.write(line(result));
      return result.comparable ? 0 : 1;
    }
    if (command === 'conformance') {
      if (positional.length > 1) throw new Error('conformance accepts at most one fixture directory');
      const defaultDirectory = fileURLToPath(new URL('../fixtures/context-firewall/', import.meta.url));
      const result = await conformanceReport(positional[0] ?? defaultDirectory);
      if (summary) {
        for (const item of result.results) {
          const value = item.actual;
          io.stdout.write(value == null
            ? `${item.fixture} | ${item.evidence_validation_state} | ${item.pass ? 'PASS' : 'FAIL'}\n`
            : `${item.fixture} | raw ${value.raw_bytes} | initial ${value.initial_visible_bytes} | escalated ${value.escalated_bytes} | final ${value.final_visible_bytes} | ${item.pass ? 'PASS' : 'FAIL'}\n`);
        }
        io.stdout.write(`${result.conformance}: ${result.fixture_count} fixtures\n`);
      } else io.stdout.write(line(result));
      return result.conformance === 'PASS' ? 0 : 1;
    }
    throw new Error('usage: agent-trajectory-profiler <profile|validate|compare|conformance> ...');
  } catch (error) {
    io.stderr.write(line({ code: 'INVALID_INVOCATION', message: error.message }));
    return 2;
  }
}
