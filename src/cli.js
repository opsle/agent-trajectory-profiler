import { readFile, readdir } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalJson, sha256Bytes } from './canonical.js';
import { compareTrajectories, profileTrajectory, validateTrajectory } from './context-evidence.js';
import { validateRunRecord } from './run-record.js';
import {
  summarizeCumulativeValue,
  summarizeRunRecord,
  trajectoryOperatorIndicator,
  valueSummaryOperatorIndicator,
} from './value-summary.js';

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
  return trajectoryOperatorIndicator(profile);
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
  const quiet = args.includes('--quiet');
  const cumulative = args.includes('--cumulative');
  const knownFlags = new Set(['--summary', '--quiet', '--cumulative']);
  const positional = args.filter((arg) => !knownFlags.has(arg));
  try {
    if (command === 'profile' || command === 'validate') {
      if (positional.length !== 1) throw new Error(`${command} requires one trajectory file`);
      const input = await readJson(positional[0]);
      const trajectory = input.trajectory ?? input;
      const checked = validateTrajectory(trajectory);
      const result = command === 'profile'
        ? profileTrajectory(trajectory)
        : { valid: checked.valid, violations: checked.violations };
      io.stdout.write(line(result));
      if (!quiet) {
        io.stderr.write(command === 'profile'
          ? trajectoryOperatorIndicator(result)
          : `[Trajectory Profiler] ${trajectory.run?.run_id ?? 'unknown run'} | trajectory ${result.valid ? 'valid' : 'rejected'} | ${result.violations.length} violation(s)\n`);
      }
      return result.valid ? 0 : 1;
    }
    if (command === 'validate-record') {
      if (positional.length !== 1) throw new Error('validate-record requires one observational run-record file');
      const record = await readJson(positional[0]);
      const checked = validateRunRecord(record);
      const result = { valid: checked.valid, violations: checked.violations };
      io.stdout.write(line(result));
      if (!quiet) {
        io.stderr.write(`[Trajectory Profiler] ${record.run?.id ?? 'unknown run'} | observational record ${result.valid ? 'valid' : 'rejected'} | ${result.violations.length} violation(s)\n`);
      }
      return result.valid ? 0 : 1;
    }
    if (command === 'value-summary') {
      if (positional.length === 0) throw new Error('value-summary requires at least one observational run-record file');
      const records = await Promise.all(positional.map(readJson));
      const result = cumulative || records.length > 1
        ? summarizeCumulativeValue(records)
        : summarizeRunRecord(records[0]);
      io.stdout.write(line(result));
      if (!quiet) io.stderr.write(valueSummaryOperatorIndicator(result));
      return result.valid ? 0 : 1;
    }
    if (command === 'compare') {
      if (positional.length < 2) throw new Error('compare requires at least two trajectory files');
      const inputs = await Promise.all(positional.map(readJson));
      const result = compareTrajectories(inputs.map((input) => input.trajectory ?? input));
      io.stdout.write(line(result));
      if (!quiet) {
        io.stderr.write(`[Trajectory Profiler] ${result.profiles.length} trajectories compared | ${result.comparable ? 'comparable' : `not comparable: ${result.reason}`}\n`);
      }
      return result.comparable ? 0 : 1;
    }
    if (command === 'conformance') {
      if (positional.length > 1) throw new Error('conformance accepts at most one fixture directory');
      const defaultDirectory = fileURLToPath(new URL('../fixtures/context-firewall/', import.meta.url));
      const result = await conformanceReport(positional[0] ?? defaultDirectory);
      io.stdout.write(line(result));
      if (!quiet) io.stderr.write(`[Trajectory Profiler] ${result.fixture_count} fixtures checked | ${result.conformance}\n`);
      return result.conformance === 'PASS' ? 0 : 1;
    }
    throw new Error('usage: agent-trajectory-profiler <profile|validate|validate-record|value-summary|compare|conformance> ...');
  } catch (error) {
    io.stderr.write(line({ code: 'INVALID_INVOCATION', message: error.message }));
    return 2;
  }
}
