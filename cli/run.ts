import { writeFile } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { loadLocalTarget } from '../lib/local';
import { toSarif } from '../lib/sarif';
import { SecurityScanner } from '../lib/scanner';
import { fetchRemoteTarget, isRemoteTarget, TargetError } from '../lib/targets';
import type { FetchBundle, Finding, ScanResult } from '../lib/types';
import { parseCliArgs, USAGE, UsageError, type FailOn } from './args';
import { SKILLSCAN_VERSION } from './version';

export const EXIT_OK = 0;
export const EXIT_FINDINGS = 1;
export const EXIT_ERROR = 2;

export interface CliIO {
  stdout: (text: string) => void;
  stderr: (text: string) => void;
  color?: boolean;
}

const SEVERITY_RANK: Record<Finding['severity'], number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const VERDICT: Record<ScanResult['riskLevel'], string> = {
  pass: 'PASS',
  review: 'MANUAL REVIEW',
  block: 'BLOCK INSTALL',
};

/** True when any finding is at or above the --fail-on severity. */
export function exceedsThreshold(result: ScanResult, failOn: FailOn): boolean {
  if (failOn === 'none') return false;
  const limit = SEVERITY_RANK[failOn];
  return result.findings.some(finding => SEVERITY_RANK[finding.severity] <= limit);
}

function paint(enabled: boolean, code: string, text: string): string {
  return enabled ? `\x1b[${code}m${text}\x1b[0m` : text;
}

const SEVERITY_COLOR: Record<Finding['severity'], string> = {
  critical: '1;31',
  high: '31',
  medium: '33',
  low: '36',
  info: '2',
};

const VERDICT_COLOR: Record<ScanResult['riskLevel'], string> = { pass: '1;32', review: '1;33', block: '1;31' };

function formatSummary(target: string, result: ScanResult, color = false): string {
  const counts = (['critical', 'high', 'medium', 'low', 'info'] as const)
    .map(severity => `${result.severityCounts[severity]} ${severity}`)
    .join(', ');
  return [
    `skillscan ${target}`,
    `Verdict: ${paint(color, VERDICT_COLOR[result.riskLevel], VERDICT[result.riskLevel])}  Score ${result.score}/100 (${result.grade})  ${result.scannedFiles} files, ${result.linesAnalyzed} lines, ${result.checksRun} checks`,
    `Findings: ${counts}`,
    result.summary,
  ].join('\n');
}

export function formatText(target: string, result: ScanResult, options: { verbose?: boolean; color?: boolean } = {}): string {
  const color = options.color ?? false;
  const shown = result.findings.filter(finding => options.verbose || finding.severity !== 'info');
  const hiddenInfo = result.findings.length - shown.length;
  const lines = [formatSummary(target, result, color), ''];

  for (const finding of shown) {
    const label = paint(color, SEVERITY_COLOR[finding.severity], finding.severity.toUpperCase().padEnd(8));
    lines.push(`${label}  ${finding.category}: ${finding.title}`);
    const location = finding.path ?? finding.file;
    if (location) lines.push(`          ${location}${finding.line ? `:${finding.line}` : ''}`);
    if (finding.snippet) lines.push(`          > ${finding.snippet.trim().slice(0, 160)}`);
    if (finding.remediation) lines.push(`          Fix: ${finding.remediation}`);
    lines.push('');
  }

  if (hiddenInfo > 0) {
    lines.push(`${hiddenInfo} informational ${hiddenInfo === 1 ? 'note' : 'notes'} hidden (use --verbose to list).`);
  }
  for (const warning of result.scanWarnings ?? []) {
    lines.push(`Warning: ${warning}`);
  }

  return lines.join('\n').trimEnd();
}

async function loadTarget(target: string): Promise<FetchBundle> {
  if (isRemoteTarget(target)) return fetchRemoteTarget(target);
  if (existsSync(target)) return loadLocalTarget(target);
  if (/^[a-z][a-z0-9+.-]*:/i.test(target) && !/^[a-z]:[\\/]/i.test(target)) {
    throw new UsageError(`Unsupported target "${target}". Supported URLs: GitHub, ClawdHub/Molthub, npm, OpenVSX.`);
  }
  throw new UsageError(`Path not found: ${target}`);
}

/** Run a scan of a target and return the merged result (no output, no exit code). */
export async function scanTarget(target: string): Promise<ScanResult> {
  const bundle = await loadTarget(target);
  if (bundle.files.length === 0) {
    throw new TargetError(`No scannable files found in ${target}`);
  }
  const result = await new SecurityScanner().scan(bundle.files);
  return {
    ...result,
    sourceType: bundle.sourceType,
    fetchedAt: bundle.fetchedAt,
    partial: bundle.partial,
    scanWarnings: bundle.warnings,
  };
}

/** CLI entry point. Returns the process exit code instead of exiting, so it is testable. */
export async function run(argv: string[], io: CliIO): Promise<number> {
  let command;
  try {
    command = parseCliArgs(argv);
  } catch (error) {
    io.stderr(`skillscan: ${(error as Error).message}\n\n${USAGE}\n`);
    return EXIT_ERROR;
  }

  if (command.kind === 'help') {
    io.stdout(`${USAGE}\n`);
    return EXIT_OK;
  }
  if (command.kind === 'version') {
    io.stdout(`${SKILLSCAN_VERSION}\n`);
    return EXIT_OK;
  }

  let result: ScanResult;
  try {
    result = await scanTarget(command.target);
  } catch (error) {
    const message = error instanceof UsageError || error instanceof TargetError
      ? error.message
      : `scan failed: ${error instanceof Error ? error.message : String(error)}`;
    io.stderr(`skillscan: ${message}\n`);
    return EXIT_ERROR;
  }

  const text = `${formatText(command.target, result, { verbose: command.verbose, color: io.color })}\n`;
  const report = command.format === 'sarif'
    ? `${JSON.stringify(toSarif(result, { toolVersion: SKILLSCAN_VERSION }), null, 2)}\n`
    : command.format === 'json'
      ? `${JSON.stringify(result, null, 2)}\n`
      : `${formatText(command.target, result, { verbose: command.verbose })}\n`;

  if (command.output) {
    try {
      await writeFile(command.output, report);
    } catch (error) {
      io.stderr(`skillscan: could not write ${command.output}: ${(error as Error).message}\n`);
      return EXIT_ERROR;
    }
    // The machine-readable report is in the file; the terminal gets the readable version.
    io.stdout(`${text}Report written to ${command.output}\n`);
  } else {
    io.stdout(command.format === 'text' ? text : report);
  }

  return exceedsThreshold(result, command.failOn) ? EXIT_FINDINGS : EXIT_OK;
}
