import { parseArgs } from 'node:util';
import type { Finding } from '../lib/types';

export type OutputFormat = 'text' | 'json' | 'sarif';
export type FailOn = Finding['severity'] | 'none';

export const FAIL_ON_VALUES: readonly FailOn[] = ['critical', 'high', 'medium', 'low', 'info', 'none'];

export type CliCommand =
  | { kind: 'help' }
  | { kind: 'version' }
  | {
      kind: 'scan';
      target: string;
      format: OutputFormat;
      failOn: FailOn;
      output?: string;
      verbose: boolean;
    };

export class UsageError extends Error {}

export const USAGE = `Usage: skillscan <path-or-url> [options]

Static security scan for Claude Code skills, MCP servers, npm packages,
VS Code extensions, and GitHub Actions workflows. No AI, no uploads of local files.

Targets:
  ./path/to/dir                  Local skill folder, MCP server repo, or extension folder
  ./path/to/file                 A single local file (scanned whatever its extension)
  https://github.com/owner/repo  GitHub repository, tree, or blob URL
  https://clawdhub.ai/skills/... ClawdHub / Molthub skill URL (resolved to GitHub)
  pkg:npm/name@1.2.3             npm package (also npm:name or npmjs.com URL)
  https://open-vsx.org/extension/publisher/name
                                 OpenVSX extension

Options:
  --json                Print the full scan result as JSON
  --sarif               Print a SARIF 2.1.0 log (for GitHub code scanning)
  -o, --output <file>   Write the report (text, --json, or --sarif) to <file>;
                        the human-readable report still goes to stdout
  --fail-on <severity>  Exit 1 when any finding is at or above this severity:
                        critical (default, same as "block install"), high,
                        medium, low, info, or none (never fail on findings)
  --verbose             Also list informational findings in text output
  -h, --help            Show this help
  -v, --version         Show the version

Exit codes:
  0  No finding at or above --fail-on
  1  At least one finding at or above --fail-on (default: install blocked)
  2  Usage error or the scan could not run`;

export function parseCliArgs(argv: string[]): CliCommand {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      strict: true,
      options: {
        json: { type: 'boolean' },
        sarif: { type: 'boolean' },
        output: { type: 'string', short: 'o' },
        'fail-on': { type: 'string' },
        verbose: { type: 'boolean' },
        help: { type: 'boolean', short: 'h' },
        version: { type: 'boolean', short: 'v' },
      },
    });
  } catch (error) {
    throw new UsageError(error instanceof Error ? error.message : String(error));
  }

  const { values, positionals } = parsed;

  if (values.help) return { kind: 'help' };
  if (values.version) return { kind: 'version' };

  if (values.json && values.sarif) {
    throw new UsageError('--json and --sarif cannot be used together');
  }

  if (positionals.length === 0) {
    throw new UsageError('Missing target: pass a local path or a supported URL');
  }
  if (positionals.length > 1) {
    throw new UsageError(`Expected one target, got ${positionals.length}: ${positionals.join(' ')}`);
  }

  const failOn = (values['fail-on'] ?? 'critical').toLowerCase();
  if (!(FAIL_ON_VALUES as readonly string[]).includes(failOn)) {
    throw new UsageError(`Invalid --fail-on value "${values['fail-on']}". Use one of: ${FAIL_ON_VALUES.join(', ')}`);
  }

  if (values.output === '') {
    throw new UsageError('--output requires a file path');
  }

  return {
    kind: 'scan',
    target: positionals[0],
    format: values.sarif ? 'sarif' : values.json ? 'json' : 'text',
    failOn: failOn as FailOn,
    output: values.output,
    verbose: values.verbose ?? false,
  };
}
