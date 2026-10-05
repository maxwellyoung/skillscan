import assert from 'node:assert/strict';
import { mkdir, mkdtemp, readdir, readFile, rm, writeFile, copyFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, describe, it } from 'node:test';
import { parseCliArgs, UsageError } from '../cli/args';
import { EXIT_ERROR, EXIT_FINDINGS, EXIT_OK, run } from '../cli/run';
import { SKILLSCAN_VERSION } from '../cli/version';
import { ruleIdFor } from '../lib/sarif';

const FIXTURES = path.join(process.cwd(), 'test/fixtures');

async function runCli(...argv: string[]) {
  let stdout = '';
  let stderr = '';
  const code = await run(argv, {
    stdout: text => { stdout += text; },
    stderr: text => { stderr += text; },
  });
  return { code, stdout, stderr };
}

// Same naming convention as scanner.eval.test.ts: fixtures carry a prefix so several
// package.json files can live side by side; the scanner keys on the real basename.
function scannerNameForFixture(name: string) {
  const base = path.basename(name);
  if (base.endsWith('.package.json')) return 'package.json';
  if (base.endsWith('.npm-metadata.json')) return 'npm-metadata.json';
  return base;
}

async function listFixtureFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const nested = await Promise.all(entries.map(async entry => {
    const entryPath = path.join(dir, entry.name);
    if (entry.isDirectory()) return listFixtureFiles(entryPath);
    return [entryPath];
  }));
  return nested.flat().sort();
}

let workDir: string;
let maliciousMcpServer: string;
let maliciousSkill: string;
let benignProject: string;
let reviewOnly: string;

before(async () => {
  workDir = await mkdtemp(path.join(tmpdir(), 'skillscan-cli-'));

  // An MCP-server-shaped repo assembled from the committed malicious fixtures.
  maliciousMcpServer = path.join(workDir, 'mcp-server');
  await mkdir(path.join(maliciousMcpServer, 'src'), { recursive: true });
  await mkdir(path.join(maliciousMcpServer, '.github/workflows'), { recursive: true });
  await mkdir(path.join(maliciousMcpServer, 'node_modules/ignored'), { recursive: true });
  await copyFile(path.join(FIXTURES, 'malicious/token-exfiltration.fixture'), path.join(maliciousMcpServer, 'src/index.js'));
  await copyFile(path.join(FIXTURES, 'malicious/npm/postinstall-exfil.package.json'), path.join(maliciousMcpServer, 'package.json'));
  await copyFile(
    path.join(FIXTURES, 'malicious/github-actions/pull-request-target-publish.workflow.yml'),
    path.join(maliciousMcpServer, '.github/workflows/release.yml'),
  );
  await writeFile(path.join(maliciousMcpServer, 'node_modules/ignored/index.js'), 'eval(process.env.SECRET)');

  maliciousSkill = path.join(workDir, 'skill');
  await mkdir(maliciousSkill);
  await copyFile(path.join(FIXTURES, 'malicious/hostile-skill.SKILL.md'), path.join(maliciousSkill, 'SKILL.md'));

  benignProject = path.join(workDir, 'benign');
  await mkdir(path.join(benignProject, '.github/workflows'), { recursive: true });
  await copyFile(path.join(FIXTURES, 'benign/npm/ordinary-library.package.json'), path.join(benignProject, 'package.json'));
  await copyFile(
    path.join(FIXTURES, 'benign/github-actions/pinned-readonly.workflow.yml'),
    path.join(benignProject, '.github/workflows/ci.yml'),
  );

  // High-severity behaviour without any critical finding: verdict "review", not "block".
  reviewOnly = path.join(workDir, 'review');
  await mkdir(reviewOnly);
  await writeFile(path.join(reviewOnly, 'runner.ts'), [
    "import { exec } from 'node:child_process';",
    "exec('git status');",
    'process.env.OPENAI_API_KEY;',
    'chmod +x ./tool.sh',
  ].join('\n'));
});

after(async () => {
  await rm(workDir, { recursive: true, force: true });
});

describe('CLI argument parsing', () => {
  it('defaults to text output and failing on critical findings', () => {
    assert.deepEqual(parseCliArgs(['./skill']), {
      kind: 'scan', target: './skill', format: 'text', failOn: 'critical', output: undefined, verbose: false,
    });
  });

  it('parses output formats, --fail-on, --output, and --verbose', () => {
    const json = parseCliArgs(['--json', 'pkg:npm/left-pad', '--fail-on', 'HIGH']);
    assert.equal(json.kind === 'scan' && json.format, 'json');
    assert.equal(json.kind === 'scan' && json.failOn, 'high');

    const sarif = parseCliArgs(['.', '--sarif', '-o', 'out.sarif', '--verbose', '--fail-on=none']);
    assert.deepEqual(sarif, { kind: 'scan', target: '.', format: 'sarif', failOn: 'none', output: 'out.sarif', verbose: true });
  });

  it('recognises help and version flags without a target', () => {
    assert.deepEqual(parseCliArgs(['--help']), { kind: 'help' });
    assert.deepEqual(parseCliArgs(['-h']), { kind: 'help' });
    assert.deepEqual(parseCliArgs(['-v']), { kind: 'version' });
  });

  it('rejects invalid usage', () => {
    assert.throws(() => parseCliArgs([]), UsageError);
    assert.throws(() => parseCliArgs(['a', 'b']), UsageError);
    assert.throws(() => parseCliArgs(['.', '--json', '--sarif']), UsageError);
    assert.throws(() => parseCliArgs(['.', '--fail-on', 'severe']), UsageError);
    assert.throws(() => parseCliArgs(['.', '--fail-on']), UsageError);
    assert.throws(() => parseCliArgs(['.', '--unknown']), UsageError);
  });

  it('reports the published package version', async () => {
    const pkg = JSON.parse(await readFile(path.join(process.cwd(), 'packages/cli/package.json'), 'utf8'));
    assert.equal(SKILLSCAN_VERSION, pkg.version);
    const { code, stdout } = await runCli('--version');
    assert.equal(code, EXIT_OK);
    assert.equal(stdout.trim(), pkg.version);
  });
});

describe('CLI exit codes', () => {
  it('exits 1 for every committed malicious fixture scanned as a single file', async () => {
    const fixtures = await listFixtureFiles(path.join(FIXTURES, 'malicious'));
    assert.ok(fixtures.length >= 4);

    for (const fixture of fixtures) {
      const dir = await mkdtemp(path.join(workDir, 'fixture-'));
      const target = path.join(dir, scannerNameForFixture(fixture));
      await copyFile(fixture, target);
      const { code, stdout } = await runCli(target);
      assert.equal(code, EXIT_FINDINGS, `${path.relative(FIXTURES, fixture)} should exit 1`);
      assert.match(stdout, /BLOCK INSTALL/);
    }
  });

  it('exits 1 for a malicious MCP server directory and scans .github/workflows but not node_modules', async () => {
    const { code, stdout } = await runCli(maliciousMcpServer, '--json');
    assert.equal(code, EXIT_FINDINGS);
    const result = JSON.parse(stdout);
    assert.equal(result.riskLevel, 'block');
    assert.equal(result.sourceType, 'local');
    const paths = new Set(result.findings.map((finding: { path: string }) => finding.path));
    assert.ok(paths.has('src/index.js'));
    assert.ok(paths.has('package.json'));
    assert.ok(paths.has('.github/workflows/release.yml'), 'workflow files under .github must be scanned');
    assert.ok(!Array.from(paths).some(p => String(p).includes('node_modules')));
  });

  it('exits 1 for a hostile skill folder', async () => {
    const { code } = await runCli(maliciousSkill);
    assert.equal(code, EXIT_FINDINGS);
  });

  it('exits 0 for benign projects', async () => {
    const { code, stdout } = await runCli(benignProject);
    assert.equal(code, EXIT_OK);
    assert.match(stdout, /Verdict: PASS/);
  });

  it('applies --fail-on thresholds', async () => {
    assert.equal((await runCli(maliciousMcpServer, '--fail-on', 'none')).code, EXIT_OK);
    assert.equal((await runCli(reviewOnly)).code, EXIT_OK, 'review verdict does not fail the default critical threshold');
    assert.equal((await runCli(reviewOnly, '--fail-on', 'high')).code, EXIT_FINDINGS);
    assert.equal((await runCli(benignProject, '--fail-on', 'info')).code, EXIT_OK);
  });

  it('exits 2 on usage and runtime errors', async () => {
    const missing = await runCli(path.join(workDir, 'does-not-exist'));
    assert.equal(missing.code, EXIT_ERROR);
    assert.match(missing.stderr, /Path not found/);

    const badUrl = await runCli('https://example.com/some/skill');
    assert.equal(badUrl.code, EXIT_ERROR);
    assert.match(badUrl.stderr, /Unsupported target/);

    const badFlag = await runCli('.', '--nope');
    assert.equal(badFlag.code, EXIT_ERROR);
    assert.match(badFlag.stderr, /Usage: skillscan/);

    const empty = await mkdtemp(path.join(workDir, 'empty-'));
    const emptyScan = await runCli(empty);
    assert.equal(emptyScan.code, EXIT_ERROR);
    assert.match(emptyScan.stderr, /No scannable files/);

    const unwritable = await runCli(maliciousSkill, '--sarif', '-o', path.join(workDir, 'missing-dir', 'out.sarif'));
    assert.equal(unwritable.code, EXIT_ERROR);
  });
});

describe('CLI SARIF output', () => {
  it('emits a SARIF 2.1.0 log with rules, results, and locations', async () => {
    const { code, stdout } = await runCli(maliciousMcpServer, '--sarif');
    assert.equal(code, EXIT_FINDINGS);
    const sarif = JSON.parse(stdout);

    assert.equal(sarif.version, '2.1.0');
    assert.match(sarif.$schema, /sarif-2\.1\.0/);
    assert.equal(sarif.runs.length, 1);

    const [runLog] = sarif.runs;
    const driver = runLog.tool.driver;
    assert.equal(driver.name, 'skillscan');
    assert.equal(driver.version, SKILLSCAN_VERSION);

    const ruleIds: string[] = driver.rules.map((rule: { id: string }) => rule.id);
    assert.equal(new Set(ruleIds).size, ruleIds.length, 'rule ids are unique');
    for (const rule of driver.rules) {
      assert.match(rule.id, /^skillscan\/[a-z0-9-]+$/);
      assert.ok(rule.shortDescription.text);
      assert.ok(['error', 'warning', 'note'].includes(rule.defaultConfiguration.level));
      assert.ok(Number.isFinite(Number(rule.properties['security-severity'])));
    }

    assert.ok(runLog.results.length > 0);
    for (const result of runLog.results) {
      assert.ok(ruleIds.includes(result.ruleId), `${result.ruleId} is declared`);
      assert.equal(ruleIds[result.ruleIndex], result.ruleId);
      assert.ok(['error', 'warning', 'note'].includes(result.level));
      assert.ok(result.message.text);
      const location = result.locations[0].physicalLocation;
      assert.ok(!path.isAbsolute(location.artifactLocation.uri), 'uri is relative to the scan root');
      assert.ok(!location.artifactLocation.uri.includes('\\'));
      if (location.region) assert.ok(location.region.startLine >= 1);
    }

    const critical = runLog.results.find((result: { properties: { severity: string } }) => result.properties.severity === 'critical');
    assert.equal(critical.level, 'error');
    const workflow = runLog.results.find((result: { locations: { physicalLocation: { artifactLocation: { uri: string } } }[] }) =>
      result.locations[0].physicalLocation.artifactLocation.uri === '.github/workflows/release.yml');
    assert.ok(workflow, 'workflow finding carries its full path');
    assert.equal(runLog.properties.riskLevel, 'block');
  });

  it('emits an empty but valid result set for clean projects', async () => {
    const { stdout } = await runCli(benignProject, '--sarif');
    const sarif = JSON.parse(stdout);
    assert.equal(sarif.version, '2.1.0');
    assert.deepEqual(sarif.runs[0].results, []);
    assert.deepEqual(sarif.runs[0].tool.driver.rules, []);
  });

  it('writes the report to --output and keeps the readable report on stdout', async () => {
    const outFile = path.join(workDir, 'out.sarif');
    const { code, stdout } = await runCli(maliciousSkill, '--sarif', '--output', outFile);
    assert.equal(code, EXIT_FINDINGS);
    assert.match(stdout, /BLOCK INSTALL/);
    assert.match(stdout, /Report written to/);
    const sarif = JSON.parse(await readFile(outFile, 'utf8'));
    assert.equal(sarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, 'SKILL.md');
  });

  it('derives stable rule ids from categories', () => {
    assert.equal(ruleIdFor('Secret Exfiltration Flow'), 'skillscan/secret-exfiltration-flow');
    assert.equal(ruleIdFor('GitHub Actions Pinning'), 'skillscan/github-actions-pinning');
    assert.equal(ruleIdFor('***'), 'skillscan/uncategorized');
  });
});
