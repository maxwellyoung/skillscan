import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { SecurityScanner } from '../lib/scanner';
import type { GitHubFile, ScanResult } from '../lib/types';

const FIXTURE_DIR = path.join(process.cwd(), 'test/fixtures/malicious');

function toGitHubFile(name: string, content: string): GitHubFile {
  const base = path.basename(name);
  const scannerName = base.endsWith('.package.json') ? 'package.json' : base;

  return {
    name: scannerName,
    path: `test/fixtures/malicious/${name}`,
    content,
  };
}

function summarize(name: string, result: ScanResult) {
  return {
    fixture: name,
    score: result.score,
    grade: result.grade,
    riskLevel: result.riskLevel,
    severityCounts: result.severityCounts,
    topFindings: result.findings.slice(0, 3).map((finding) => ({
      severity: finding.severity,
      category: finding.category,
      title: finding.title,
    })),
  };
}

async function main() {
  const names = await listFixtureFiles(FIXTURE_DIR);

  const scanner = new SecurityScanner();
  const results = [];

  for (const name of names) {
    const content = await readFile(path.join(FIXTURE_DIR, name), 'utf8');
    const result = await scanner.scan([toGitHubFile(name, content)]);
    results.push(summarize(name, result));
  }

  const failed = results.filter((result) => result.riskLevel !== 'block');

  console.log(JSON.stringify({
    fixtures: results.length,
    expectedRiskLevel: 'block',
    passed: failed.length === 0,
    results,
  }, null, 2));

  if (failed.length > 0) {
    console.error(`Expected every malicious fixture to block. Missed: ${failed.map((r) => r.fixture).join(', ')}`);
    process.exit(1);
  }
}

async function listFixtureFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = await Promise.all(entries.map(async (entry) => {
    const entryPath = path.join(dir, entry.name);
    const relative = path.relative(FIXTURE_DIR, entryPath);
    if (entry.name.startsWith('.')) return [];
    if (entry.isDirectory()) return listFixtureFiles(entryPath);
    return [relative];
  }));

  return files.flat().sort();
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
