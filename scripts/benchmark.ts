import { createHash } from 'node:crypto';
import { readdir, readFile, writeFile } from 'node:fs/promises';
import { basename } from 'node:path';
import { SecurityScanner } from '../lib/scanner';
import { SCANNER_VERSION } from '../lib/version';
import type { ScanResult } from '../lib/types';

const evaluatedAt = '2026-05-21T12:00:00.000Z';
const reportPath = 'app/benchmark/report.json';
const fixtures = { benign: 'pass', review: 'review', malicious: 'block' } as const;
type Verdict = ScanResult['riskLevel'];

async function listFiles(dir: string): Promise<string[]> {
  const entries = await readdir(dir, { withFileTypes: true });
  const paths = await Promise.all(entries.filter(entry => !entry.name.startsWith('.')).map(entry => {
    const file = dir + '/' + entry.name;
    return entry.isDirectory() ? listFiles(file) : [file];
  }));
  return paths.flat().sort();
}

async function main() {
  const corpus = createHash('sha256');
  const scannerHash = createHash('sha256');
  for (const file of ['lib/scanner.ts', 'lib/version.ts']) {
    scannerHash.update(file + '\0').update(await readFile(file)).update('\0');
  }

  const scanner = new SecurityScanner(() => Date.parse(evaluatedAt));
  const matrix: Record<Verdict, Record<Verdict, number>> = {
    pass: { pass: 0, review: 0, block: 0 },
    review: { pass: 0, review: 0, block: 0 },
    block: { pass: 0, review: 0, block: 0 },
  };
  const results = [];
  for (const [folder, expected] of Object.entries(fixtures)) {
    for (const path of await listFiles('test/fixtures/' + folder)) {
      const content = await readFile(path, 'utf8');
      corpus.update(path + '\0' + expected + '\0' + content + '\0');
      const basenameValue = basename(path);
      const name = basenameValue.endsWith('.npm-metadata.json') ? 'npm-metadata.json'
        : basenameValue.endsWith('.package.json') ? 'package.json' : basenameValue;
      const result = await scanner.scan([{ path, name, content }]);
      matrix[expected][result.riskLevel]++;
      results.push({ path, expected, actual: result.riskLevel });
    }
  }

  const report = {
    scannerVersion: SCANNER_VERSION,
    evaluatedAt,
    corpusSha256: corpus.digest('hex'),
    scannerSha256: scannerHash.digest('hex'),
    matrix,
    results,
  };
  const encoded = JSON.stringify(report, null, 2) + '\n';
  if (process.argv.includes('--check')) {
    if (await readFile(reportPath, 'utf8') !== encoded) throw new Error('Benchmark report is stale. Run pnpm benchmark.');
  } else {
    await writeFile(reportPath, encoded);
  }
  const mismatches = results.filter(row => row.expected !== row.actual);
  if (mismatches.length) throw new Error('Unexpected fixture verdicts: ' + mismatches.map(row => row.path).join(', '));
  console.log('Benchmark verified across ' + results.length + ' fixtures.');
}

main().catch(error => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
