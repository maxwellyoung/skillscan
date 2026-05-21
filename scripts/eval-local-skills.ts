import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { SecurityScanner } from '../lib/scanner';
import type { Finding, GitHubFile } from '../lib/types';

const DEFAULT_ROOTS = [
  '/Users/maxwellyoung/.codex/skills',
  '/Users/maxwellyoung/.agents/skills',
  '/Users/maxwellyoung/.codex/plugins/cache',
];

function findSkillFiles(roots: string[]): string[] {
  return execFileSync('find', [...roots, '-name', 'SKILL.md', '-type', 'f'], {
    encoding: 'utf8',
  })
    .trim()
    .split('\n')
    .filter(Boolean);
}

function redactHome(path: string | undefined): string | undefined {
  return path?.replace('/Users/maxwellyoung/', '~/');
}

function summarizeFinding(finding: Finding) {
  return {
    severity: finding.severity,
    category: finding.category,
    title: finding.title,
    file: redactHome(finding.file),
    line: finding.line,
    snippet: finding.snippet?.slice(0, 180),
  };
}

async function main() {
  const roots = process.argv.slice(2);
  const skillPaths = findSkillFiles(roots.length > 0 ? roots : DEFAULT_ROOTS);
  const files: GitHubFile[] = skillPaths.map((path) => ({
    name: path,
    path,
    content: readFileSync(path, 'utf8'),
  }));

  const result = await new SecurityScanner().scan(files);
  const findingsByCategory = Object.groupBy(result.findings, (finding) => finding.category);
  const blockingFindings = result.findings.filter((finding) =>
    finding.severity === 'critical' || finding.severity === 'high'
  );

  const summary = {
    files: files.length,
    score: result.score,
    grade: result.grade,
    riskLevel: result.riskLevel,
    severityCounts: result.severityCounts,
    findings: result.findings.length,
    categories: Object.fromEntries(
      Object.entries(findingsByCategory).map(([category, findings]) => [
        category,
        findings?.length ?? 0,
      ]),
    ),
    blockingSample: blockingFindings.slice(0, 25).map(summarizeFinding),
    informationalSample: result.findings
      .filter((finding) => finding.severity === 'info')
      .slice(0, 25)
      .map(summarizeFinding),
  };

  console.log(JSON.stringify(summary, null, 2));

  if (blockingFindings.length > 0) {
    process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
