import type { Finding, ScanResult } from './types';

type Severity = Finding['severity'];

export const SARIF_SCHEMA = 'https://json.schemastore.org/sarif-2.1.0.json';
const INFORMATION_URI = 'https://github.com/maxwellyoung/skillscan';

const LEVEL: Record<Severity, 'error' | 'warning' | 'note'> = {
  critical: 'error',
  high: 'error',
  medium: 'warning',
  low: 'note',
  info: 'note',
};

// GitHub code scanning buckets: >=9 critical, 7-8.9 high, 4-6.9 medium, 0.1-3.9 low.
const SECURITY_SEVERITY: Record<Severity, string> = {
  critical: '9.5',
  high: '8.0',
  medium: '5.5',
  low: '3.0',
  info: '0.0',
};

const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/** Stable rule id derived from the finding category, e.g. "skillscan/secret-exfiltration-flow". */
export function ruleIdFor(category: string): string {
  const slug = category.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
  return `skillscan/${slug || 'uncategorized'}`;
}

function ruleNameFor(category: string): string {
  return category.replace(/[^A-Za-z0-9]+/g, ' ').trim().split(' ')
    .map(word => word.charAt(0).toUpperCase() + word.slice(1)).join('') || 'Uncategorized';
}

function toUri(filePath: string): string {
  return filePath.replace(/\\/g, '/').replace(/^\.\//, '');
}

export interface SarifOptions {
  toolVersion: string;
}

/** Convert a scan result into a SARIF 2.1.0 log with one run. */
export function toSarif(result: ScanResult, options: SarifOptions) {
  const rules = new Map<string, { category: string; severity: Severity; remediation?: string; description: string }>();

  for (const finding of result.findings) {
    const id = ruleIdFor(finding.category);
    const existing = rules.get(id);
    // A category can contain findings of different severities; the rule carries the worst one.
    if (!existing || SEVERITY_ORDER.indexOf(finding.severity) < SEVERITY_ORDER.indexOf(existing.severity)) {
      rules.set(id, {
        category: finding.category,
        severity: finding.severity,
        remediation: finding.remediation ?? existing?.remediation,
        description: finding.description,
      });
    }
  }

  const ruleIds = Array.from(rules.keys()).sort();

  return {
    $schema: SARIF_SCHEMA,
    version: '2.1.0' as const,
    runs: [
      {
        tool: {
          driver: {
            name: 'skillscan',
            informationUri: INFORMATION_URI,
            version: options.toolVersion,
            semanticVersion: options.toolVersion,
            rules: ruleIds.map(id => {
              const rule = rules.get(id)!;
              return {
                id,
                name: ruleNameFor(rule.category),
                shortDescription: { text: rule.category },
                fullDescription: { text: rule.description },
                ...(rule.remediation ? { help: { text: rule.remediation } } : {}),
                defaultConfiguration: { level: LEVEL[rule.severity] },
                properties: {
                  tags: ['security'],
                  'security-severity': SECURITY_SEVERITY[rule.severity],
                },
              };
            }),
          },
        },
        results: result.findings.map(finding => {
          const uri = finding.path ?? finding.file;
          const region = finding.line && finding.line > 0
            ? {
                startLine: finding.line,
                ...(finding.snippet ? { snippet: { text: finding.snippet } } : {}),
              }
            : undefined;

          return {
            ruleId: ruleIdFor(finding.category),
            ruleIndex: ruleIds.indexOf(ruleIdFor(finding.category)),
            level: LEVEL[finding.severity],
            message: { text: `${finding.title}. ${finding.description}` },
            ...(uri
              ? {
                  locations: [{
                    physicalLocation: {
                      artifactLocation: { uri: toUri(uri) },
                      ...(region ? { region } : {}),
                    },
                  }],
                }
              : {}),
            properties: {
              severity: finding.severity,
              category: finding.category,
              ...(finding.remediation ? { remediation: finding.remediation } : {}),
            },
          };
        }),
        invocations: [{ executionSuccessful: true }],
        properties: {
          score: result.score,
          grade: result.grade,
          riskLevel: result.riskLevel,
          severityCounts: result.severityCounts,
          scannedFiles: result.scannedFiles,
          partial: result.partial ?? false,
          ...(result.scanWarnings?.length ? { scanWarnings: result.scanWarnings } : {}),
        },
      },
    ],
  };
}
