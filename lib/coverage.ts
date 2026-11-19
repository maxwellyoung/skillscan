import type { FetchBundle, ScanResult } from './types';
import { SCANNER_VERSION } from './version';

/** An incomplete scan must never certify an unexamined payload as safe. */
export function withCoverage(result: ScanResult, bundle: FetchBundle): ScanResult {
  const partial = bundle.partial;
  return {
    ...result,
    ...(partial && result.riskLevel === 'pass' ? { riskLevel: 'review' as const, score: Math.min(result.score, 55), grade: 'F' as const } : {}),
    summary: partial ? 'Partial scan: manual review is required for unscanned content.' : result.summary,
    sourceType: bundle.sourceType, fetchedAt: bundle.fetchedAt, partial, scanWarnings: bundle.warnings,
    scannerVersion: SCANNER_VERSION, target: bundle.target, artifactCoverage: bundle.artifactCoverage,
  };
}
