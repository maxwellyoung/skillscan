export interface ScanTarget {
  name: string;
  version?: string;
  revision?: string;
  path?: string;
}

export interface ArtifactCoverage {
  metadataFiles: number;
  artifactFiles: number;
  integrity: 'verified' | 'unavailable' | 'mismatch';
  entryPointsScanned: number;
  entryPointsDeclared: number;
}

export interface ScanResult {
  score: number; // Heuristic finding score on a 0–100 scale.
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  riskLevel: 'pass' | 'review' | 'block';
  severityCounts: Record<Finding['severity'], number>;
  findings: Finding[];
  summary: string;
  scannedFiles: number;
  linesAnalyzed: number;
  checksRun: number;
  scannerVersion?: string;
  target?: ScanTarget;
  artifactCoverage?: ArtifactCoverage;
  sourceType?: 'code' | 'github' | 'npm' | 'openvsx' | 'local';
  fetchedAt?: string;
  partial?: boolean;
  scanWarnings?: string[];
  excludedFiles?: number;
}

export interface Finding {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  title: string;
  description: string;
  file?: string;
  /** Full path of the scanned file (repo-relative, registry-prefixed, or local-relative). */
  path?: string;
  line?: number;
  snippet?: string;
  remediation?: string;
}

export interface ScanRequest {
  code?: string;
  url?: string;
}

export interface GitHubFile {
  name: string;
  content: string;
  path: string;
}

export interface FetchBundle {
  files: GitHubFile[];
  sourceType: NonNullable<ScanResult['sourceType']>;
  fetchedAt: string;
  partial: boolean;
  warnings: string[];
  target?: ScanTarget;
  artifactCoverage?: ArtifactCoverage;
}
