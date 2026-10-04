export interface ScanResult {
  score: number; // 0-100 (100 = safe)
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  riskLevel: 'pass' | 'review' | 'block';
  severityCounts: Record<Finding['severity'], number>;
  findings: Finding[];
  summary: string;
  scannedFiles: number;
  linesAnalyzed: number;
  checksRun: number;
  sourceType?: 'code' | 'github' | 'npm' | 'openvsx' | 'local';
  fetchedAt?: string;
  partial?: boolean;
  scanWarnings?: string[];
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
}
