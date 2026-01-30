export interface ScanResult {
  score: number; // 0-100 (100 = safe)
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  findings: Finding[];
  summary: string;
  scannedFiles: number;
  linesAnalyzed: number;
}

export interface Finding {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  title: string;
  description: string;
  file?: string;
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