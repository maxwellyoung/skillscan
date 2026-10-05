import { NextRequest, NextResponse } from 'next/server';
import { fetchRemoteTarget, TargetError } from '@/lib/targets';
import { SecurityScanner } from '@/lib/scanner';
import { ScanRequest, GitHubFile } from '@/lib/types';
import type { ScanResult } from '@/lib/types';

function inferPastedFileName(code: string): string {
  const trimmed = code.trim();

  if (/^---[\s\S]{0,400}(?:allowed-tools|tools|permissions)\s*:/i.test(trimmed)) {
    return 'SKILL.md';
  }

  if (/\bon\s*:\s*[\s\S]{0,500}\bjobs\s*:/i.test(trimmed) || /\bpull_request_target\b[\s\S]{0,500}\bjobs\s*:/i.test(trimmed)) {
    return 'pasted.workflow.yml';
  }

  try {
    const json = JSON.parse(trimmed);
    if (json?.engines?.vscode || json?.activationEvents || json?.contributes) {
      return 'package.json';
    }
    if (json?.scripts || json?.dependencies || json?.devDependencies || json?.name || json?.version) {
      return 'package.json';
    }
  } catch {
    // Not JSON; treat as executable source below.
  }

  if (/from ['"`]vscode['"`]|require\(['"`]vscode['"`]\)|vscode\./i.test(trimmed)) {
    return 'extension.ts';
  }

  return 'code.ts';
}

export async function POST(request: NextRequest) {
  try {
    const body: ScanRequest = await request.json();
    const url = body.url?.trim();
    const code = body.code?.trim();
    let sourceType: ScanResult['sourceType'] = code ? 'code' : undefined;
    let fetchedAt: string | undefined;
    let partial = false;
    let scanWarnings: string[] = [];
    
    if (!code && !url) {
      return NextResponse.json(
        { error: 'Either code or url must be provided' },
        { status: 400 }
      );
    }

    if (code && code.length > 200_000) {
      return NextResponse.json(
        { error: 'Code input is too large. Scan a GitHub URL or keep pasted code under 200KB.' },
        { status: 413 }
      );
    }

    let files: GitHubFile[] = [];

    if (url) {
      try {
        const bundle = await fetchRemoteTarget(url);
        files = bundle.files;
        sourceType = bundle.sourceType;
        fetchedAt = bundle.fetchedAt;
        partial = bundle.partial;
        scanWarnings = bundle.warnings;
      } catch (error) {
        if (error instanceof TargetError) {
          return NextResponse.json({ error: error.message }, { status: 400 });
        }
        throw error;
      }
    }

    if (code) {
      const name = inferPastedFileName(code);
      sourceType = 'code';
      fetchedAt = new Date().toISOString();
      files = [{
        name,
        content: code,
        path: name
      }];
    }

    if (files.length === 0) {
      return NextResponse.json(
        { error: 'No files found to scan' },
        { status: 400 }
      );
    }

    // Perform security scan
    const scanner = new SecurityScanner();
    const result = await scanner.scan(files);

    return NextResponse.json({
      ...result,
      sourceType,
      fetchedAt,
      partial,
      scanWarnings,
    });

  } catch (error) {
    console.error('Scan error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

export async function GET() {
  return NextResponse.json(
    { 
      message: 'SkillScan Security Scanner API',
      endpoints: {
        'POST /api/scan': 'Scan code, GitHub repositories, npm packages, OpenVSX extensions, GitHub Actions workflows, or supported skill-directory URLs for security issues'
      }
    }
  );
}
