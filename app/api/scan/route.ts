import { NextRequest, NextResponse } from 'next/server';
import { fetchRemoteTarget, TargetError } from '@/lib/targets';
import { SecurityScanner } from '@/lib/scanner';
import { ScanRequest, FetchBundle } from '@/lib/types';
import { readBoundedResponse } from '@/lib/remote';
import { withCoverage } from '@/lib/coverage';
import { admitScan } from '@/lib/rate-limit';

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

export const maxDuration = 60;

export async function POST(request: NextRequest) {
  let release: (() => void) | null = null;
  try {
    let body: ScanRequest;
    try {
      const bytes = await readBoundedResponse(new Response(request.body, { headers: request.headers }), 220_000, AbortSignal.timeout(5_000));
      const value: unknown = JSON.parse(new TextDecoder().decode(bytes));
      if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('Invalid body');
      body = value as ScanRequest;
      if ((body.code !== undefined && typeof body.code !== 'string') || (body.url !== undefined && typeof body.url !== 'string')) throw new Error('Invalid fields');
    } catch (error) {
      const oversized = error instanceof Error && error.message.includes('size limit');
      return NextResponse.json({ error: oversized ? 'Request body is too large' : 'Provide a JSON object with a string code or url' }, { status: oversized ? 413 : 400 });
    }
    const url = body.url?.trim();
    const code = body.code?.trim();
    if ((!code && !url) || (code && url)) return NextResponse.json({ error: 'Provide exactly one of code or url' }, { status: 400 });
    if ((code && code.length > 200_000) || (url && url.length > 2048)) return NextResponse.json({ error: 'Input is too large' }, { status: 413 });
    const key = request.headers.get('x-real-ip') || 'unknown';
    release = admitScan(key, Boolean(url));
    if (!release) return NextResponse.json({ error: 'Scan limit reached. Try again in a minute.' }, { status: 429, headers: { 'Retry-After': '60' } });
    let bundle: FetchBundle;
    if (url) bundle = await fetchRemoteTarget(url, request.signal);
    else {
      const name = inferPastedFileName(code!);
      bundle = { files: [{ name, content: code!, path: name }], sourceType: 'code', fetchedAt: new Date().toISOString(), partial: false, warnings: [] };
    }
    if (!bundle.files.length) return NextResponse.json({ error: 'No files found to scan' }, { status: 400 });
    return NextResponse.json(withCoverage(await new SecurityScanner().scan(bundle.files), bundle));
  } catch (error) {
    if (error instanceof TargetError) return NextResponse.json({ error: error.message }, { status: 400 });
    return NextResponse.json({ error: 'Scan failed' }, { status: 500 });
  } finally { release?.(); }
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
