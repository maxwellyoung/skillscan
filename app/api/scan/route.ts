import { NextRequest, NextResponse } from 'next/server';
import { GitHubFetcher } from '@/lib/github';
import { RegistryFetcher } from '@/lib/registry';
import { SecurityScanner } from '@/lib/scanner';
import { ScanRequest, GitHubFile } from '@/lib/types';

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
      // Handle GitHub and ClawdHub URLs
      if (url.includes('github.com') ||
          url.includes('githubusercontent.com') ||
          url.includes('claudhub.ai') ||
          url.includes('clawdhub.ai') ||
          url.includes('molthub.ai')) {
        try {
          if (url.includes('/blob/') || url.includes('raw.githubusercontent.com')) {
            // Single file URL
            const file = await GitHubFetcher.fetchSingleFile(url);
            files = [file];
          } else {
            // Repository URL (including ClawdHub)
            files = await GitHubFetcher.fetchRepo(url);
          }
        } catch (error) {
          console.error('Fetch error:', error);
          
          if (url.includes('claudhub.ai') || url.includes('clawdhub.ai') || url.includes('molthub.ai')) {
            return NextResponse.json(
              { error: 'Failed to fetch from the skill directory. The skill may not exist or the GitHub repository is private/deleted.' },
              { status: 400 }
            );
          } else {
            return NextResponse.json(
              { error: 'Failed to fetch from GitHub. Please check the URL and try again.' },
              { status: 400 }
            );
          }
        }
      } else if (RegistryFetcher.isNpmUrl(url)) {
        try {
          files = await RegistryFetcher.fetchNpm(url);
        } catch (error) {
          console.error('npm fetch error:', error);
          return NextResponse.json(
            { error: 'Failed to fetch npm package metadata. Check the package URL or version.' },
            { status: 400 }
          );
        }
      } else if (RegistryFetcher.isOpenVsxUrl(url)) {
        try {
          files = await RegistryFetcher.fetchOpenVsx(url);
        } catch (error) {
          console.error('OpenVSX fetch error:', error);
          return NextResponse.json(
            { error: 'Failed to fetch OpenVSX extension metadata. Check the extension URL.' },
            { status: 400 }
          );
        }
      } else {
        return NextResponse.json(
          { error: 'GitHub, ClawdHub, npm, and OpenVSX URLs are supported' },
          { status: 400 }
        );
      }
    }

    if (code) {
      const name = inferPastedFileName(code);
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

    return NextResponse.json(result);

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
