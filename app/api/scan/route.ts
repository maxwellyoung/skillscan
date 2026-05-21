import { NextRequest, NextResponse } from 'next/server';
import { GitHubFetcher } from '@/lib/github';
import { SecurityScanner } from '@/lib/scanner';
import { ScanRequest, GitHubFile } from '@/lib/types';

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
      } else {
        return NextResponse.json(
          { error: 'Only GitHub and ClawdHub URLs are supported' },
          { status: 400 }
        );
      }
    }

    if (code) {
      // Handle direct code input — use .ts extension so scanner treats it as executable
      files = [{
        name: 'code.ts',
        content: code,
        path: 'code.ts'
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
        'POST /api/scan': 'Scan code, GitHub repositories, or supported skill-directory URLs for security issues'
      }
    }
  );
}
