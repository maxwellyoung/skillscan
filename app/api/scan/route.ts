import { NextRequest, NextResponse } from 'next/server';
import { GitHubFetcher } from '@/lib/github';
import { SecurityScanner } from '@/lib/scanner';
import { ScanRequest, GitHubFile } from '@/lib/types';

export async function POST(request: NextRequest) {
  try {
    const body: ScanRequest = await request.json();
    
    if (!body.code && !body.url) {
      return NextResponse.json(
        { error: 'Either code or url must be provided' },
        { status: 400 }
      );
    }

    let files: GitHubFile[] = [];

    if (body.url) {
      // Handle GitHub URL
      if (body.url.includes('github.com') || body.url.includes('githubusercontent.com')) {
        try {
          if (body.url.includes('/blob/') || body.url.includes('raw.githubusercontent.com')) {
            // Single file URL
            const file = await GitHubFetcher.fetchSingleFile(body.url);
            files = [file];
          } else {
            // Repository URL
            files = await GitHubFetcher.fetchRepo(body.url);
          }
        } catch (error) {
          console.error('GitHub fetch error:', error);
          return NextResponse.json(
            { error: 'Failed to fetch from GitHub. Please check the URL and try again.' },
            { status: 400 }
          );
        }
      } else {
        return NextResponse.json(
          { error: 'Only GitHub URLs are supported' },
          { status: 400 }
        );
      }
    }

    if (body.code) {
      // Handle direct code input
      files = [{
        name: 'code.txt',
        content: body.code,
        path: 'code.txt'
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
        'POST /api/scan': 'Scan code or GitHub repository for security issues'
      }
    }
  );
}