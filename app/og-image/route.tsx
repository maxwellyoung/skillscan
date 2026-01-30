import { ImageResponse } from 'next/og';

export const runtime = 'edge';

export async function GET() {
  return new ImageResponse(
    (
      <div
        style={{
          height: '100%',
          width: '100%',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          backgroundColor: 'hsl(220, 15%, 4%)',
          fontSize: 32,
          fontWeight: 600,
        }}
      >
        <div
          style={{
            background: 'linear-gradient(90deg, hsl(355, 78%, 58%) 0%, hsl(355, 78%, 70%) 100%)',
            backgroundClip: 'text',
            WebkitBackgroundClip: 'text',
            color: 'transparent',
            fontSize: 72,
            fontWeight: 300,
            marginBottom: 24,
            letterSpacing: '-0.02em',
          }}
        >
          SkillScan
        </div>
        <div
          style={{
            color: 'hsl(0, 0%, 90%)',
            fontSize: 32,
            marginBottom: 16,
            textAlign: 'center',
            maxWidth: 800,
          }}
        >
          Security Scanner for AI Skills & Code
        </div>
        <div
          style={{
            color: 'hsl(220, 15%, 60%)',
            fontSize: 24,
            textAlign: 'center',
            maxWidth: 600,
          }}
        >
          Scan Claude Code skills and repositories for security vulnerabilities
        </div>
      </div>
    ),
    {
      width: 1200,
      height: 630,
    },
  );
}