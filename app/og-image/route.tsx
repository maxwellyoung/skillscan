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
          justifyContent: 'space-between',
          padding: '72px 80px',
          backgroundColor: '#000000',
          color: 'rgba(255,255,255,0.9)',
        }}
      >
        <div style={{ display: 'flex', fontSize: 28, fontWeight: 500, letterSpacing: '-0.01em' }}>SkillScan</div>

        <div style={{ display: 'flex', flexDirection: 'column' }}>
          <div style={{ display: 'flex', fontSize: 84, fontWeight: 300, letterSpacing: '-0.03em', color: '#ffffff', lineHeight: 1.05 }}>
            Know what you&apos;re installing.
          </div>
          <div style={{ display: 'flex', marginTop: 28, fontSize: 30, lineHeight: 1.4, color: 'rgba(255,255,255,0.55)', maxWidth: 900 }}>
            Static security checks for agent skills, MCP servers, npm packages, VS Code extensions, and GitHub Actions.
          </div>
        </div>

        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 24, color: 'rgba(255,255,255,0.45)' }}>
          <div style={{ display: 'flex' }}>Web · npm CLI · GitHub Action</div>
          <div style={{ display: 'flex' }}>skillscan.ninetynine.digital</div>
        </div>
      </div>
    ),
    {
      width: 1200,
      height: 630,
    },
  );
}
