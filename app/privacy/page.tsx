import type { Metadata } from 'next';
import Link from 'next/link';

export const metadata: Metadata = { title: 'Privacy · SkillScan', alternates: { canonical: '/privacy' } };

export default function Privacy() {
  return (
    <main className="mx-auto max-w-2xl space-y-6 px-6 py-12 text-white/80">
      <Link className="underline" href="/">SkillScan</Link>
      <h1 className="font-serif text-4xl text-white">Privacy</h1>
      <p>The web scanner sends your pasted code or target URL to the SkillScan API for processing on Vercel. The application processes pasted code in memory. It has no database of scan inputs or results. Hosting and upstream providers operate their own services and logging policies.</p>
      <p>Remote scans request public content from GitHub, npm or OpenVSX. Rate limits use a request counter. When a shared limiter is configured, it receives only an aggregate counter for remote scans.</p>
      <p>The CLI scans local paths offline after installation. A scan report may include source excerpts. Opting into SARIF upload in GitHub Actions sends the report to GitHub Code Scanning.</p>
    </main>
  );
}
