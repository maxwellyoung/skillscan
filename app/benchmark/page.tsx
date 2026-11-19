import type { Metadata } from 'next';
import Link from 'next/link';
import report from './report.json';

export const metadata: Metadata = { title: 'Evaluation · SkillScan', alternates: { canonical: '/benchmark' } };
const verdicts = ['pass', 'review', 'block'] as const;

export default function Benchmark() {
  return (
    <main className="mx-auto max-w-3xl space-y-6 px-6 py-12 text-white/80">
      <Link className="underline" href="/">SkillScan</Link>
      <h1 className="font-serif text-4xl text-white">Scanner evaluation</h1>
      <p>Scanner {report.scannerVersion} was checked against {report.results.length} labeled fixtures. The harness runs the scanner directly with a fixed clock. These counts describe the checked-in fixtures. They do not estimate real-world detection or false-positive rates.</p>
      <p>The corpus covers representative patterns and uses examples maintained alongside the rules. It does not measure remote coverage, live behavior, or performance on an independent holdout.</p>
      <table className="w-full border-collapse text-left text-sm">
        <caption className="pb-3 text-left">Expected verdict by observed verdict</caption>
        <thead>
          <tr className="border-b border-white/25">
            <th scope="col" className="py-2">Expected</th>
            {verdicts.map(verdict => <th scope="col" key={verdict}>{verdict}</th>)}
          </tr>
        </thead>
        <tbody>
          {verdicts.map(verdict => <tr key={verdict} className="border-b border-white/15">
            <th scope="row" className="py-2">{verdict}</th>
            {verdicts.map(actual => <td key={actual}>{report.matrix[verdict][actual]}</td>)}
          </tr>)}
        </tbody>
      </table>
      <details>
        <summary className="cursor-pointer font-medium text-white">Fixture results and reproduction</summary>
        <ul className="mt-3 space-y-2">
          {report.results.map(result => <li key={result.path} className="break-words text-sm">
            <code>{result.path.replace('test/fixtures/', '')}</code> · {result.actual} (expected {result.expected})
          </li>)}
        </ul>
        <dl className="mt-4 space-y-1 text-sm">
          <dt>Evaluation clock</dt>
          <dd><code>{report.evaluatedAt}</code></dd>
          <dt>Corpus SHA-256</dt>
          <dd><code className="break-all">{report.corpusSha256}</code></dd>
          <dt>Scanner SHA-256</dt>
          <dd><code className="break-all">{report.scannerSha256}</code></dd>
        </dl>
        <p className="mt-4">Run <code>pnpm benchmark --check</code> from the source checkout to reproduce the report.</p>
      </details>
    </main>
  );
}
