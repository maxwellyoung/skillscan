import assert from 'node:assert/strict';
import { describe, it } from 'node:test';
import { NextRequest } from 'next/server';
import { POST } from '../app/api/scan/route';
import { RemoteBudget, trustedFetch } from '../lib/remote';
import { GitHubFetcher } from '../lib/github';
import { RegistryFetcher } from '../lib/registry';
import { withCoverage } from '../lib/coverage';
import { excludeFiles } from '../lib/exclusions';
import { SecurityScanner } from '../lib/scanner';
import { admitScan } from '../lib/rate-limit';
import { toSarif } from '../lib/sarif';
import { run } from '../cli/run';
import type { FetchBundle } from '../lib/types';

const cleanBundle = (): FetchBundle => ({ files: [{ name: 'safe.js', path: 'safe.js', content: 'console.log("hello")' }], sourceType: 'github', fetchedAt: '', partial: false, warnings: [] });

describe('release hardening', () => {
  it('uses the default branch and fetches important files exactly once', async t => {
    const urls: string[] = [];
    t.mock.method(globalThis, 'fetch', async (input: string | URL | Request) => {
      const url = new URL(String(input)); urls.push(url.href);
      if (url.hostname === 'raw.githubusercontent.com') return new Response('{}');
      if (!url.pathname.includes('/contents')) return Response.json({ default_branch: 'master' });
      assert.equal(url.searchParams.get('ref'), 'master');
      return Response.json([{ type: 'file', name: 'package.json', path: 'package.json', download_url: 'https://raw.githubusercontent.com/o/r/master/package.json' }]);
    });
    const bundle = await GitHubFetcher.fetchRepoBundle('https://github.com/o/r');
    assert.equal(bundle.files.length, 1);
    assert.equal(bundle.partial, false);
    assert.equal(urls.filter(url => url.includes('raw.githubusercontent.com')).length, 1);
  });

  it('resolves slash-containing refs and subdirectories without assuming main', async t => {
    t.mock.method(globalThis, 'fetch', async (input: string | URL | Request) => {
      const url = new URL(String(input));
      if (url.pathname.includes('/commits/')) return decodeURIComponent(url.pathname.split('/commits/')[1]) === 'feature/a' ? Response.json({}) : new Response('', { status: 404 });
      if (url.hostname === 'api.github.com') {
        assert.equal(url.pathname, '/repos/o/r/contents/skills');
        assert.equal(url.searchParams.get('ref'), 'feature/a');
        return Response.json([{ type: 'file', name: 'SKILL.md', path: 'skills/SKILL.md', download_url: 'https://raw.githubusercontent.com/o/r/feature/a/skills/SKILL.md' }]);
      }
      return new Response('# Hello');
    });
    assert.equal((await GitHubFetcher.fetchRepoBundle('https://github.com/o/r/tree/feature/a/skills')).files[0].path, 'skills/SKILL.md');
  });

  it('rejects registry lookalikes and prevents metadata or redirect SSRF', async t => {
    let calls = 0;
    t.mock.method(globalThis, 'fetch', async (input: string | URL | Request) => {
      calls++;
      const url = String(input);
      assert.equal(new URL(url).hostname, 'registry.npmjs.org');
      if (url.endsWith('/x')) return Response.json({ 'dist-tags': { latest: '1' }, versions: { '1': { dist: { tarball: 'https://registry.npmjs.org/x.tgz' } } } });
      return new Response('', { status: 302, headers: { location: 'http://127.0.0.1/private' } });
    });
    for (const url of ['https://evil.invalid/open-vsx.org/extension/o/r', 'https://open-vsx.org.evil.invalid/extension/o/r', './open-vsx.org/extension/o/r']) assert.equal(RegistryFetcher.isOpenVsxUrl(url), false);
    const bundle = await RegistryFetcher.fetchNpm('npm:x');
    assert.equal(bundle.partial, true); assert.equal(calls, 2);
    assert.ok(bundle.warnings.some(warning => warning.includes('Unsupported URL')));
  });

  it('bounds request counts, deadlines, and cancellation', async t => {
    const mock = t.mock.method(globalThis, 'fetch', async (_input: unknown, init?: RequestInit) => { assert.ok(init?.signal); return new Response('ok'); });
    const budget = new RemoteBudget(undefined, 1);
    await trustedFetch('https://github.com/o/r', ['github.com'], budget);
    await assert.rejects(trustedFetch('https://github.com/o/r', ['github.com'], budget), /request limit/);
    await assert.rejects(trustedFetch('https://github.com/o/r', ['github.com'], new RemoteBudget(undefined, 1, -1)), /deadline/);
    assert.equal(mock.mock.callCount(), 1);
    assert.equal(new RemoteBudget(AbortSignal.abort()).nextSignal().aborted, true);
  });

  it('aborts an unresponsive remote request at the shared deadline', async t => {
    t.mock.method(globalThis, 'fetch', async (_input: unknown, init?: RequestInit) => new Promise<Response>((_resolve, reject) => {
      init?.signal?.addEventListener('abort', () => reject(new Error('deadline abort')), { once: true });
    }));
    const keepAlive = setTimeout(() => {}, 100);
    try {
      await assert.rejects(trustedFetch('https://github.com/o/r', ['github.com'], new RemoteBudget(undefined, 1, 10)), /deadline abort/);
    } finally { clearTimeout(keepAlive); }
  });

  it('never reports PASS or exits zero for an incomplete clean scan', async t => {
    const bundle = cleanBundle(); bundle.partial = true;
    const result = withCoverage(await new SecurityScanner().scan(bundle.files), bundle);
    assert.equal(result.riskLevel, 'review'); assert.equal(result.score, 55);
    assert.equal(toSarif(result, { toolVersion: '0.1.0' }).runs[0].invocations[0].executionSuccessful, false);
    t.mock.method(globalThis, 'fetch', async (input: string | URL | Request) => {
      const url = String(input);
      if (!url.includes('/contents')) return Response.json({ default_branch: 'main' });
      return Response.json([
        { type: 'file', name: 'safe.js', path: 'safe.js', download_url: 'https://raw.githubusercontent.com/o/r/main/safe.js' },
        { type: 'file', name: 'hidden.js', path: 'hidden.js', download_url: 'https://evil.invalid/hidden.js' },
      ]);
    });
    // Raw fetch must return text rather than the metadata control response.
    const original = globalThis.fetch;
    t.mock.method(globalThis, 'fetch', async (input: string | URL | Request, init?: RequestInit) => String(input).includes('raw.githubusercontent.com') ? new Response('console.log("hi")') : original(input, init));
    let output = '';
    assert.equal(await run(['https://github.com/o/r', '--json', '--fail-on', 'none'], { stdout: text => { output += text; }, stderr: () => {} }), 2);
    assert.equal(JSON.parse(output).riskLevel, 'review');
  });

  it('requires explicit exclusion flags and reports the removed scope', () => {
    const bundle = cleanBundle();
    bundle.files.push({ name: 'payload.js', path: 'test/nested/payload.js', content: 'eval(input)' });
    bundle.files.push({ name: 'pattern+[x].js', path: 'pattern+[x].js', content: 'eval(input)' });
    assert.equal(excludeFiles(bundle, []).excluded, 0);
    const selected = excludeFiles(bundle, ['test/**', 'pattern+[x].js']);
    assert.equal(selected.excluded, 2); assert.equal(selected.bundle.files.length, 1);
    assert.ok(selected.bundle.warnings[0].includes('2 files'));
    assert.equal(selected.bundle.partial, false);
  });

  it('rejects malformed, oversized, ambiguous and non-string API inputs', async () => {
    for (const value of ['null', '{', JSON.stringify({ code: 1 }), JSON.stringify({ url: {}, code: 'hello' }), JSON.stringify({ url: 'https://github.com/o/r', code: 'hello' })]) {
      assert.equal((await POST(new NextRequest('https://localhost/api/scan', { method: 'POST', body: value }))).status, 400);
    }
    assert.equal((await POST(new NextRequest('https://localhost/api/scan', { method: 'POST', body: JSON.stringify({ code: 'x'.repeat(220_000) }) }))).status, 413);
  });

  it('enforces remote rate and concurrent scan limits and releases permits once', () => {
    const releases: Array<() => void> = [];
    for (let i = 0; i < 4; i++) { const release = admitScan('concurrency', true); assert.ok(release); releases.push(release); }
    assert.equal(admitScan('other', true), null);
    releases.forEach(release => { release(); release(); });
    const fifth = admitScan('concurrency', true); assert.ok(fifth); fifth();
    assert.equal(admitScan('concurrency', true), null);
  });
});
