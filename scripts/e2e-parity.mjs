import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdtemp, writeFile, rm } from 'node:fs/promises';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout } from 'node:timers/promises';

const directory = await mkdtemp(join(tmpdir(), 'skillscan-parity-'));
const portProbe = createServer();
portProbe.listen(0, '127.0.0.1');
await once(portProbe, 'listening');
const port = portProbe.address().port;
await new Promise((resolve, reject) => portProbe.close(error => error ? reject(error) : resolve()));
const base = 'http://127.0.0.1:' + port;
const server = spawn(process.execPath, ['node_modules/next/dist/bin/next', 'start', '--hostname', '127.0.0.1', '--port', String(port)], { stdio: ['ignore', 'inherit', 'inherit'] });

try {
  let ready = false;
  for (let attempt = 0; attempt < 30 && server.exitCode === null; attempt++) {
    try {
      const response = await fetch(base + '/api/scan', { signal: AbortSignal.timeout(1000) });
      await response.body?.cancel();
      if (response.ok) { ready = true; break; }
    } catch {
      // Wait for the production listener to accept requests.
    }
    await setTimeout(300);
  }
  assert.ok(ready, 'the production server started');

  const pack = JSON.parse(execFileSync('npm', ['pack', '--json', '--ignore-scripts', '--pack-destination', directory], { cwd: 'packages/cli', encoding: 'utf8' }));
  execFileSync('tar', ['-xf', join(directory, pack[0].filename), '-C', directory]);
  const input = "\n\nconst answer = 42;\nconsole.log(answer);\n";
  const file = join(directory, 'code.ts');
  await writeFile(file, input);

  const webResponse = await fetch(base + '/api/scan', {
    method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ code: input }),
  });
  assert.equal(webResponse.status, 200);
  assert.equal(webResponse.headers.get('cache-control'), 'no-store');
  const web = await webResponse.json();

  function cli(args) {
    return JSON.parse(execFileSync(process.execPath, [...args, file, '--json'], { encoding: 'utf8' }));
  }
  const source = cli(['--import', 'tsx', 'cli/skillscan.ts']);
  const packed = cli([join(directory, 'package/dist/cli.js')]);
  assert.equal(web.scannerVersion, pack[0].version);
  assert.equal(web.riskLevel, 'pass');
  assert.equal(web.linesAnalyzed, input.split('\n').length);
  for (const key of ['scannerVersion', 'score', 'grade', 'riskLevel', 'severityCounts', 'findings', 'linesAnalyzed', 'scannedFiles', 'partial']) {
    assert.deepEqual(source[key], web[key], 'source CLI and web disagree on ' + key);
    assert.deepEqual(packed[key], web[key], 'packed CLI and web disagree on ' + key);
  }

  for (const [path, expected] of [
    ['/', 'rel="canonical"'],
    ['/benchmark', 'Scanner evaluation'],
    ['/privacy', 'Privacy'],
    ['/robots.txt', 'Sitemap: https://skillscan.ninetynine.digital/sitemap.xml'],
    ['/sitemap.xml', 'https://skillscan.ninetynine.digital/benchmark'],
  ]) {
    const response = await fetch(base + path);
    assert.equal(response.status, 200, path);
    assert.match(response.headers.get('content-security-policy') ?? '', /frame-ancestors/);
    assert.ok((await response.text()).includes(expected), path);
  }
  console.log('Production API, source CLI and packed npm CLI agree on scanner ' + web.scannerVersion + '. Discovery routes and defensive headers passed.');
} finally {
  if (server.exitCode === null && server.signalCode === null) {
    const exited = once(server, 'exit');
    server.kill('SIGTERM');
    await exited;
  }
  await rm(directory, { recursive: true, force: true });
}
