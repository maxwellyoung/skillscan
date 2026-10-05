// Bundles the CLI and the scanner it imports into one dependency-free file for
// the published @maxwellyoung/skillscan package (packages/cli).
import { build } from 'esbuild';
import { copyFile, rm } from 'node:fs/promises';

const pkgDir = 'packages/cli';

await rm(`${pkgDir}/dist`, { recursive: true, force: true });
await build({
  entryPoints: ['cli/skillscan.ts'],
  outfile: `${pkgDir}/dist/cli.js`,
  bundle: true,
  platform: 'node',
  target: 'node20',
  format: 'cjs',
  // Readable output so people can audit what a security tool runs.
  minify: false,
  legalComments: 'none',
  logLevel: 'info',
});
// npm only packs a LICENSE that lives in the package directory.
await copyFile('LICENSE', `${pkgDir}/LICENSE`);
