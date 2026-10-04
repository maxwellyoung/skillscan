import { readdir, readFile, stat } from 'node:fs/promises';
import path from 'node:path';
import { MAX_FILE_BYTES, shouldScanFile, shouldSkipDirectory } from './files';
import type { FetchBundle, GitHubFile } from './types';

export const MAX_LOCAL_FILES = 2_000;

function toPosix(p: string): string {
  return p.split(path.sep).join('/');
}

async function readScannable(absolutePath: string, relativePath: string, warnings: string[]): Promise<GitHubFile> {
  const buffer = await readFile(absolutePath);
  if (buffer.length > MAX_FILE_BYTES) {
    warnings.push(`${relativePath} is larger than ${MAX_FILE_BYTES} bytes; only the first ${MAX_FILE_BYTES} bytes were scanned.`);
  }
  return {
    name: path.basename(absolutePath),
    path: relativePath,
    content: buffer.subarray(0, MAX_FILE_BYTES).toString('utf8'),
  };
}

/**
 * Load a local skill folder, MCP server checkout, extension folder, or single file
 * into the same shape the remote fetchers produce. Uses the shared file-selection
 * rules so local scans match GitHub scans of the same tree. An explicitly named
 * file is always scanned, whatever its extension.
 */
export async function loadLocalTarget(target: string): Promise<FetchBundle> {
  const root = path.resolve(target);
  const rootStat = await stat(root);
  const warnings: string[] = [];
  const fetchedAt = new Date().toISOString();

  // Paths are reported relative to the working directory when the target is inside it,
  // so SARIF locations resolve against a repository checkout (e.g. in GitHub Actions).
  const relativeToCwd = path.relative(process.cwd(), root);
  const outsideCwd = relativeToCwd === '..' || relativeToCwd.startsWith(`..${path.sep}`) || path.isAbsolute(relativeToCwd);
  const base = outsideCwd
    ? (rootStat.isFile() ? path.dirname(root) : root)
    : process.cwd();

  if (rootStat.isFile()) {
    const file = await readScannable(root, toPosix(path.relative(base, root)), warnings);
    return { files: [file], sourceType: 'local', fetchedAt, partial: warnings.length > 0, warnings };
  }

  if (!rootStat.isDirectory()) {
    throw new Error(`${target} is not a file or directory`);
  }

  const files: GitHubFile[] = [];
  let truncated = false;

  async function walk(dir: string): Promise<void> {
    const entries = (await readdir(dir, { withFileTypes: true }))
      .sort((a, b) => a.name.localeCompare(b.name));

    for (const entry of entries) {
      if (files.length >= MAX_LOCAL_FILES) {
        truncated = true;
        return;
      }
      const absolute = path.join(dir, entry.name);
      const relative = toPosix(path.relative(base, absolute));

      if (entry.isDirectory()) {
        if (!shouldSkipDirectory(toPosix(path.relative(root, absolute)))) await walk(absolute);
      } else if (entry.isFile() && shouldScanFile(entry.name)) {
        files.push(await readScannable(absolute, relative, warnings));
      }
      // Symlinks are not followed so a scan cannot escape the target directory.
    }
  }

  await walk(root);

  if (truncated) {
    warnings.push(`Stopped after ${MAX_LOCAL_FILES} files; the rest of the directory was not scanned.`);
  }

  return { files, sourceType: 'local', fetchedAt, partial: warnings.length > 0, warnings };
}
