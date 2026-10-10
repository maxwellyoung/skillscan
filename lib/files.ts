/**
 * File-selection rules shared by every source (GitHub, local directories).
 * Keeping them in one place means the CLI and the web API scan the same set of files.
 */
export const IMPORTANT_FILES = ['SKILL.md', 'AGENTS.md', 'CLAUDE.md', 'package.json', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lockb', 'README.md'];
export const MAX_FILE_BYTES = 250_000;

/** File names are not a trust boundary: inspect text even under binary-looking names. */
export function decodeTextContent(bytes: Uint8Array, truncated = false): string | null {
  const encoding = bytes[0] === 0xff && bytes[1] === 0xfe ? 'utf-16le'
    : bytes[0] === 0xfe && bytes[1] === 0xff ? 'utf-16be' : 'utf-8';
  try {
    const text = new TextDecoder(encoding, { fatal: true }).decode(bytes, { stream: truncated });
    // NULs and binary control characters distinguish artifacts from source text.
    return /[\u0000-\u0008\u000e-\u001f]/.test(text) ? null : text;
  } catch {
    return null;
  }
}

const SKIPPED_DIRECTORIES = new Set(['node_modules', '.git']);

/**
 * Matches whole path segments so `.github/workflows` is still scanned
 * (a substring check on `.git` would silently skip it).
 */
export function shouldSkipDirectory(dirPath: string): boolean {
  return dirPath.split(/[\\/]/).some(segment => SKIPPED_DIRECTORIES.has(segment));
}
