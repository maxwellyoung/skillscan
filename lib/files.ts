/**
 * File-selection rules shared by every source (GitHub, local directories).
 * Keeping them in one place means the CLI and the web API scan the same set of files.
 */
export const SUPPORTED_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.sh', '.py', '.rb', '.go', '.rs', '.json', '.yaml', '.yml', '.toml', '.env'];
export const IMPORTANT_FILES = ['SKILL.md', 'AGENTS.md', 'CLAUDE.md', 'package.json', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lockb', 'README.md'];
export const MAX_FILE_BYTES = 250_000;

export function shouldScanFile(name: string): boolean {
  return SUPPORTED_EXTENSIONS.some(ext => name.endsWith(ext)) || IMPORTANT_FILES.includes(name);
}

const SKIPPED_DIRECTORIES = new Set(['node_modules', '.git']);

/**
 * Matches whole path segments so `.github/workflows` is still scanned
 * (a substring check on `.git` would silently skip it).
 */
export function shouldSkipDirectory(dirPath: string): boolean {
  return dirPath.split(/[\\/]/).some(segment => SKIPPED_DIRECTORIES.has(segment));
}
