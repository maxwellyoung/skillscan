import type { GitHubFile, FetchBundle } from './types';
import { RemoteBudget, UpstreamError, readBoundedJson, readBoundedResponse, trustedFetch } from './remote';
import { IMPORTANT_FILES, MAX_FILE_BYTES, decodeTextContent, shouldSkipDirectory } from './files';
import { GITHUB_HOSTS, SKILL_DIRECTORY_HOSTS, trustedHttpsUrl } from './urls';

const MAX_FILES = 50;
const COMMIT_SHA = /^[a-f0-9]{40}$/i;
const REPO_PART = /^(?!\.{1,2}$)[a-z0-9_.-]+$/i;

function parseTarget(input: string) {
  const url = trustedHttpsUrl(input, [...GITHUB_HOSTS, ...SKILL_DIRECTORY_HOSTS]);
  const parts = url.pathname.split('/').slice(1).map(decodeURIComponent);
  while (parts.at(-1) === '') parts.pop();
  const directory = SKILL_DIRECTORY_HOSTS.includes(url.hostname);
  if (directory && (parts.shift() !== 'skills' || parts.length !== 2)) throw new Error('Invalid skill directory URL');
  const [owner, rawRepo, ...tail] = parts;
  const repo = rawRepo?.replace(/\.git$/, '');
  if (!owner || !repo || !REPO_PART.test(owner) || !REPO_PART.test(repo)) throw new Error('Invalid GitHub repository URL');

  const operation = url.hostname === 'raw.githubusercontent.com' ? 'blob' : tail.shift();
  if (!directory && !['github.com', 'raw.githubusercontent.com'].includes(url.hostname)) throw new Error('Expected a GitHub repository or file URL');
  if (operation && !['tree', 'blob'].includes(operation)) throw new Error('Expected a GitHub repository, tree, or file URL');
  if (tail.length > 40 || tail.some(part => !part || part === '.' || part === '..' || /[\\/]/.test(part))) {
    throw new Error('Invalid GitHub target path');
  }
  if ((operation && !tail.length) || (operation === 'blob' && tail.length < 2)) throw new Error('Incomplete GitHub target');
  return { owner, repo, operation, tail };
}

export class GitHubFetcher {
  private constructor(private readonly budget: RemoteBudget, private readonly token?: string) {}

  private request(url: string, accept?: string) {
    const headers: Record<string, string> = { 'User-Agent': 'SkillScan-Security-Scanner/1.0' };
    if (accept) headers.Accept = accept;
    if (this.token) headers.Authorization = 'Bearer ' + this.token;
    return trustedFetch(url, GITHUB_HOSTS, this.budget, { headers });
  }

  private async readFile(owner: string, repo: string, revision: string, path: string): Promise<string | null> {
    const encodedPath = path.split('/').map(encodeURIComponent).join('/');
    const response = await this.request('https://raw.githubusercontent.com/' + owner + '/' + repo + '/' + revision + '/' + encodedPath);
    if (!response.ok) throw UpstreamError.fromResponse('GitHub', response);
    return decodeTextContent(await readBoundedResponse(response, MAX_FILE_BYTES));
  }

  private async resolveCommit(base: string, ref: string): Promise<string | null> {
    if (COMMIT_SHA.test(ref)) return ref.toLowerCase();
    const response = await this.request(base + '/commits/' + encodeURIComponent(ref), 'application/vnd.github.sha');
    if (response.status === 404 || response.status === 422) return null;
    if (!response.ok) throw UpstreamError.fromResponse('GitHub', response);
    const sha = new TextDecoder().decode(await readBoundedResponse(response, 128)).trim();
    if (!COMMIT_SHA.test(sha)) throw new Error('GitHub commit identity unavailable');
    return sha.toLowerCase();
  }

  /** Anonymous web callers use public targets. The local CLI can opt into its own token. */
  static async fetchBundle(input: string, budget = new RemoteBudget(), token: string | null | undefined = process.env.GITHUB_TOKEN): Promise<FetchBundle> {
    const { owner, repo, operation, tail } = parseTarget(input);
    const fetcher = new GitHubFetcher(budget, token ?? undefined);
    const base = 'https://api.github.com/repos/' + owner + '/' + repo;
    let revision: string | null = null;
    let rootPath = '';
    if (operation && COMMIT_SHA.test(tail[0])) {
      revision = tail[0].toLowerCase();
      rootPath = tail.slice(1).join('/');
    } else if (operation) {
      const maxRefParts = Math.min(12, tail.length - (operation === 'blob' ? 1 : 0));
      for (let count = maxRefParts; count > 0; count--) {
        revision = await fetcher.resolveCommit(base, tail.slice(0, count).join('/'));
        if (revision) {
          rootPath = tail.slice(count).join('/');
          break;
        }
      }
    } else {
      const response = await fetcher.request(base, 'application/vnd.github+json');
      if (!response.ok) throw UpstreamError.fromResponse('GitHub', response);
      const metadata = await readBoundedJson(response) as { default_branch?: string };
      if (metadata.default_branch) revision = await fetcher.resolveCommit(base, metadata.default_branch);
    }
    if (!revision) throw new Error('GitHub branch, tag, or commit was not found');

    const target = { name: owner + '/' + repo, revision, path: rootPath || undefined };
    const result = { sourceType: 'github' as const, target, fetchedAt: new Date().toISOString() };
    if (operation === 'blob') {
      const content = await fetcher.readFile(owner, repo, revision, rootPath);
      if (content === null) throw new Error('Binary file cannot be scanned as text');
      const name = rootPath.split('/').at(-1)!;
      return { ...result, files: [{ name, path: rootPath, content }], partial: false, warnings: [] };
    }

    const files: GitHubFile[] = [];
    const warnings: string[] = [];
    const visited = new Set<string>();
    const commit = revision;
    let omitted = 0;
    const noteOmission = (warning: string) => {
      omitted++;
      if (warnings.length < 40) warnings.push(warning);
    };

    const walk = async (dir: string): Promise<void> => {
      const encodedDir = dir.split('/').map(encodeURIComponent).join('/');
      const response = await fetcher.request(base + '/contents/' + encodedDir + '?ref=' + commit, 'application/vnd.github+json');
      if (!response.ok) throw UpstreamError.fromResponse('GitHub', response);
      const items = await readBoundedJson(response);
      if (!Array.isArray(items)) throw new Error('Expected a GitHub directory listing');
      if (items.length >= 1000) noteOmission('GitHub directory listing limit reached for ' + (dir || 'repository root') + '.');
      const priority = (item: { name: string; type: string }) => IMPORTANT_FILES.includes(item.name) ? 0 : item.type === 'file' ? 1 : 2;
      items.sort((a, b) => priority(a) - priority(b) || String(a.path).localeCompare(String(b.path)));
      for (const item of items) {
        if (files.length >= MAX_FILES) { noteOmission('Stopped after ' + MAX_FILES + ' GitHub text files.'); return; }
        if (typeof item.path !== 'string' || typeof item.name !== 'string' || visited.has(item.path)) continue;
        const parentPath = item.path.slice(0, item.path.lastIndexOf('/') + 1).replace(/\/$/, '');
        if (parentPath !== dir || item.name !== item.path.split('/').at(-1) || !item.name || item.name === '.' || item.name === '..' || /[\\/]/.test(item.name)) {
          noteOmission('Skipped a GitHub entry with an invalid path.');
          continue;
        }
        visited.add(item.path);
        if (item.type === 'dir') {
          if (!shouldSkipDirectory(item.path)) {
            try { await walk(item.path); } catch { noteOmission('Directory ' + item.path + ' could not be completely scanned.'); }
          }
        } else if (item.type === 'file' && item.download_url && !item.submodule_git_url) {
          try {
            trustedHttpsUrl(item.download_url, ['raw.githubusercontent.com']);
            const content = await fetcher.readFile(owner, repo, commit, item.path);
            if (content !== null) files.push({ name: item.name, path: item.path, content });
          } catch { noteOmission('File ' + item.path + ' could not be scanned within the remote limits.'); }
        } else {
          noteOmission('GitHub entry ' + item.path + ' was unavailable as a regular file.');
        }
      }
    };
    await walk(rootPath);
    if (omitted > warnings.length) warnings.push((omitted - warnings.length) + ' additional GitHub omissions were left out of this report.');
    return { ...result, files, partial: omitted > 0, warnings: Array.from(new Set(warnings)) };
  }

  static async fetchRepoBundle(input: string, budget?: RemoteBudget) {
    return this.fetchBundle(input, budget);
  }

  static async fetchRepo(input: string) {
    return (await this.fetchRepoBundle(input)).files;
  }

  static async fetchSingleFile(input: string, budget?: RemoteBudget): Promise<GitHubFile> {
    if (parseTarget(input).operation !== 'blob') throw new Error('Expected a GitHub file URL');
    return (await this.fetchBundle(input, budget)).files[0];
  }
}
