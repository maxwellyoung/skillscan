import { GitHubFile, FetchBundle } from './types';
import { RemoteBudget, readBoundedJson, readBoundedResponse, trustedFetch } from './remote';
import { IMPORTANT_FILES, MAX_FILE_BYTES, decodeTextContent, shouldSkipDirectory } from './files';
import { GITHUB_HOSTS, SKILL_DIRECTORY_HOSTS, trustedHttpsUrl } from './urls';

export class GitHubFetcher {
  private static readonly MAX_FILES = 50;
  private static readonly MAX_FILE_BYTES = MAX_FILE_BYTES;
  private static readonly IMPORTANT_FILES = IMPORTANT_FILES;

  private static convertClawdHubUrl(input: string): string {
    const url = trustedHttpsUrl(input, [...GITHUB_HOSTS, ...SKILL_DIRECTORY_HOSTS]);
    if (SKILL_DIRECTORY_HOSTS.includes(url.hostname)) {
      const parts = url.pathname.split('/');
      if (parts[1] !== 'skills' || !parts[2] || !parts[3]) throw new Error('Invalid skill directory URL');
      return `https://github.com/${parts[2]}/${parts[3]}`;
    }
    return url.href;
  }

  /** All GitHub requests share the credential boundary, including API-provided URLs. */
  private static async request(input: string, api = false, budget = new RemoteBudget()): Promise<Response> {
    const url = trustedHttpsUrl(input, GITHUB_HOSTS);
    const headers: Record<string, string> = { 'User-Agent': 'SkillScan-Security-Scanner/1.0' };
    if (api) headers.Accept = 'application/vnd.github.v3+json';
    if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
    // Redirects must not create another destination after validation.
    return trustedFetch(url.href, GITHUB_HOSTS, budget, { headers });
  }

  private static async readTextResponse(response: Response): Promise<string | null> {
    return decodeTextContent(await readBoundedResponse(response, this.MAX_FILE_BYTES));
  }

  static async fetchRepo(url: string): Promise<GitHubFile[]> {
    return (await this.fetchRepoBundle(url)).files;
  }

  static async fetchRepoBundle(input: string, budget = new RemoteBudget()): Promise<FetchBundle> {
    const url = new URL(this.convertClawdHubUrl(input));
    const parts = url.pathname.split('/').slice(1).map(decodeURIComponent);
    const [owner, rawRepo] = parts;
    const repo = rawRepo?.replace(/\.git$/, '');
    if (url.hostname !== 'github.com' || ![owner, repo].every(p => p && /^[a-z0-9_.-]+$/i.test(p) && p !== '.' && p !== '..')) {
      throw new Error('Invalid GitHub repository URL');
    }
    const base = `https://api.github.com/repos/${owner}/${repo}`;
    let branch: string;
    let rootPath = '';
    if (parts.length > 2 && parts[2]) {
      if (parts[2] !== 'tree' || !parts[3]) throw new Error('Expected a GitHub repository or tree URL');
      const tail = parts.slice(3);
      if (tail.length > 12) throw new Error('GitHub tree path is too deep');
      branch = '';
      for (let count = tail.length; count > 0; count -= 1) {
        const candidate = tail.slice(0, count).join('/');
        const response = await this.request(`${base}/commits/${encodeURIComponent(candidate)}`, true, budget);
        if (response.ok) {
          branch = candidate;
          rootPath = tail.slice(count).join('/');
          break;
        }
        if (response.status !== 404 && response.status !== 422) throw new Error(`GitHub ref lookup failed (${response.status})`);
      }
      if (!branch) throw new Error('GitHub branch or tag not found');
    } else {
      const response = await this.request(base, true, budget);
      if (!response.ok) throw new Error(`GitHub repository lookup failed (${response.status})`);
      const metadata = await readBoundedJson(response) as { default_branch?: string };
      if (!metadata.default_branch) throw new Error('GitHub default branch unavailable');
      branch = metadata.default_branch;
    }

    const files: GitHubFile[] = [];
    const warnings: string[] = [];
    const visited = new Set<string>();
    // Walk each path once; important files sort first rather than being fetched twice.
    const walk = async (dir: string): Promise<void> => {
      const response = await this.request(`${base}/contents/${dir.split('/').map(encodeURIComponent).join('/')}?ref=${encodeURIComponent(branch)}`, true, budget);
      if (!response.ok) throw new Error(`GitHub directory lookup failed (${response.status})`);
      const items = await readBoundedJson(response);
      if (!Array.isArray(items)) throw new Error('Expected a GitHub directory listing');
      const priority = (item: { name: string; type: string }) => this.IMPORTANT_FILES.includes(item.name) ? 0 : item.type === 'file' ? 1 : 2;
      items.sort((a, b) => priority(a) - priority(b) || String(a.path).localeCompare(String(b.path)));
      for (const item of items) {
        if (files.length >= this.MAX_FILES) { warnings.push(`Stopped after ${this.MAX_FILES} GitHub text files.`); return; }
        if (typeof item.path !== 'string' || typeof item.name !== 'string' || visited.has(item.path)) continue;
        visited.add(item.path);
        if (item.type === 'dir' && !shouldSkipDirectory(item.path)) {
          try { await walk(item.path); } catch { warnings.push(`Directory ${item.path} could not be completely scanned.`); }
        } else if (item.type === 'file' && item.download_url) {
          try {
            const content = await this.fetchRawContent(item.download_url, budget, true);
            if (content !== null) files.push({ name: item.name, path: item.path, content });
          } catch { warnings.push(`File ${item.path} could not be scanned within the remote limits.`); }
        }
      }
    };
    await walk(rootPath);
    return { files, sourceType: 'github', fetchedAt: new Date().toISOString(), partial: warnings.length > 0, warnings: Array.from(new Set(warnings)) };
  }

  static async fetchSingleFile(url: string, budget = new RemoteBudget()): Promise<GitHubFile> {
    const convertedUrl = this.convertClawdHubUrl(url);
    const content = await this.fetchRawContent(convertedUrl, budget);
    if (content === null) throw new Error('Binary file cannot be scanned as text');
    const filename = new URL(convertedUrl).pathname.split('/').pop() || 'unknown';
    
    return {
      name: filename,
      content,
      path: filename
    };
  }

  private static async fetchRawContent(input: string, budget: RemoteBudget, skipBinary = false): Promise<string | null> {
    const url = trustedHttpsUrl(input, ['github.com', 'raw.githubusercontent.com']);
    if (url.hostname === 'github.com') {
      const parts = url.pathname.split('/');
      if (parts[3] !== 'blob' || !parts[4] || !parts[5]) throw new Error('Expected a GitHub file URL');
      url.hostname = 'raw.githubusercontent.com';
      parts.splice(3, 1);
      url.pathname = parts.join('/');
    }
    const response = await this.request(url.href, false, budget);
    if (!response.ok) throw new Error(`Failed to fetch file: ${response.statusText}`);
    const text = await this.readTextResponse(response);
    if (text === null && !skipBinary) throw new Error('Binary file cannot be scanned as text');
    return text;
  }

}
