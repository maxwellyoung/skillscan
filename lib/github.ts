import { GitHubFile } from './types';
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
  private static async request(input: string, api = false): Promise<Response> {
    const url = trustedHttpsUrl(input, GITHUB_HOSTS);
    const headers: Record<string, string> = { 'User-Agent': 'SkillScan-Security-Scanner/1.0' };
    if (api) headers.Accept = 'application/vnd.github.v3+json';
    if (process.env.GITHUB_TOKEN) headers.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
    // Redirects must not create another destination after validation.
    return fetch(url.href, { headers, redirect: 'error' });
  }

  private static async readTextResponse(response: Response): Promise<string | null> {
    if (Number(response.headers.get('content-length')) > this.MAX_FILE_BYTES) {
      await response.body?.cancel();
      throw new Error('File is too large to scan safely');
    }
    if (!response.body) return '';
    const reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    try {
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        size += value.length;
        if (size > this.MAX_FILE_BYTES) {
          await reader.cancel();
          throw new Error('File is too large to scan safely');
        }
        chunks.push(value);
      }
    } finally {
      reader.releaseLock();
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) {
      bytes.set(chunk, offset);
      offset += chunk.length;
    }
    return decodeTextContent(bytes);
  }

  static async fetchRepo(url: string): Promise<GitHubFile[]> {
    // Handle ClawdHub URLs by converting to GitHub
    const convertedUrl = this.convertClawdHubUrl(url);
    
    const repoInfo = this.parseGitHubUrl(convertedUrl);
    if (!repoInfo) {
      throw new Error('Invalid GitHub or ClawdHub URL');
    }

    const files: GitHubFile[] = [];
    
    // First, try to fetch important files
    for (const filename of this.IMPORTANT_FILES) {
      try {
        const content = await this.fetchRawFile(repoInfo.owner, repoInfo.repo, filename, repoInfo.branch);
        if (content) {
          files.push({
            name: filename,
            content,
            path: filename
          });
        }
      } catch {
        // File doesn't exist, continue
        console.warn(`File ${filename} not found, skipping`);
      }
    }

    // Then fetch code files from the repository
    try {
      const repoFiles = await this.fetchRepoContents(repoInfo.owner, repoInfo.repo, repoInfo.branch);
      files.push(...repoFiles.slice(0, this.MAX_FILES - files.length));
    } catch (error) {
      console.error('Failed to fetch repo contents:', error);
    }

    return files;
  }

  static async fetchSingleFile(url: string): Promise<GitHubFile> {
    const convertedUrl = this.convertClawdHubUrl(url);
    const content = await this.fetchRawContent(convertedUrl);
    const filename = new URL(convertedUrl).pathname.split('/').pop() || 'unknown';
    
    return {
      name: filename,
      content,
      path: filename
    };
  }

  private static parseGitHubUrl(url: string): { owner: string; repo: string; branch: string } | null {
    const parsed = trustedHttpsUrl(url, GITHUB_HOSTS);
    const parts = parsed.pathname.split('/').slice(1);
    const [owner, repo] = parts;
    if (![owner, repo].every(part => part && /^[a-z0-9_.-]+$/i.test(part) && part !== '.' && part !== '..')) return null;
    if (parsed.hostname === 'github.com') {
      return { owner, repo: repo.replace(/\.git$/, ''), branch: ['tree', 'blob'].includes(parts[2]) ? parts[3] || 'main' : 'main' };
    }
    if (parsed.hostname === 'raw.githubusercontent.com' && parts[2]) {
      return { owner, repo, branch: parts[2] };
    }
    return null;
  }

  private static async fetchRawContent(input: string): Promise<string> {
    const url = trustedHttpsUrl(input, ['github.com', 'raw.githubusercontent.com']);
    if (url.hostname === 'github.com') {
      const parts = url.pathname.split('/');
      if (parts[3] !== 'blob' || !parts[4] || !parts[5]) throw new Error('Expected a GitHub file URL');
      url.hostname = 'raw.githubusercontent.com';
      parts.splice(3, 1);
      url.pathname = parts.join('/');
    }
    const response = await this.request(url.href);
    if (!response.ok) throw new Error(`Failed to fetch file: ${response.statusText}`);
    const text = await this.readTextResponse(response);
    if (text === null) throw new Error('Binary file cannot be scanned as text');
    return text;
  }

  private static async fetchRawFile(owner: string, repo: string, filename: string, branch: string = 'main'): Promise<string | null> {
    const url = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${filename}`;
    
    try {
      const response = await this.request(url);

      if (!response.ok) {
        return null;
      }

      return await this.readTextResponse(response);
    } catch {
      return null;
    }
  }

  private static async fetchRepoContents(owner: string, repo: string, branch: string = 'main'): Promise<GitHubFile[]> {
    const files: GitHubFile[] = [];
    const visited = new Set<string>();

    async function fetchDirectory(path: string = ''): Promise<void> {
      if (files.length >= GitHubFetcher.MAX_FILES) return;

      const url = `https://api.github.com/repos/${owner}/${repo}/contents/${path}?ref=${branch}`;
      
      try {
        const response = await GitHubFetcher.request(url, true);

        if (!response.ok) {
          console.error(`GitHub API error: ${response.status} ${response.statusText}`);
          return;
        }

        const contents = await response.json();
        
        if (!Array.isArray(contents)) {
          return;
        }

        for (const item of contents) {
          if (files.length >= GitHubFetcher.MAX_FILES) break;
          if (visited.has(item.path)) continue;
          
          visited.add(item.path);

          if (item.type === 'file') {
            if (item.download_url) {
              try {
                const content = await GitHubFetcher.fetchRawContent(item.download_url);
                files.push({
                  name: item.name,
                  content,
                  path: item.path
                });
              } catch (error) {
                console.error(`Failed to fetch ${item.path}:`, error);
              }
            }
          } else if (item.type === 'dir' && !shouldSkipDirectory(item.path)) {
            await fetchDirectory(item.path);
          }
        }
      } catch (error) {
        console.error(`Failed to fetch directory ${path}:`, error);
      }
    }

    await fetchDirectory();
    return files;
  }
}
