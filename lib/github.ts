import { GitHubFile } from './types';

export class GitHubFetcher {
  private static readonly MAX_FILES = 50;
  private static readonly SUPPORTED_EXTENSIONS = ['.ts', '.tsx', '.js', '.jsx', '.mjs', '.cjs', '.sh', '.py', '.rb', '.go', '.rs', '.json'];
  private static readonly IMPORTANT_FILES = ['SKILL.md', 'package.json', 'README.md'];

  /**
   * Convert ClawdHub/Molthub skill URLs to their GitHub source.
   * e.g. https://clawdhub.com/skills/some-skill -> GitHub repo URL
   */
  private static convertClawdHubUrl(url: string): string {
    // Convert ClawdHub URLs to GitHub URLs
    // ClawdHub format: https://claudhub.ai/skills/username/skillname
    // or https://molthub.ai/skills/username/skillname
    
    if (url.includes('claudhub.ai/skills/') || url.includes('molthub.ai/skills/')) {
      // Extract username and repo name from ClawdHub URL
      const match = url.match(/(?:claudhub|molthub)\.ai\/skills\/([^\/]+)\/([^\/\?]+)/);
      if (match) {
        const [, username, skillname] = match;
        return `https://github.com/${username}/${skillname}`;
      }
    }
    
    return url;
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
        console.log(`File ${filename} not found, skipping`);
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
    const filename = convertedUrl.split('/').pop() || 'unknown';
    
    return {
      name: filename,
      content,
      path: filename
    };
  }

  private static parseGitHubUrl(url: string): { owner: string; repo: string; branch: string } | null {
    // Handle both github.com and raw.githubusercontent.com URLs
    const githubMatch = url.match(/github\.com\/([^\/]+)\/([^\/]+)(?:\/(?:tree|blob)\/([^\/]+))?/);
    const rawMatch = url.match(/raw\.githubusercontent\.com\/([^\/]+)\/([^\/]+)\/([^\/]+)/);
    
    if (githubMatch) {
      return {
        owner: githubMatch[1],
        repo: githubMatch[2].replace(/\.git$/, ''),
        branch: githubMatch[3] || 'main'
      };
    }
    
    if (rawMatch) {
      return {
        owner: rawMatch[1],
        repo: rawMatch[2],
        branch: rawMatch[3]
      };
    }
    
    return null;
  }

  private static async fetchRawContent(url: string): Promise<string> {
    // Convert GitHub URL to raw URL if needed
    let rawUrl = url;
    if (url.includes('github.com') && !url.includes('raw.githubusercontent.com')) {
      rawUrl = url
        .replace('github.com', 'raw.githubusercontent.com')
        .replace('/blob/', '/');
    }

    const headers: Record<string, string> = {
      'User-Agent': 'SkillScan-Security-Scanner/1.0'
    };
    const ghToken = process.env.GITHUB_TOKEN;
    if (ghToken) {
      headers['Authorization'] = `Bearer ${ghToken}`;
    }

    const response = await fetch(rawUrl, { headers });

    if (!response.ok) {
      throw new Error(`Failed to fetch file: ${response.statusText}`);
    }

    return await response.text();
  }

  private static async fetchRawFile(owner: string, repo: string, filename: string, branch: string = 'main'): Promise<string | null> {
    const url = `https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${filename}`;
    
    try {
      const headers: Record<string, string> = {
        'User-Agent': 'SkillScan-Security-Scanner/1.0'
      };
      const ghToken = process.env.GITHUB_TOKEN;
      if (ghToken) {
        headers['Authorization'] = `Bearer ${ghToken}`;
      }

      const response = await fetch(url, { headers });

      if (!response.ok) {
        return null;
      }

      return await response.text();
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
        const headers: Record<string, string> = {
          'User-Agent': 'SkillScan-Security-Scanner/1.0',
          'Accept': 'application/vnd.github.v3+json'
        };
        
        // Use GitHub token if available (raises rate limit from 60 to 5000 req/hr)
        const ghToken = process.env.GITHUB_TOKEN;
        if (ghToken) {
          headers['Authorization'] = `Bearer ${ghToken}`;
        }

        const response = await fetch(url, { headers });

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
            const shouldInclude = GitHubFetcher.SUPPORTED_EXTENSIONS.some(ext => 
              item.name.endsWith(ext)
            ) || GitHubFetcher.IMPORTANT_FILES.includes(item.name);

            if (shouldInclude && item.download_url) {
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
          } else if (item.type === 'dir' && !item.path.includes('node_modules') && !item.path.includes('.git')) {
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