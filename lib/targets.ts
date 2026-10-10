import { GitHubFetcher } from './github';
import { RegistryFetcher } from './registry';
import type { FetchBundle } from './types';
import { GITHUB_HOSTS, SKILL_DIRECTORY_HOSTS, trustedHttpsUrl } from './urls';

/** A target the user asked for that could not be fetched; `message` is safe to show. */
export class TargetError extends Error {}

function githubTargetUrl(input: string): URL | null {
  try {
    return trustedHttpsUrl(input, [...GITHUB_HOSTS, ...SKILL_DIRECTORY_HOSTS]);
  } catch {
    return null;
  }
}

export function isRemoteTarget(target: string): boolean {
  return githubTargetUrl(target) !== null ||
    RegistryFetcher.isNpmUrl(target) ||
    RegistryFetcher.isOpenVsxUrl(target);
}

/**
 * Fetch the files behind a GitHub, ClawdHub/Molthub, npm, or OpenVSX URL.
 * Shared by POST /api/scan and the CLI so both resolve targets identically.
 */
export async function fetchRemoteTarget(url: string): Promise<FetchBundle> {
  const githubUrl = githubTargetUrl(url);
  if (githubUrl) {
    try {
      const files = githubUrl.pathname.split('/')[3] === 'blob' || githubUrl.hostname === 'raw.githubusercontent.com'
        ? [await GitHubFetcher.fetchSingleFile(url)]
        : await GitHubFetcher.fetchRepo(url);
      return { files, sourceType: 'github', fetchedAt: new Date().toISOString(), partial: false, warnings: [] };
    } catch (error) {
      console.error('Fetch error:', error);
      throw new TargetError(SKILL_DIRECTORY_HOSTS.includes(githubUrl.hostname)
        ? 'Failed to fetch from the skill directory. The skill may not exist or the GitHub repository is private/deleted.'
        : 'Failed to fetch from GitHub. Please check the URL and try again.');
    }
  }

  if (RegistryFetcher.isNpmUrl(url)) {
    try {
      return await RegistryFetcher.fetchNpm(url);
    } catch (error) {
      console.error('npm fetch error:', error);
      throw new TargetError('Failed to fetch npm package metadata. Check the package URL or version.');
    }
  }

  if (RegistryFetcher.isOpenVsxUrl(url)) {
    try {
      return await RegistryFetcher.fetchOpenVsx(url);
    } catch (error) {
      console.error('OpenVSX fetch error:', error);
      throw new TargetError('Failed to fetch OpenVSX extension metadata. Check the extension URL.');
    }
  }

  throw new TargetError('GitHub, ClawdHub, npm, and OpenVSX URLs are supported');
}
