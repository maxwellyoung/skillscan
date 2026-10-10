export const GITHUB_HOSTS = ['github.com', 'raw.githubusercontent.com', 'api.github.com'];
export const SKILL_DIRECTORY_HOSTS = ['claudhub.ai', 'clawdhub.ai', 'molthub.ai'];

/** Validate the parsed destination, never a host-like substring in user input. */
export function trustedHttpsUrl(input: string, hosts: readonly string[]): URL {
  const url = new URL(input);
  if (url.protocol !== 'https:' || url.username || url.password || url.port || !hosts.includes(url.hostname)) {
    throw new Error('Unsupported URL destination');
  }
  return url;
}
