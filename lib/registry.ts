import { GitHubFile } from './types';

function encodePackageName(name: string): string {
  return name.startsWith('@') ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
}

function parseNpmSpecifier(input: string): { name: string; version?: string } | null {
  const trimmed = input.trim();
  const withoutUrl = trimmed
    .replace(/^https?:\/\/(?:www\.)?npmjs\.com\/package\//i, '')
    .replace(/^pkg:npm\//i, '')
    .replace(/^npm:/i, '');

  if (!withoutUrl || withoutUrl === trimmed && /^https?:\/\//i.test(trimmed)) return null;

  const cleaned = withoutUrl.split(/[?#]/)[0].replace(/\/v\/[^/]+$/i, '');
  const scoped = cleaned.startsWith('@');
  const versionIndex = scoped ? cleaned.indexOf('@', 1) : cleaned.lastIndexOf('@');

  if (versionIndex > 0) {
    return {
      name: cleaned.slice(0, versionIndex),
      version: cleaned.slice(versionIndex + 1) || undefined,
    };
  }

  return { name: cleaned };
}

function parseOpenVsxUrl(input: string): { namespace: string; extension: string; version?: string } | null {
  const match = input.match(/open-vsx\.org\/extension\/([^/\s?#]+)\/([^/\s?#]+)(?:\/([^/\s?#]+))?/i);
  if (!match) return null;
  return {
    namespace: match[1],
    extension: match[2],
    version: match[3],
  };
}

export class RegistryFetcher {
  static isNpmUrl(input: string): boolean {
    return /^(?:https?:\/\/(?:www\.)?npmjs\.com\/package\/|pkg:npm\/|npm:)/i.test(input.trim());
  }

  static isOpenVsxUrl(input: string): boolean {
    return /open-vsx\.org\/extension\//i.test(input.trim());
  }

  static async fetchNpm(input: string): Promise<GitHubFile[]> {
    const spec = parseNpmSpecifier(input);
    if (!spec) throw new Error('Invalid npm package URL or package URL');

    const response = await fetch(`https://registry.npmjs.org/${encodePackageName(spec.name)}`, {
      headers: { 'User-Agent': 'SkillScan-Security-Scanner/1.0' },
    });

    if (!response.ok) throw new Error(`Failed to fetch npm metadata: ${response.statusText}`);

    const metadata = await response.json();
    const version = spec.version || metadata['dist-tags']?.latest;
    const packageJson = metadata.versions?.[version];

    if (!packageJson) throw new Error(`npm package version not found: ${spec.name}@${version ?? 'latest'}`);

    return [
      {
        name: 'package.json',
        path: `npm:${spec.name}@${version}/package.json`,
        content: JSON.stringify(packageJson, null, 2),
      },
      {
        name: 'npm-metadata.json',
        path: `npm:${spec.name}@${version}/npm-metadata.json`,
        content: JSON.stringify({
          name: metadata.name,
          version,
          distTags: metadata['dist-tags'],
          time: metadata.time,
          maintainers: metadata.maintainers,
          repository: packageJson.repository,
          homepage: packageJson.homepage,
          bugs: packageJson.bugs,
          dist: packageJson.dist,
        }, null, 2),
      },
    ];
  }

  static async fetchOpenVsx(input: string): Promise<GitHubFile[]> {
    const spec = parseOpenVsxUrl(input);
    if (!spec) throw new Error('Invalid OpenVSX extension URL');

    const versionPath = spec.version ? `/${spec.version}` : '';
    const response = await fetch(`https://open-vsx.org/api/${spec.namespace}/${spec.extension}${versionPath}`, {
      headers: { 'User-Agent': 'SkillScan-Security-Scanner/1.0' },
    });

    if (!response.ok) throw new Error(`Failed to fetch OpenVSX metadata: ${response.statusText}`);

    const metadata = await response.json();
    const packageJson = metadata.manifest || {
      name: metadata.name,
      version: metadata.version,
      publisher: metadata.namespace,
      engines: { vscode: metadata.engines?.vscode },
      categories: metadata.categories,
      activationEvents: metadata.activationEvents,
      contributes: metadata.contributes,
      repository: metadata.repository,
    };

    return [
      {
        name: 'package.json',
        path: `openvsx:${spec.namespace}.${spec.extension}/package.json`,
        content: JSON.stringify(packageJson, null, 2),
      },
      {
        name: 'openvsx-metadata.json',
        path: `openvsx:${spec.namespace}.${spec.extension}/metadata.json`,
        content: JSON.stringify(metadata, null, 2),
      },
    ];
  }
}
