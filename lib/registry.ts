import { gunzipSync, inflateRawSync } from 'node:zlib';
import { GitHubFile, FetchBundle } from './types';
import { decodeTextContent } from './files';
import { RemoteBudget, ResponseTooLargeError, readBoundedResponse, readBoundedJson, trustedFetch } from './remote';
import { trustedHttpsUrl } from './urls';

const MAX_ARTIFACT_BYTES = 6_000_000;
const MAX_EXTRACTED_FILES = 40;
const MAX_EXTRACTED_FILE_BYTES = 180_000;
const MAX_INFLATED_ARTIFACT_BYTES = 12_000_000;

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
  try {
    const url = trustedHttpsUrl(input.trim(), ['open-vsx.org']);
    const match = url.pathname.match(/^\/extension\/([a-z0-9_-]+)\/([a-z0-9_.-]+)(?:\/([a-z0-9_.-]+))?\/?$/i);
    return match ? { namespace: match[1], extension: match[2], version: match[3] } : null;
  } catch { return null; }
}

async function fetchArtifact(url: string, warnings: string[], hosts: string[], budget: RemoteBudget): Promise<{ bytes: Buffer; lastModified?: string } | null> {
  try {
    // Follow only explicitly validated registry/CDN redirects. No credentials are attached.
    let response: Response | undefined;
    for (let hop = 0; hop < 4; hop++) {
      const target = trustedHttpsUrl(url, hosts);
      response = await fetch(target.href, { redirect: 'manual', signal: budget.nextSignal(), cache: 'no-store' });
      if (![301, 302, 303, 307, 308].includes(response.status)) break;
      const location = response.headers.get('location');
      await response.body?.cancel();
      if (!location) throw new Error('Missing artifact redirect destination');
      url = new URL(location, target).href;
      response = undefined;
    }
    if (!response?.ok) throw new Error('Artifact download failed or exceeded redirect limit');
    const lastModified = response.headers.get('last-modified') ?? undefined;
    return { bytes: Buffer.from(await readBoundedResponse(response, MAX_ARTIFACT_BYTES)), lastModified };
  } catch (error) {
    warnings.push(`Artifact fetch failed: ${error instanceof Error ? error.message : 'unknown error'}`);
    return null;
  }
}

/** Manifest and referenced entry points take precedence over archive order. */
function selectArtifactFiles(files: GitHubFile[], warnings: string[]): GitHubFile[] {
  const entrypoints = new Set<string>();
  for (const file of files.filter(file => file.name === 'package.json')) {
    try {
      const manifest = JSON.parse(file.content);
      const root = file.path.slice(0, file.path.lastIndexOf('/') + 1);
      const collect = (value: unknown): void => {
        if (typeof value === 'string') entrypoints.add(root + value.replace(/^\.\//, ''));
        else if (value && typeof value === 'object') Object.values(value).forEach(collect);
      };
      for (const key of ['main', 'module', 'browser', 'bin', 'exports']) collect(manifest[key]);
      for (const script of Object.values(manifest.scripts || {})) {
        if (typeof script === 'string') {
          for (const token of script.match(/[\w./-]+\.(?:[cm]?js|ts|sh|bash|zsh|ps1|py|php|pl)\b/g) || []) collect(token);
        }
      }
    } catch { warnings.push(`Could not parse archive manifest ${file.path}.`); }
  }
  const priority = (file: GitHubFile): number => file.name === 'package.json' ? 0 : entrypoints.has(file.path) ? 1 : /\.(?:[cm]?js|ts|sh|bash|zsh|ps1|py|php|pl)$/.test(file.path) ? 2 : 3;
  files.sort((a, b) => priority(a) - priority(b) || a.path.localeCompare(b.path));
  if (files.length > MAX_EXTRACTED_FILES) warnings.push(`Artifact scan limited to ${MAX_EXTRACTED_FILES} text files, prioritizing manifests and entry points.`);
  return files.slice(0, MAX_EXTRACTED_FILES);
}

function basename(filePath: string): string {
  return filePath.split('/').pop()?.toLowerCase() || filePath.toLowerCase();
}

function parseTarString(buffer: Buffer, start: number, length: number): string {
  return buffer.subarray(start, start + length).toString('utf8').split('\0')[0].trim();
}

function parseTarSize(buffer: Buffer, start: number): number {
  const raw = parseTarString(buffer, start, 12);
  return /^[0-7]+$/.test(raw) ? Number.parseInt(raw, 8) : raw === '' ? 0 : NaN;
}

function extractTgz(buffer: Buffer, pathPrefix: string, warnings: string[]): GitHubFile[] {
  let tar: Buffer;
  try {
    tar = gunzipSync(buffer, { maxOutputLength: MAX_INFLATED_ARTIFACT_BYTES });
  } catch {
    warnings.push(`npm tarball could not be decompressed within the ${MAX_INFLATED_ARTIFACT_BYTES}-byte limit.`);
    return [];
  }

  const files: GitHubFile[] = [];
  let offset = 0;

  while (offset + 512 <= tar.length) {
    const name = parseTarString(tar, offset, 100);
    if (!name) break;

    const typeFlag = parseTarString(tar, offset + 156, 1);
    const size = parseTarSize(tar, offset + 124);
    const dataStart = offset + 512;
    if (!Number.isFinite(size) || size < 0 || dataStart + size > tar.length) {
      warnings.push("Malformed tar entry exceeds the artifact bounds."); break;
    }

    if (typeFlag === '' || typeFlag === '0') {
      const truncated = size > MAX_EXTRACTED_FILE_BYTES;
      const contentBuffer = tar.subarray(dataStart, dataStart + Math.min(size, MAX_EXTRACTED_FILE_BYTES));
      const content = decodeTextContent(contentBuffer, truncated);
      if (content !== null) {
        if (truncated) warnings.push(`Tarball file ${name} was truncated to ${MAX_EXTRACTED_FILE_BYTES} bytes.`);
        files.push({
          name: basename(name),
          path: `${pathPrefix}/tarball/${name}`,
          content,
        });
      }
    }

    if (!['', '0', '5'].includes(typeFlag)) warnings.push(`Unsupported tar entry ${name} (type ${typeFlag}).`);
    offset = dataStart + Math.ceil(size / 512) * 512;
  }

  return selectArtifactFiles(files, warnings);
}

function extractZip(buffer: Buffer, pathPrefix: string, warnings: string[]): GitHubFile[] {
  const files: GitHubFile[] = [];
  const eocdOffset = buffer.lastIndexOf(Buffer.from([0x50, 0x4b, 0x05, 0x06]));

  if (eocdOffset < 0 || eocdOffset + 22 > buffer.length) {
    warnings.push('VSIX central directory could not be found.');
    return files;
  }

  const entryCount = buffer.readUInt16LE(eocdOffset + 10);
  const centralDirectoryOffset = buffer.readUInt32LE(eocdOffset + 16);
  let offset = centralDirectoryOffset;
  let inflatedBytes = 0;
  let processedEntries = 0;

  for (let index = 0; index < entryCount && offset + 46 <= buffer.length; index += 1) {
    const signature = buffer.readUInt32LE(offset);
    if (signature !== 0x02014b50) {
      warnings.push('VSIX central directory contains an unsupported entry.');
      break;
    }

    processedEntries++;
    const compression = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const uncompressedSize = buffer.readUInt32LE(offset + 24);
    const fileNameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localHeaderOffset = buffer.readUInt32LE(offset + 42);
    if (offset + 46 + fileNameLength + extraLength + commentLength > buffer.length) {
      warnings.push('Malformed VSIX central entry exceeds archive bounds.'); break;
    }
    const fileName = buffer.subarray(offset + 46, offset + 46 + fileNameLength).toString('utf8');

    if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff || localHeaderOffset === 0xffffffff) {
      warnings.push(`Skipped ZIP64 VSIX entry ${fileName}.`);
      offset += 46 + fileNameLength + extraLength + commentLength;
      continue;
    }

    if (!fileName.endsWith('/') && uncompressedSize <= MAX_EXTRACTED_FILE_BYTES) {
      try {
        if (localHeaderOffset + 30 > buffer.length || buffer.readUInt32LE(localHeaderOffset) !== 0x04034b50) {
          warnings.push(`Skipped malformed VSIX entry ${fileName}.`);
        } else {
          const localNameLength = buffer.readUInt16LE(localHeaderOffset + 26);
          const localExtraLength = buffer.readUInt16LE(localHeaderOffset + 28);
          const dataStart = localHeaderOffset + 30 + localNameLength + localExtraLength;
          const dataEnd = dataStart + compressedSize;
          if (dataEnd > buffer.length) throw new Error('Entry exceeds archive bounds');
          const compressed = buffer.subarray(dataStart, dataEnd);
          const contentBuffer = compression === 0
            ? compressed
            : compression === 8
              ? inflateRawSync(compressed, { maxOutputLength: MAX_EXTRACTED_FILE_BYTES })
              : null;

          if (contentBuffer) {
            if (contentBuffer.length > MAX_EXTRACTED_FILE_BYTES) throw new Error('VSIX entry exceeds the output limit');
            inflatedBytes += contentBuffer.length;
            if (inflatedBytes > MAX_INFLATED_ARTIFACT_BYTES) { warnings.push('VSIX total decompression limit reached.'); break; }
            if (contentBuffer.length !== uncompressedSize) throw new Error('Entry size mismatch');
            const content = decodeTextContent(contentBuffer);
            if (content !== null) files.push({
              name: basename(fileName),
              path: `${pathPrefix}/vsix/${fileName}`,
              content,
            });
          } else {
            warnings.push(`Skipped VSIX entry ${fileName} with unsupported compression method ${compression}.`);
          }
        }
      } catch {
        warnings.push(`Failed to decompress VSIX entry ${fileName}.`);
      }
    } else if (!fileName.endsWith('/')) {
      warnings.push(`Skipped VSIX entry ${fileName} larger than ${MAX_EXTRACTED_FILE_BYTES} bytes.`);
    }

    offset += 46 + fileNameLength + extraLength + commentLength;
  }

  if (processedEntries < entryCount) warnings.push("Truncated VSIX central directory.");
  return selectArtifactFiles(files, warnings);
}

interface RegistryMetadata {
  name?: string; version?: string; namespace?: string;
  'dist-tags'?: Record<string, string>;
  versions?: Record<string, PackageManifest>;
  manifest?: PackageManifest;
  engines?: { vscode?: string };
  categories?: unknown; activationEvents?: unknown; contributes?: unknown;
  repository?: unknown; time?: unknown; maintainers?: unknown;
  files?: { download?: string; downloadUrl?: string }; downloadUrl?: string;
}
interface PackageManifest {
  name?: string; version?: string; maintainers?: unknown;
  repository?: unknown; homepage?: unknown; bugs?: unknown;
  dist?: { tarball?: string };
}

export class RegistryFetcher {
  static isNpmUrl(input: string): boolean {
    return /^(?:https?:\/\/(?:www\.)?npmjs\.com\/package\/|pkg:npm\/|npm:)/i.test(input.trim());
  }

  static isOpenVsxUrl(input: string): boolean {
    return parseOpenVsxUrl(input) !== null;
  }

  static async fetchNpm(input: string, budget = new RemoteBudget()): Promise<FetchBundle> {
    const spec = parseNpmSpecifier(input);
    if (!spec) throw new Error('Invalid npm package URL or package URL');
    const warnings: string[] = [];
    const fetchedAt = new Date().toISOString();

    const registryHosts = ['registry.npmjs.org'];
    const headers = { 'User-Agent': 'SkillScan-Security-Scanner/1.0' };
    const response = await trustedFetch(`https://registry.npmjs.org/${encodePackageName(spec.name)}`, registryHosts, budget, { headers });

    if (!response.ok) throw new Error(`Failed to fetch npm metadata: ${response.statusText}`);

    let metadata: RegistryMetadata | undefined;
    try {
      metadata = await readBoundedJson(response) as RegistryMetadata;
    } catch (error) {
      if (!(error instanceof ResponseTooLargeError)) throw error;
    }

    let version: string | undefined;
    let packageJson: PackageManifest | undefined;
    let time = metadata?.time as Record<string, string> | undefined;
    let publishedAtSource: 'registry' | 'tarball-last-modified' | undefined = time ? 'registry' : undefined;

    if (metadata) {
      version = spec.version || metadata['dist-tags']?.latest;
      packageJson = metadata.versions?.[version ?? ''];
    } else {
      // Popular packages publish multi-megabyte packuments (react ~7 MB, next ~31 MB).
      // Read the small per-version manifest instead; publish time then comes from the tarball.
      const manifestResponse = await trustedFetch(
        `https://registry.npmjs.org/${encodePackageName(spec.name)}/${encodeURIComponent(spec.version || 'latest')}`,
        registryHosts, budget, { headers },
      );
      if (manifestResponse.ok) {
        packageJson = await readBoundedJson(manifestResponse) as PackageManifest;
        version = packageJson.version;
      }
    }

    if (!packageJson || !version) throw new Error(`npm package version not found: ${spec.name}@${version ?? spec.version ?? 'latest'}`);

    const files: GitHubFile[] = [
      {
        name: 'package.json',
        path: `npm:${spec.name}@${version}/package.json`,
        content: JSON.stringify(packageJson, null, 2),
      },
    ];

    const tarballUrl = packageJson.dist?.tarball;
    if (tarballUrl) {
      const artifact = await fetchArtifact(tarballUrl, warnings, registryHosts, budget);
      if (artifact) {
        files.push(...extractTgz(artifact.bytes, `npm:${spec.name}@${version}`, warnings));
        // The CDN stores the tarball at publish, so Last-Modified is never earlier than the
        // publish time. Using it errs toward flagging a version as fresh, not hiding it.
        const storedAt = artifact.lastModified ? Date.parse(artifact.lastModified) : NaN;
        if (!time?.[version] && Number.isFinite(storedAt)) {
          time = { ...time, [version]: new Date(storedAt).toISOString() };
          publishedAtSource = 'tarball-last-modified';
        }
      }
    } else {
      warnings.push('npm registry metadata did not include a tarball URL.');
    }

    if (!metadata && !time?.[version]) warnings.push('npm publish time was unavailable; the registry freshness check did not run.');

    files.splice(1, 0, {
      name: 'npm-metadata.json',
      path: `npm:${spec.name}@${version}/npm-metadata.json`,
      content: JSON.stringify({
        name: metadata?.name ?? packageJson.name ?? spec.name,
        version,
        distTags: metadata?.['dist-tags'],
        time,
        publishedAtSource,
        maintainers: metadata?.maintainers ?? packageJson.maintainers,
        repository: packageJson.repository,
        homepage: packageJson.homepage,
        bugs: packageJson.bugs,
        dist: packageJson.dist,
      }, null, 2),
    });

    return {
      files,
      sourceType: 'npm',
      fetchedAt,
      partial: warnings.length > 0,
      warnings,
    };
  }

  static async fetchOpenVsx(input: string, budget = new RemoteBudget()): Promise<FetchBundle> {
    const spec = parseOpenVsxUrl(input);
    if (!spec) throw new Error('Invalid OpenVSX extension URL');
    const warnings: string[] = [];
    const fetchedAt = new Date().toISOString();

    const versionPath = spec.version ? `/${spec.version}` : '';
    const response = await trustedFetch(`https://open-vsx.org/api/${spec.namespace}/${spec.extension}${versionPath}`, ['open-vsx.org'], budget, {
      headers: { 'User-Agent': 'SkillScan-Security-Scanner/1.0' },
    });

    if (!response.ok) throw new Error(`Failed to fetch OpenVSX metadata: ${response.statusText}`);

    const metadata = await readBoundedJson(response) as RegistryMetadata;
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

    const files: GitHubFile[] = [
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

    const downloadUrl = metadata.files?.download || metadata.files?.downloadUrl || metadata.downloadUrl;
    if (downloadUrl) {
      const artifact = (await fetchArtifact(downloadUrl, warnings, ['open-vsx.org', 'openvsx.eclipsecontent.org'], budget))?.bytes;
      if (artifact) {
        files.push(...extractZip(artifact, `openvsx:${spec.namespace}.${spec.extension}`, warnings));
      }
    } else {
      warnings.push('OpenVSX metadata did not include a VSIX download URL.');
    }

    return {
      files,
      sourceType: 'openvsx',
      fetchedAt,
      partial: warnings.length > 0,
      warnings,
    };
  }
}
