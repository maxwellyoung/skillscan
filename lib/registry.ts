import { gunzipSync, inflateRawSync } from 'node:zlib';
import { GitHubFile, FetchBundle } from './types';

const MAX_ARTIFACT_BYTES = 6_000_000;
const MAX_EXTRACTED_FILES = 40;
const MAX_EXTRACTED_FILE_BYTES = 180_000;
const TEXT_EXTENSIONS = new Set([
  '.js',
  '.cjs',
  '.mjs',
  '.ts',
  '.tsx',
  '.jsx',
  '.json',
  '.yml',
  '.yaml',
  '.sh',
  '.py',
  '.rb',
  '.go',
  '.rs',
  '.md',
  '.txt',
  '.env',
]);
const IMPORTANT_BASENAMES = new Set([
  'package.json',
  'extension.js',
  'main.js',
  'index.js',
  'readme.md',
  'license',
]);

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

function extensionFor(filePath: string): string {
  const match = filePath.toLowerCase().match(/(\.[a-z0-9]+)$/);
  return match?.[1] || '';
}

function basename(filePath: string): string {
  return filePath.split('/').pop()?.toLowerCase() || filePath.toLowerCase();
}

function shouldExtractTextFile(filePath: string): boolean {
  return TEXT_EXTENSIONS.has(extensionFor(filePath)) || IMPORTANT_BASENAMES.has(basename(filePath));
}

async function fetchArtifact(url: string, warnings: string[]): Promise<Buffer | null> {
  try {
    const response = await fetch(url, {
      headers: { 'User-Agent': 'SkillScan-Security-Scanner/1.0' },
    });

    if (!response.ok) {
      warnings.push(`Artifact fetch failed: ${response.status} ${response.statusText}`);
      return null;
    }

    const contentLength = response.headers.get('content-length');
    if (contentLength && Number(contentLength) > MAX_ARTIFACT_BYTES) {
      warnings.push(`Artifact skipped because it is larger than ${MAX_ARTIFACT_BYTES} bytes.`);
      return null;
    }

    const arrayBuffer = await response.arrayBuffer();
    if (arrayBuffer.byteLength > MAX_ARTIFACT_BYTES) {
      warnings.push(`Artifact skipped because it exceeded ${MAX_ARTIFACT_BYTES} bytes after download.`);
      return null;
    }

    return Buffer.from(arrayBuffer);
  } catch (error) {
    warnings.push(`Artifact fetch failed: ${error instanceof Error ? error.message : 'unknown error'}`);
    return null;
  }
}

function parseTarString(buffer: Buffer, start: number, length: number): string {
  return buffer.subarray(start, start + length).toString('utf8').split('\0')[0].trim();
}

function parseTarSize(buffer: Buffer, start: number): number {
  const raw = parseTarString(buffer, start, 12);
  return Number.parseInt(raw || '0', 8) || 0;
}

function extractTgz(buffer: Buffer, pathPrefix: string, warnings: string[]): GitHubFile[] {
  let tar: Buffer;
  try {
    tar = gunzipSync(buffer);
  } catch {
    warnings.push('npm tarball could not be decompressed.');
    return [];
  }

  const files: GitHubFile[] = [];
  let offset = 0;

  while (offset + 512 <= tar.length && files.length < MAX_EXTRACTED_FILES) {
    const name = parseTarString(tar, offset, 100);
    if (!name) break;

    const typeFlag = parseTarString(tar, offset + 156, 1);
    const size = parseTarSize(tar, offset + 124);
    const dataStart = offset + 512;

    if ((typeFlag === '' || typeFlag === '0') && shouldExtractTextFile(name)) {
      const truncated = size > MAX_EXTRACTED_FILE_BYTES;
      const contentBuffer = tar.subarray(dataStart, dataStart + Math.min(size, MAX_EXTRACTED_FILE_BYTES));
      files.push({
        name: basename(name),
        path: `${pathPrefix}/tarball/${name}`,
        content: contentBuffer.toString('utf8') + (truncated ? '\n/* truncated by SkillScan */' : ''),
      });
    }

    offset = dataStart + Math.ceil(size / 512) * 512;
  }

  if (files.length >= MAX_EXTRACTED_FILES) {
    warnings.push(`Artifact scan limited to first ${MAX_EXTRACTED_FILES} text files.`);
  }

  return files;
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

  for (let index = 0; index < entryCount && offset + 46 <= buffer.length && files.length < MAX_EXTRACTED_FILES; index += 1) {
    const signature = buffer.readUInt32LE(offset);
    if (signature !== 0x02014b50) {
      warnings.push('VSIX central directory contains an unsupported entry.');
      break;
    }

    const compression = buffer.readUInt16LE(offset + 10);
    const compressedSize = buffer.readUInt32LE(offset + 20);
    const uncompressedSize = buffer.readUInt32LE(offset + 24);
    const fileNameLength = buffer.readUInt16LE(offset + 28);
    const extraLength = buffer.readUInt16LE(offset + 30);
    const commentLength = buffer.readUInt16LE(offset + 32);
    const localHeaderOffset = buffer.readUInt32LE(offset + 42);
    const fileName = buffer.subarray(offset + 46, offset + 46 + fileNameLength).toString('utf8');

    if (compressedSize === 0xffffffff || uncompressedSize === 0xffffffff || localHeaderOffset === 0xffffffff) {
      warnings.push(`Skipped ZIP64 VSIX entry ${fileName}.`);
      offset += 46 + fileNameLength + extraLength + commentLength;
      continue;
    }

    if (shouldExtractTextFile(fileName) && uncompressedSize <= MAX_EXTRACTED_FILE_BYTES) {
      try {
        if (localHeaderOffset + 30 > buffer.length || buffer.readUInt32LE(localHeaderOffset) !== 0x04034b50) {
          warnings.push(`Skipped malformed VSIX entry ${fileName}.`);
        } else {
          const localNameLength = buffer.readUInt16LE(localHeaderOffset + 26);
          const localExtraLength = buffer.readUInt16LE(localHeaderOffset + 28);
          const dataStart = localHeaderOffset + 30 + localNameLength + localExtraLength;
          const dataEnd = dataStart + compressedSize;
          const compressed = buffer.subarray(dataStart, dataEnd);
          const contentBuffer = compression === 0
            ? compressed
            : compression === 8
              ? inflateRawSync(compressed)
              : null;

          if (contentBuffer) {
            files.push({
              name: basename(fileName),
              path: `${pathPrefix}/vsix/${fileName}`,
              content: contentBuffer.toString('utf8'),
            });
          } else {
            warnings.push(`Skipped VSIX entry ${fileName} with unsupported compression method ${compression}.`);
          }
        }
      } catch {
        warnings.push(`Failed to decompress VSIX entry ${fileName}.`);
      }
    }

    offset += 46 + fileNameLength + extraLength + commentLength;
  }

  if (files.length >= MAX_EXTRACTED_FILES) {
    warnings.push(`VSIX scan limited to first ${MAX_EXTRACTED_FILES} stored text files.`);
  }

  return files;
}

export class RegistryFetcher {
  static isNpmUrl(input: string): boolean {
    return /^(?:https?:\/\/(?:www\.)?npmjs\.com\/package\/|pkg:npm\/|npm:)/i.test(input.trim());
  }

  static isOpenVsxUrl(input: string): boolean {
    return /open-vsx\.org\/extension\//i.test(input.trim());
  }

  static async fetchNpm(input: string): Promise<FetchBundle> {
    const spec = parseNpmSpecifier(input);
    if (!spec) throw new Error('Invalid npm package URL or package URL');
    const warnings: string[] = [];
    const fetchedAt = new Date().toISOString();

    const response = await fetch(`https://registry.npmjs.org/${encodePackageName(spec.name)}`, {
      headers: { 'User-Agent': 'SkillScan-Security-Scanner/1.0' },
    });

    if (!response.ok) throw new Error(`Failed to fetch npm metadata: ${response.statusText}`);

    const metadata = await response.json();
    const version = spec.version || metadata['dist-tags']?.latest;
    const packageJson = metadata.versions?.[version];

    if (!packageJson) throw new Error(`npm package version not found: ${spec.name}@${version ?? 'latest'}`);

    const files: GitHubFile[] = [
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

    const tarballUrl = packageJson.dist?.tarball;
    if (tarballUrl) {
      const artifact = await fetchArtifact(tarballUrl, warnings);
      if (artifact) {
        files.push(...extractTgz(artifact, `npm:${spec.name}@${version}`, warnings));
      }
    } else {
      warnings.push('npm registry metadata did not include a tarball URL.');
    }

    return {
      files,
      sourceType: 'npm',
      fetchedAt,
      partial: warnings.length > 0,
      warnings,
    };
  }

  static async fetchOpenVsx(input: string): Promise<FetchBundle> {
    const spec = parseOpenVsxUrl(input);
    if (!spec) throw new Error('Invalid OpenVSX extension URL');
    const warnings: string[] = [];
    const fetchedAt = new Date().toISOString();

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
      const artifact = await fetchArtifact(downloadUrl, warnings);
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
