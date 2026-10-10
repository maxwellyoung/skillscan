import type { FetchBundle } from './types';

/** Explicit opt-in scope selection; target-controlled files cannot suppress findings. */
export function excludeFiles(bundle: FetchBundle, patterns: string[]): { bundle: FetchBundle; excluded: number } {
  if (patterns.length > 50 || patterns.some(pattern => !pattern || pattern.length > 200)) throw new Error('Use at most 50 nonempty exclusion patterns of 200 characters or fewer');
  const expressions = patterns.map(pattern => {
    let source = '^';
    for (let i = 0; i < pattern.length; i++) {
      const c = pattern[i];
      if (c === '*' && pattern[i + 1] === '*') {
        i++;
        if (pattern[i + 1] === '/') { i++; source += '(?:.*/)?'; } else source += '.*';
      } else if (c === '*') source += '[^/]*';
      else if (c === '?') source += '[^/]';
      else source += c.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    }
    return new RegExp(source + '$');
  });
  const files = bundle.files.filter(file => !expressions.some(expression => expression.test(file.path)));
  const excluded = bundle.files.length - files.length;
  return { excluded, bundle: { ...bundle, files, warnings: excluded ? [...bundle.warnings, `Explicit exclusions removed ${excluded} files from the scan scope.`] : bundle.warnings } };
}
