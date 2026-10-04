# Status

Last updated: 2026-10-04
Status: Active
Lifecycle: product-hardening

## Current State

- Skill/security scanning tool is being hardened as a public developer-security product.
- Scanner now includes harsher scoring, cross-line secret exfiltration detection, lifecycle-script analysis, hostile skill-instruction checks, persistence/system-modification detection, adversarial evals, and a local installed-skills false-positive corpus.
- `skillscan` CLI (local paths plus GitHub/ClawdHub/npm/OpenVSX targets) with text, `--json`, and SARIF 2.1.0 output, `--fail-on`, and 0/1/2 exit codes. Shares `lib/scanner.ts`, `lib/targets.ts`, and `lib/files.ts` with the API route.
- Composite GitHub Action (`action.yml`) runs the CLI and optionally uploads SARIF to code scanning. CI now runs typecheck, tests, the malicious-fixture eval, and dogfoods the action.
- GitHub repo scans now include `.github/workflows` (a substring `.git` check previously skipped it).

## Revive When

- Add richer evidence extraction and package manifest heuristics.

## Next Useful Move

- Publish the CLI to npm: the unscoped `skillscan` name is owned by another maintainer (dejimarquis/SkillScan), so pick a scoped name (e.g. `@maxwellyoung/skillscan`) keeping the `skillscan` bin; remove `private`, add a LICENSE file, then switch the action from `npx tsx` to the published package.
- Expand the eval corpus with real malicious repositories; malicious-fixture regressions now run in CI.
