# SkillScan

SkillScan 0.1.0 is a static heuristic security scanner for skills, MCP servers,
npm packages, OpenVSX extensions, and GitHub Actions workflows. Findings support
review; a PASS is not a security certification. Do not execute scanned payloads.

## Commands and runtime

Use the pinned pnpm version in package.json (`pnpm@10.34.6`). The web application
uses Next.js 15, React 18, TypeScript 5, Tailwind 3, and Vercel Node.js 24.
The bundled CLI requires Node.js 20.3 or later and has no runtime dependencies.

- `pnpm dev`: development web server
- `pnpm build` / `pnpm start`: production web build / server
- `pnpm lint`: ESLint with zero warnings allowed
- `pnpm typecheck`: generate route types and check TypeScript
- `pnpm test`: scanner, fetch boundaries, coverage, CLI, API, and SARIF tests
- `pnpm eval:malicious`: check the malicious fixture corpus
- `pnpm skillscan <target>`: run the CLI from source
- `pnpm build:cli`: bundle packages/cli/dist/cli.js

## Shared implementation

`lib/scanner.ts` contains the 29 heuristic checks and scoring. The web API and CLI
share it. `lib/targets.ts` resolves remote targets; `lib/github.ts` and
`lib/registry.ts` fetch content. `lib/remote.ts` enforces trusted destinations,
streamed size limits, request counts, deadlines, and cancellation. `lib/files.ts`
decodes text independent of filename extensions. `lib/local.ts` walks local paths.
`lib/coverage.ts` prevents partial scans from receiving PASS. `lib/exclusions.ts`
applies explicit CLI scope exclusions, and `lib/sarif.ts` exports findings.

`app/page.tsx` is the web scanner. `app/api/scan/route.ts` accepts exactly one string
`code` or `url`, bounds request bodies, and returns the shared result including
coverage warnings. `cli/run.ts` implements the CLI; `action.yml` wraps it for CI.

The private root package is the Next.js application. Only `packages/cli`
(@maxwellyoung/skillscan) is publishable. Build its bundle before packing; inspect
the tarball before publication. Keep cli/version.ts and packages/cli/package.json
versions synchronized. Do not add root engines/bin/files: root engines can override
Vercel's runtime setting.

## Security and coverage contracts

- Validate parsed HTTPS destinations before every credential-bearing request.
  GitHub redirects fail closed. Registry redirects validate every hop against
  explicit npm/OpenVSX/CDN hosts and carry no credentials.
- Optional GITHUB_TOKEN stays server-side and is only sent to trusted GitHub hosts.
  Use least privilege. Never log secrets, request bodies, or fetched payloads.
- Remote scans have an 80-request ceiling, 45-second deadline, and at most ten
  seconds per request. Metadata, downloads, and decompression have separate limits.
- GitHub scans include up to 50 text files, local scans 2,000, and registry archives
  40, with manifests and entry points prioritized. Limits/fetch failures are
  disclosed as partial coverage. Partial clean scans require review and exit 2.
- UTF-8 and BOM-marked UTF-16 text are inspected; binary content is skipped.
  Local directory scans skip .git/node_modules directories and do not follow
  symlinks. Explicit `--exclude` globs are reported. Target-owned files cannot
  silently suppress findings.
- API limits are best-effort per process: four concurrent scans; five remote or
  thirty pasted-code scans per IP per minute. Serverless instances do not share
  state. Fleet-wide abuse protection requires an edge/shared limiter.
- Static regex checks can produce false positives and miss sophisticated attacks.
  High-risk executable examples can produce findings; explicitly exclude fixture
  paths when appropriate rather than weakening checks globally.

## Verification and release

CI runs lint, generated-type checking, tests, the malicious evaluation, CLI
packaging smoke checks, a production build, and composite-action tests. Pin action
references to full commit SHAs. Use the repository lockfile and explicit build
approvals in pnpm-workspace.yaml.

A current audit contains one unpatched development-only braces advisory through
eslint-config-next / fast-glob / micromatch. These glob patterns come from trusted
lint configuration, not the public scan endpoint. Keep the advisory visible;
do not call the complete dependency graph vulnerability-free.

Push, merge, deployment, npm publication, and external messages require the user's
current authorization. Distinguish local checks, hosted CI, deployment identity,
live behavior, and registry publication receipts in release claims.
