# SkillScan

Static security scanning for AI skills, MCP servers, npm packages, VS Code extensions, and GitHub Actions workflows. Use it from the web UI, the `POST /api/scan` API, the `skillscan` CLI, or the GitHub Action (JSON and SARIF output).

SkillScan checks local skill instructions, GitHub-hosted code, npm package metadata, OpenVSX extension metadata, GitHub Actions workflows, and MCP server repositories for risky patterns before you install or run them. It is intentionally fast and boring: static analysis, clear findings, and remediation notes.

## The ClawdHub Supply Chain Crisis

Nick Saraev's viral "It Got Worse - Clawdbot" video exposed:
- **No vetting process** on ClawdHub - malicious skills published freely
- **Thousands of compromised Clawdbot instances** via Shodan scanning
- **API token theft** through malicious skill instructions
- **Supply chain attacks** via skill repositories

His advice? "Read every file or feed files to AI to check safety." **We automate that.**

## What it demonstrates

- Static analysis for a fast-moving AI tooling ecosystem.
- GitHub URL, npm package URL, OpenVSX extension URL, file, and direct-code scanning.
- Risk scoring with severity, category, location, snippet, and remediation.
- A focused security UI that avoids hiding findings behind generic AI summaries.
- A public example of building small developer tools with practical failure modes.

## Features

- ClawdHub and Claude Code skill attack detection.
- MCP server and GitHub repository scanning.
- npm package metadata and lifecycle-script scanning.
- VS Code/OpenVSX extension manifest and source-behavior scanning.
- GitHub Actions workflow scanning for release-pipeline and PR-trigger risks.
- 0-100 security score with A-F grades.
- Pattern checks for shell execution, network access, file-system access, prompt injection, credential patterns, data exfiltration, package install hooks, extension activation behavior, and CI workflow trust boundaries.
- No AI inference required for the core scan.
- CLI with human, JSON, and SARIF 2.1.0 output plus CI exit codes; composite GitHub Action with optional code scanning upload.
- Explicit install verdicts: pass, manual review, or block install.
- Committed malicious fixture corpus for token exfiltration, malicious install hooks, hostile skill instructions, and persistence attempts.
- False-positive eval against installed local Codex, agents, and plugin skills.

## Security Checks

Based on real ClawdHub compromises and supply chain attacks:

1. **Shell Command Execution** - `exec()`, `spawn()`, `child_process` usage
2. **Network Requests** - HTTP/HTTPS calls to external URLs
3. **File System Access** - Reading/writing files outside workspace
4. **Environment Variable Access** - Accessing `process.env` for secrets
5. **Dynamic Code Execution** - `eval()`, Function constructor usage
6. **Base64 Encoding** - Potential data exfiltration encoding
7. **Obfuscated Code** - Minified, hex-encoded, or suspicious patterns
8. **Prompt Injection** - "Ignore previous instructions" type patterns
9. **API Token Stealing** - Attempts to extract OpenAI/Anthropic keys ⭐ NEW
10. **Credential Patterns** - Hardcoded API keys, passwords, tokens
11. **Data Exfiltration Webhooks** - Webhook URLs for stealing data ⭐ NEW
12. **Package Analysis** - Typosquatting, malicious packages in package.json
13. **Secret Exfiltration Flow** - Cross-line detection when sensitive env vars and outbound transmission appear together
14. **Persistence & System Modification** - Startup jobs, SSH access files, curl-pipe-shell, destructive deletes, broad chmod/chown
15. **Malicious Skill Instructions** - Instruction files combining broad tool access, secrets, outbound transmission, or override language
16. **Dangerous Lifecycle Scripts** - Critical scoring for install hooks that run network, shell, secret, or filesystem-modifying behavior
17. **npm Package Provenance** - Missing repository/homepage metadata and larger CLI install surfaces
18. **Dependency Confusion Signals** - Suspicious dependency names and package-name lookalikes
19. **VS Code Extension Activation** - Broad activation events such as `*`, startup, workspace, and language-wide activation
20. **VS Code Extension Runtime Behavior** - Terminal execution, workspace file access, clipboard access, and secret exfiltration flows
21. **Known Compromised Package Versions** - Incident-intelligence matches for public npm supply-chain compromises
22. **Registry Freshness Cooldown** - Fresh package versions and high-impact packages less than 7 days old
23. **Package Integrity Metadata** - Missing integrity hashes or weak registry metadata
24. **GitHub Actions Trust Boundaries** - `pull_request_target`, checkout, write permissions, and secret access combinations
25. **GitHub Actions Pinning** - Third-party actions referenced by mutable tags instead of full commit SHAs
26. **npm Tarball Extraction** - Published package artifacts are downloaded, unpacked, and scanned beyond registry metadata
27. **VSIX Artifact Extraction** - OpenVSX extension packages are downloaded, unpacked, and scanned beyond marketplace metadata
28. **Runtime Downloader Detection** - GitHub Releases, Bun/runtime bootstraps, and second-stage payload download patterns
29. **Import-Time Payload Detection** - Python/JavaScript import-time secret reads, outbound exfiltration, and optional dependency bootstraps

## Evaluation Harness

The scanner has adversarial evals for cases that should fail hard and benign cases that should stay quiet.

Committed malicious fixtures live in `test/fixtures/malicious` and cover:

- Multi-line secret exfiltration through outbound requests.
- `postinstall` scripts that fetch and execute remote code.
- `SKILL.md` instructions that request broad tools, secrets, and webhook transmission.
- Persistence attempts through launch agents, SSH authorized keys, and broad file permission changes.
- npm packages that exfiltrate environment variables during install.
- VS Code extensions with broad activation, terminal execution, clipboard access, and outbound secret transmission.
- Known-compromised npm package/version metadata.
- GitHub Actions workflows with `pull_request_target`, write permissions, unpinned third-party actions, and npm publish secrets.
- npm tarball and VSIX artifact payloads, including runtime downloaders, fake bundled assets, and import-time exfiltration.

Those fixtures must all produce `riskLevel: "block"`:

```bash
pnpm eval:malicious
```

The unit suite also covers benign cases that should not become noisy:

- Security documentation that mentions tokens without being treated as executable theft.
- Local app code using `NEXT_PUBLIC_*` env vars and relative API routes.

Run them with:

```bash
pnpm test
```

For a local false-positive corpus, scan the installed Codex, agents, and plugin skills:

```bash
pnpm eval:local-skills
```

That command summarizes findings with home paths redacted and exits nonzero if any critical or high-risk finding appears.

## Usage

### Scan ClawdHub Skill
```
https://claudhub.ai/skills/username/skillname
```

### Scan GitHub Repository
```
https://github.com/username/repo
```

### Scan npm Package
```
https://www.npmjs.com/package/package-name
pkg:npm/package-name@1.2.3
```

### Scan OpenVSX Extension
```
https://open-vsx.org/extension/publisher/extension-name
```

### Scan Single File
```
https://github.com/username/repo/blob/main/file.ts
```

### Scan Code Directly
Paste skill instructions, package manifests, extension manifests, GitHub Actions workflows, or source code directly into the scanner.

## Command line

The `skillscan` CLI runs the same scanner as the web app and API (`lib/scanner.ts`), entirely offline for local paths. No AI, no account, and local files are never uploaded.

> Not yet published to npm. Until it is, run it from a checkout:
> `pnpm install && pnpm skillscan <target>` (or `pnpm build:cli && node dist/cli/skillscan.js <target>`).

```bash
skillscan ./my-skill                     # Claude Code skill folder
skillscan ./my-mcp-server                # MCP server repo (includes .github/workflows)
skillscan ./my-extension --json          # VS Code extension folder, JSON result
skillscan . --sarif -o skillscan.sarif   # SARIF 2.1.0 for GitHub code scanning
skillscan pkg:npm/left-pad@1.3.0         # npm package (metadata + tarball)
skillscan https://github.com/owner/repo  # GitHub repo, tree, or blob URL
skillscan https://open-vsx.org/extension/publisher/name
```

Local directories are walked recursively (skipping `node_modules` and `.git`, not following symlinks) using the same file-selection rules as GitHub scans, capped at 2,000 files and 250 KB per file; anything truncated is reported as a scan warning. A path to a single file is always scanned, whatever its extension.

| Option | Meaning |
| --- | --- |
| `--json` | Full scan result as JSON (same shape as `POST /api/scan`) |
| `--sarif` | SARIF 2.1.0 log: one rule per finding category, results with file/line/snippet locations and `security-severity` for code scanning |
| `-o, --output <file>` | Write the report to a file; the human-readable report still goes to stdout |
| `--fail-on <severity>` | `critical` (default, equivalent to the "block install" verdict), `high`, `medium`, `low`, `info`, or `none` |
| `--verbose` | Also list informational findings in text output |

Exit codes: `0` nothing at or above `--fail-on`, `1` at least one finding at or above `--fail-on`, `2` usage error or the scan could not run.

## GitHub Action

`action.yml` is a composite action that runs the CLI on a path and can upload the SARIF report to GitHub code scanning.

```yaml
name: SkillScan
on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write   # only needed when upload-sarif is true

jobs:
  skillscan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: maxwellyoung/skillscan@<commit-sha>   # pin to a full commit SHA
        with:
          path: .                 # local path or supported URL
          fail-on: critical       # critical | high | medium | low | info | none
          upload-sarif: true      # needs code scanning enabled on the repo
```

| Input | Default | Description |
| --- | --- | --- |
| `path` | `.` | Local path or supported URL to scan |
| `fail-on` | `critical` | Severity threshold that fails the step |
| `sarif-file` | `skillscan.sarif` | Where the SARIF report is written |
| `upload-sarif` | `false` | Upload via `github/codeql-action/upload-sarif` |
| `category` | `skillscan` | Code scanning category for the upload |
| `node-version` | `22` | Node.js used to run the scanner |

Outputs: `exit-code` (`0`/`1`/`2`) and `sarif-file`. SARIF is uploaded before the fail-on check, so findings reach code scanning even when the step fails. The action runs the TypeScript CLI from its own checkout with `npx tsx@4.22.3`, so it downloads `tsx` from npm at run time; it does not send scanned files anywhere.

## How skillscan compares

Checked against each project's own README, docs, and source on 2026-10-04. Cells marked "unverified" could not be confirmed from a primary source.

| | SkillScan | [Snyk Agent Scan](https://github.com/snyk/agent-scan) (formerly Invariant Labs MCP-Scan) | [Cisco MCP Scanner](https://github.com/cisco-ai-defense/mcp-scanner) |
| --- | --- | --- | --- |
| Approach | Static regex/heuristic rules over files | Discovers agent configs, connects to MCP servers, sends tool descriptions and skill content to the Snyk Agent Scan API for analysis | Pluggable analyzers: YARA rules, regex, Cisco AI Defense API, LLM-as-judge, behavioral code analysis |
| Works fully offline, no API key | Yes for local paths (remote targets fetch from GitHub/npm/OpenVSX) | No: requires a Snyk API token; the CLI only lists components without analysis | Yes with `--analyzers yara` (and the `static` subcommand); the default analyzers (`api,yara,llm`) need API keys |
| Uses an LLM | No | Unverified (server-side engine not documented) | Optional (LLM and behavioral analyzers; local models supported) |
| Connects to / runs live MCP servers | No | Yes (with consent prompt) | Yes (`remote`, `stdio`, `config` subcommands) |
| Claude Code skills (`SKILL.md`) | Yes | Yes | No (Cisco ships a separate `skill-scanner` project) |
| MCP server source code | Yes (pattern rules) | No | Yes (behavioral analyzer, YARA) |
| npm packages | Yes (registry metadata + tarball contents) | No | Yes (`npm-scan`) |
| VS Code extensions | Yes (local folders, OpenVSX + VSIX contents) | Only MCP servers/skills bundled in extensions | No |
| GitHub Actions workflows | Yes | No | No |
| JSON output | Yes | Yes (`--json`, schema marked experimental) | Yes (`raw` format) |
| SARIF output | Yes | No | No |
| Official GitHub Action | Yes (`action.yml`) | No (`--ci` flag for CI use) | No |
| Non-zero exit on findings | Yes (`--fail-on`) | Yes (exit 1 when risks remain in CI mode) | Unverified |
| Runtime guard / proxy | No | Agent Guard hooks that forward events to Snyk Evo (enterprise) | No |
| Language / install | TypeScript; from source today (npm package not yet published) | Python; `uvx snyk-agent-scan@latest` or standalone binaries | Python; `uv tool install cisco-ai-mcp-scanner` or pip |
| License | MIT | Apache-2.0 | Apache-2.0 |

Where the others are stronger: both can inspect live MCP servers and their actual tool descriptions, Cisco's behavioral analyzer does cross-file dataflow for Python, and Snyk Agent Scan auto-discovers agent configs across many clients. SkillScan's patterns are regex heuristics, so expect false positives and sophisticated evasions to be missed.

## Why SkillScan Exists

ClawdHub has **zero vetting**. Any skill can be published. The Nick Saraev video showed:

1. Malicious skills stealing API tokens
2. Thousands of compromised Clawdbot instances
3. Supply chain attacks through skill repositories
4. Zero protection for end users

**Don't be the next victim.** Scan before you install.

## API

### POST /api/scan

Scan code, GitHub repositories, npm packages, OpenVSX extensions, GitHub Actions workflows, or supported skill-directory URLs for security issues.

**Request Body:**
```json
{
  "url": "https://github.com/username/repo",
  // OR
  "code": "your code here"
}
```

**Response:**
```json
{
  "score": 85,
  "grade": "B",
  "summary": "Found 2 medium-risk issues. Generally safe but worth reviewing.",
  "scannedFiles": 5,
  "linesAnalyzed": 1247,
  "findings": [
    {
      "severity": "medium",
      "category": "Network Access",
      "title": "Network request detected",
      "description": "Code makes network requests which could be used for data exfiltration.",
      "file": "index.ts",
      "path": "src/index.ts",
      "line": 42,
      "snippet": "fetch('https://api.example.com/data')",
      "remediation": "Ensure URLs are validated and requests are to trusted domains only."
    }
  ]
}
```

## Development

### Setup
```bash
pnpm install
```

### Run Development Server
```bash
pnpm dev
```

### Build for Production
```bash
pnpm build
```

### Quality Checks
```bash
pnpm test
npx tsc --noEmit
pnpm eval:malicious
pnpm eval:local-skills
pnpm lint
pnpm build:cli
pnpm build
```

## Case Study

See [CASE_STUDY.md](./CASE_STUDY.md) for the product framing, tradeoffs, and next steps.

## Tech Stack

- **Next.js 14** - React framework with App Router
- **TypeScript** - Type safety
- **Tailwind CSS** - Styling with custom dark theme
- **Framer Motion** - Smooth animations
- **Lucide React** - Beautiful icons

## Design Philosophy

SkillScan is designed by security-conscious developers, for security-conscious developers. It's not a generic SaaS tool - it's a specialized security scanner that understands the Claude Code ecosystem.

- **Fast** - Static analysis only, no AI inference delays
- **Accurate** - Pattern-based detection for known vulnerabilities
- **Focused** - Specifically designed for Claude Code skills and MCP servers
- **Clean** - Terminal-inspired UI without cheesy "hacker" aesthetics

## License

MIT License - built for the Claude Code community.
