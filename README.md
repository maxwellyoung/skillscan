# SkillScan

Static security scanning for AI skills, MCP servers, npm packages, and VS Code extensions.

SkillScan checks local skill instructions, GitHub-hosted code, npm package metadata, OpenVSX extension metadata, and MCP server repositories for risky patterns before you install or run them. It is intentionally fast and boring: static analysis, clear findings, and remediation notes.

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
- 0-100 security score with A-F grades.
- Pattern checks for shell execution, network access, file-system access, prompt injection, credential patterns, data exfiltration, package install hooks, and extension activation behavior.
- No AI inference required for the core scan.
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

## Evaluation Harness

The scanner has adversarial evals for cases that should fail hard and benign cases that should stay quiet.

Committed malicious fixtures live in `test/fixtures/malicious` and cover:

- Multi-line secret exfiltration through outbound requests.
- `postinstall` scripts that fetch and execute remote code.
- `SKILL.md` instructions that request broad tools, secrets, and webhook transmission.
- Persistence attempts through launch agents, SSH authorized keys, and broad file permission changes.
- npm packages that exfiltrate environment variables during install.
- VS Code extensions with broad activation, terminal execution, clipboard access, and outbound secret transmission.

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
Paste skill instructions, package manifests, extension manifests, or source code directly into the scanner.

## Why SkillScan Exists

ClawdHub has **zero vetting**. Any skill can be published. The Nick Saraev video showed:

1. Malicious skills stealing API tokens
2. Thousands of compromised Clawdbot instances
3. Supply chain attacks through skill repositories
4. Zero protection for end users

**Don't be the next victim.** Scan before you install.

## API

### POST /api/scan

Scan code, GitHub repositories, npm packages, OpenVSX extensions, or supported skill-directory URLs for security issues.

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
pnpm eval:malicious
pnpm eval:local-skills
pnpm lint
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
