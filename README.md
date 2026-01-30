# SkillScan - ClawdHub Security Scanner

**Every skill is guilty until proven safe.**

A fast, free security scanner for ClawdHub skills, Claude Code skills, and MCP servers. Born from the viral "It Got Worse - Clawdbot" video exposing the ClawdHub supply chain crisis.

## The ClawdHub Supply Chain Crisis

Nick Saraev's viral "It Got Worse - Clawdbot" video exposed:
- **No vetting process** on ClawdHub - malicious skills published freely
- **Thousands of compromised Clawdbot instances** via Shodan scanning
- **API token theft** through malicious skill instructions
- **Supply chain attacks** via skill repositories

His advice? "Read every file or feed files to AI to check safety." **We automate that.**

## Features

- 🔒 **ClawdHub Attack Detection** - Scans for real attack vectors from the crisis
- ⚡ **Instant Scanning** - No AI needed, pure regex-based pattern matching
- 🎯 **ClawdHub + GitHub Support** - Paste ClawdHub URLs directly
- 📊 **Risk Scoring** - 0-100 security score with A-F grades
- 🌙 **Security-Focused UI** - Built by and for security-conscious developers

## 13 Security Checks

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
13. **Excessive Permissions** - Skills requesting too many tool accesses

## Usage

### Scan ClawdHub Skill
```
https://claudhub.ai/skills/username/skillname
```

### Scan GitHub Repository
```
https://github.com/username/repo
```

### Scan Single File
```
https://github.com/username/repo/blob/main/file.ts
```

### Scan Code Directly
Paste your skill code directly into the scanner.

## Why SkillScan Exists

ClawdHub has **zero vetting**. Any skill can be published. The Nick Saraev video showed:

1. Malicious skills stealing API tokens
2. Thousands of compromised Clawdbot instances
3. Supply chain attacks through skill repositories
4. Zero protection for end users

**Don't be the next victim.** Scan before you install.

## API

### POST /api/scan

Scan code or GitHub repository for security issues.

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