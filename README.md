# SkillScan - Security Scanner for Claude Code Skills

A fast, free security scanner for Claude Code skills and MCP servers. Analyzes code for 12+ security risk vectors using static analysis.

## Features

- 🔒 **Static Security Analysis** - Scans for 12+ security risk categories
- ⚡ **Fast Scanning** - No AI needed, pure regex-based pattern matching
- 🐙 **GitHub Integration** - Scan entire repositories or individual files
- 🎯 **Risk Assessment** - Get scored reports with severity levels
- 🌙 **Dark Mode UI** - Terminal-inspired security-focused design

## Security Checks

SkillScan detects the following security risks:

1. **Shell Command Execution** - `exec()`, `spawn()`, `child_process` usage
2. **Network Requests** - HTTP/HTTPS calls to external URLs
3. **File System Access** - Reading/writing files outside workspace
4. **Environment Variable Access** - Accessing `process.env` for secrets
5. **Dynamic Code Execution** - `eval()`, Function constructor usage
6. **Base64 Encoding** - Potential data exfiltration encoding
7. **Obfuscated Code** - Minified, hex-encoded, or suspicious patterns
8. **Prompt Injection** - "Ignore previous instructions" type patterns
9. **Credential Patterns** - Hardcoded API keys, passwords, tokens
10. **Suspicious URLs** - Pastebin, webhooks, localhost, ngrok, etc.
11. **Package Analysis** - Typosquatting, malicious packages in package.json
12. **Excessive Permissions** - Skills requesting too many tool accesses

## Usage

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