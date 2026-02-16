# CLAUDE.md - SkillScan Security Scanner

## Overview
SkillScan is a fast, free security scanner for ClawdHub skills, Claude Code skills, and MCP servers. Born from Nick Saraev's viral "It Got Worse - Clawdbot" video exposing the ClawdHub supply chain crisis. Every skill is guilty until proven safe.

**Mission**: Automate security analysis of Claude skills to protect against supply chain attacks, API token theft, and malicious code execution.

## Commands
```bash
pnpm dev              # Start development server (Next.js)
pnpm build            # Build for production
pnpm start            # Start production server
pnpm lint             # ESLint code checking
```

## Architecture

### Tech Stack
- **Framework**: Next.js 14 with App Router
- **Runtime**: React 18, TypeScript 5
- **Styling**: Tailwind CSS with custom dark theme
- **Animation**: Framer Motion for smooth interactions
- **Icons**: Lucide React
- **Deployment**: Vercel (recommended)

### Project Structure
```
app/
├── api/
│   └── scan/            # POST /api/scan - main scanning endpoint
├── globals.css          # Tailwind + custom styles
├── layout.tsx           # Root layout with dark theme
└── page.tsx             # Main scanner interface

lib/
├── github.ts            # GitHub API integration
├── scanner.ts           # Core security scanning engine
└── types.ts             # TypeScript definitions

components/
└── ui/                  # (If using Shadcn/UI components)
```

### Security Engine (`lib/scanner.ts`)
The core scanner performs **13 security checks** using regex pattern matching:

1. **Shell Command Execution** - `exec()`, `spawn()`, `child_process`
2. **Network Requests** - HTTP/HTTPS external calls
3. **File System Access** - Reading/writing files outside workspace
4. **Environment Variable Access** - `process.env` secret extraction
5. **Dynamic Code Execution** - `eval()`, Function constructor
6. **Base64 Encoding** - Potential data exfiltration
7. **Obfuscated Code** - Minified, hex-encoded patterns
8. **Prompt Injection** - "Ignore previous instructions" patterns
9. **API Token Stealing** - OpenAI/Anthropic key extraction attempts ⭐
10. **Credential Patterns** - Hardcoded API keys, passwords
11. **Data Exfiltration Webhooks** - Suspicious webhook URLs ⭐
12. **Package Analysis** - Typosquatting in package.json
13. **Excessive Permissions** - Over-broad tool access requests

## API Reference

### POST /api/scan

Scan code or GitHub repository for security vulnerabilities.

**Request Body:**
```json
{
  "url": "https://github.com/username/repo",
  // OR
  "url": "https://claudhub.ai/skills/username/skillname", 
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
      "severity": "high" | "medium" | "low",
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

### Score Calculation
- **A (90-100)**: Excellent security, minimal risks
- **B (80-89)**: Good security, minor concerns  
- **C (70-79)**: Acceptable security, some risks
- **D (60-69)**: Poor security, multiple risks
- **F (0-59)**: Dangerous, major security flaws

## Key Features

### Multi-Source Scanning
- **ClawdHub Skills**: Direct ClawdHub.ai URL scanning
- **GitHub Repositories**: Full repo or single file analysis  
- **Direct Code**: Paste code directly into scanner
- **Batch Processing**: Multiple files analyzed together

### GitHub Integration (`lib/github.ts`)
```typescript
// Fetch repository contents
const contents = await fetchGitHubContents(owner, repo, path);

// Detect ClawdHub skills by structure
const isClawdHubSkill = hasSkillJson && hasIndexFile;

// Analyze package.json for malicious dependencies
const packageAnalysis = analyzePackageJson(packageJson);
```

### Real-Time Analysis
- **Fast Scanning**: Pure regex patterns, no AI inference delays
- **Instant Results**: Sub-second analysis for most repositories
- **Progress Indication**: Live feedback during GitHub fetching
- **Error Handling**: Graceful fallbacks for API failures

### Security-Focused Design
- **Dark Theme**: Terminal-inspired aesthetic
- **Clean Interface**: No cheesy "hacker" styling
- **Security Mindset**: Built by security-conscious developers
- **Privacy First**: No code stored server-side

## Configuration

### Environment Variables
```bash
# GitHub API (optional, increases rate limits)
GITHUB_TOKEN=ghp_...        # GitHub personal access token

# Analytics (optional)
VERCEL_ANALYTICS_ID=...     # Vercel Analytics ID
```

### Tailwind Configuration
Custom dark theme optimized for security focus:
```javascript
// tailwind.config.ts
theme: {
  extend: {
    colors: {
      background: "hsl(var(--background))",
      foreground: "hsl(var(--foreground))",
      danger: "hsl(var(--destructive))",
      success: "hsl(var(--success))",
    },
    fontFamily: {
      mono: ['var(--font-geist-mono)'],
    }
  }
}
```

## Deployment

### Vercel (Recommended)
1. Push to GitHub repository
2. Connect to Vercel
3. Set environment variables:
   ```bash
   GITHUB_TOKEN=ghp_your_token_here
   ```
4. Deploy automatically on push to main

### Self-Hosted
```bash
# Build for production
pnpm build

# Start production server
pnpm start

# Or use PM2 for production
pm2 start npm --name "skillscan" -- start
```

## Usage Examples

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
https://github.com/username/repo/blob/main/index.ts
```

### Direct Code Analysis
Paste skill code directly into the web interface for immediate analysis.

## The ClawdHub Crisis Context

SkillScan was created in response to Nick Saraev's viral "It Got Worse - Clawdbot" video which exposed:

- **Zero Vetting Process**: Any skill can be published to ClawdHub
- **Thousands of Compromised Instances**: Shodan scans revealed widespread compromise
- **API Token Theft**: Malicious skills stealing OpenAI/Anthropic keys
- **Supply Chain Attacks**: Poisoned skill repositories
- **User Vulnerability**: No protection for end users installing skills

His recommendation: "Read every file or feed files to AI to check safety." **SkillScan automates this process.**

## Development Guidelines

### Adding New Security Checks
1. Add pattern to `lib/scanner.ts`
2. Define severity level (high/medium/low)
3. Include remediation guidance
4. Test with known vulnerable code samples
5. Update documentation

### Pattern Development
```typescript
// Example security check pattern
{
  pattern: /process\.env\[['"`]([^'"`]+)['"`]\]/g,
  severity: 'medium' as const,
  category: 'Environment Access',
  title: 'Environment variable access detected',
  description: 'Code accesses environment variables which may contain secrets.',
  remediation: 'Ensure environment variable access is for non-sensitive configuration only.'
}
```

### Testing New Patterns
```bash
# Test against known vulnerable samples
pnpm test

# Manual testing with curl
curl -X POST http://localhost:3000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"code":"eval(userInput)"}'
```

## Gotchas & Important Notes

### Rate Limits
- **GitHub API**: 60 requests/hour without token, 5000 with token
- **ClawdHub**: No official API, uses web scraping (fragile)
- **Large Repos**: May timeout on very large repositories

### Security Considerations
- **Code Privacy**: Code sent to server for analysis (not stored)
- **GitHub Token**: Only needs public repo access (`public_repo` scope)
- **False Positives**: Regex patterns may flag legitimate code
- **False Negatives**: Sophisticated attacks may bypass detection

### Performance
- **Client-Side**: UI updates are real-time
- **Server-Side**: Scanning is CPU-intensive for large codebases
- **Memory Usage**: Large repositories may consume significant RAM

## Current Status
- **Version**: 1.0.0
- **Status**: SHIPPED and public
- **Launch**: Response to ClawdHub security crisis
- **Usage**: [Add usage statistics if available]
- **Community**: Security-focused developer community

## Next Steps
1. **Enhanced Patterns**: Add more sophisticated attack detection
2. **Machine Learning**: Train models on known malicious skills
3. **API Expansion**: Support for more skill repositories
4. **Browser Extension**: Integrate directly into ClawdHub browsing
5. **Community Reporting**: Allow users to report suspicious skills
6. **Automated Monitoring**: Continuous scanning of new ClawdHub uploads

## Contributing
SkillScan is built for the Claude Code security community. Contributions welcome for:
- New security patterns
- Performance improvements  
- UI/UX enhancements
- Additional skill repository support
- Documentation improvements

Remember: **Every skill is guilty until proven safe.**