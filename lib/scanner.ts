import { Finding, ScanResult, GitHubFile } from './types';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

const CHECKS_RUN = 29;
const severityRank: Record<Severity, number> = {
  critical: 0,
  high: 1,
  medium: 2,
  low: 3,
  info: 4,
};

const KNOWN_COMPROMISED_NPM = new Map([
  ['axios@0.30.4', 'Axios supply-chain compromise: malicious npm release published outside the normal GitHub release flow.'],
  ['axios@1.14.1', 'Axios supply-chain compromise: malicious npm release published outside the normal GitHub release flow.'],
  ['eslint-config-prettier@8.10.1', 'eslint-config-prettier maintainer account compromise: malicious npm release.'],
  ['eslint-config-prettier@9.1.1', 'eslint-config-prettier maintainer account compromise: malicious npm release.'],
  ['eslint-config-prettier@10.1.6', 'eslint-config-prettier maintainer account compromise: malicious npm release.'],
  ['eslint-config-prettier@10.1.7', 'eslint-config-prettier maintainer account compromise: malicious npm release.'],
  ['@bitwarden/cli@2026.4.0', 'Bitwarden CLI npm compromise window: malicious release distributed through npm.'],
  ['intercom-client@7.0.4', 'Mini Shai-Hulud / TeamPCP campaign: compromised npm release.'],
  ['intercom-client@7.0.5', 'Mini Shai-Hulud / TeamPCP campaign: compromised npm release.'],
]);

const HIGH_VALUE_PACKAGE_NAMES = new Set([
  'axios',
  'eslint',
  'eslint-config-prettier',
  '@bitwarden/cli',
  '@tanstack/react-router',
  '@tanstack/router-core',
  'intercom-client',
]);

const SHA_PIN = /^[a-f0-9]{40}$/i;

/**
 * SkillScan Security Scanner v2
 * 
 * Key improvement: distinguishes between executable code and documentation.
 * Markdown files with code examples are NOT treated the same as real .js/.ts files.
 */
export class SecurityScanner {
  private findings: Finding[] = [];
  private scannedFiles = 0;
  private linesAnalyzed = 0;
  private seenFindings = new Set<string>();
  private currentFile?: GitHubFile;

  async scan(files: GitHubFile[]): Promise<ScanResult> {
    this.findings = [];
    this.scannedFiles = files.length;
    this.linesAnalyzed = 0;
    this.seenFindings = new Set();

    for (const file of files) {
      this.linesAnalyzed += file.content.split('\n').length;
      this.currentFile = file;
      await this.scanFile(file);
    }
    this.currentFile = undefined;

    const score = this.calculateScore();
    const grade = this.calculateGrade(score);
    const riskLevel = this.calculateRiskLevel(score);
    this.findings.sort((a, b) => {
      const severityDelta = severityRank[a.severity] - severityRank[b.severity];
      if (severityDelta !== 0) return severityDelta;
      return `${a.file ?? ''}:${a.line ?? 0}`.localeCompare(`${b.file ?? ''}:${b.line ?? 0}`);
    });
    const severityCounts = this.calculateSeverityCounts();
    const summary = this.generateSummary();

    return {
      score,
      grade,
      riskLevel,
      severityCounts,
      findings: this.findings,
      summary,
      scannedFiles: this.scannedFiles,
      linesAnalyzed: this.linesAnalyzed,
      checksRun: CHECKS_RUN
    };
  }

  /**
   * Determine if a file is documentation vs executable code.
   */
  private isDocFile(fileName: string): boolean {
    const docExtensions = ['.md', '.mdx', '.txt', '.rst', '.adoc'];
    return docExtensions.some(ext => fileName.toLowerCase().endsWith(ext));
  }

  /**
   * Check if a line in a markdown file is inside a fenced code block.
   * Code blocks in docs are examples, not executable, so they get lower severity.
   */
  private isInsideCodeBlock(content: string, index: number): boolean {
    const before = content.substring(0, index);
    const fenceMatches = before.match(/```/g);
    // Odd number of ``` means we're inside a code block
    return fenceMatches ? fenceMatches.length % 2 === 1 : false;
  }

  /**
   * Downgrade severity for documentation files.
   * Code examples in SKILL.md are not real threats.
   */
  private adjustSeverity(severity: Severity, file: GitHubFile, index?: number): Severity {
    if (!this.isDocFile(file.name)) return severity;
    
    // Inside a code block in docs = informational only
    if (index !== undefined && this.isInsideCodeBlock(file.content, index)) {
      return 'info';
    }
    
    // Prose in docs mentioning security concepts = info
    return 'info';
  }

  /**
   * Deduplicate findings: same file + line + category = skip.
   */
  private addFinding(finding: Finding): void {
    finding.path ??= this.currentFile?.path;
    const key = `${finding.path ?? finding.file}:${finding.line || 0}:${finding.category}`;
    if (this.seenFindings.has(key)) return;
    this.seenFindings.add(key);
    this.findings.push(finding);
  }

  /**
   * Safe URL patterns that should never be flagged.
   */
  private isSafeUrl(url: string): boolean {
    const safePatterns = [
      'example.com',
      'example.org',
      'example.net',
      'localhost',
      '127.0.0.1',
      '0.0.0.0',
      'httpbin.org',
      'jsonplaceholder.typicode.com',
      'api.example',
      'your-api.com',
      'your-domain',
      'yourdomain',
      'my-app',
      'myapp',
      'placeholder',
    ];
    const lower = url.toLowerCase();
    // Also safe if it's a relative URL
    if (lower.startsWith('/api/') || lower.startsWith('/')) return true;
    return safePatterns.some(p => lower.includes(p));
  }

  private async scanFile(file: GitHubFile): Promise<void> {
    const content = file.content;
    const lines = content.split('\n');
    const isDoc = this.isDocFile(file.name);

    // For doc files, only scan for the most dangerous patterns
    // (actual exfiltration URLs, real credential leaks)
    
    // 1. exec/spawn calls
    if (!isDoc) {
      this.checkExecCalls(content, file, lines);
    }

    // 2. Network requests (skip docs entirely, code examples aren't real requests)
    if (!isDoc) {
      this.checkNetworkRequests(content, file, lines);
    }

    // 3. File system access
    if (!isDoc) {
      this.checkFileSystemAccess(content, file, lines);
    }

    // 4. Environment variable access
    if (!isDoc) {
      this.checkEnvironmentAccess(content, file, lines);
    }

    // 5. Eval/Function constructor
    if (!isDoc) {
      this.checkDynamicExecution(content, file, lines);
    }

    // 6. Base64 encoding
    if (!isDoc) {
      this.checkBase64Encoding(content, file, lines);
    }

    // 7. Obfuscated code (check all files but adjust severity)
    this.checkObfuscatedCode(content, file, lines);

    // 8. Prompt injection (check all files, this IS relevant in docs)
    this.checkPromptInjection(content, file, lines);

    // 9. API token stealing — ONLY check executable files
    // Docs mentioning "API key" is normal documentation, not theft
    if (!isDoc) {
      this.checkApiTokenStealing(content, file, lines);
      this.checkSecretExfiltrationFlow(content, file, lines);
      this.checkPersistenceAndSystemModification(content, file, lines);
    }

    // 10. Credential patterns (hardcoded secrets — check all files)
    this.checkCredentialPatterns(content, file, lines);

    // 11. Suspicious URLs — check all files but filter safe URLs
    this.checkSuspiciousUrls(content, file, lines);

    // 12. Skill and agent instruction analysis
    if (this.isInstructionFile(file.name)) {
      this.checkSkillInstructions(content, file, lines);
    }

    // 13. Package.json analysis
    if (file.name === 'package.json') {
      this.checkPackageJson(content, file);
    }

    // 14. VS Code extension source behavior
    this.checkVsCodeExtensionBehavior(content, file, lines);

    // 15. GitHub Actions workflow behavior
    if (this.isGitHubActionsWorkflow(file)) {
      this.checkGitHubActionsWorkflow(content, file, lines);
    }

    // 16. Registry metadata intelligence
    if (file.name === 'npm-metadata.json') {
      this.checkNpmRegistryMetadata(content, file);
    }
  }

  private checkExecCalls(content: string, file: GitHubFile, lines: string[]): void {
    const patterns = [
      /(?<![.\w$])(?:exec|spawn|execSync|spawnSync|execFile|execFileSync)\s*\(/g,
      /child_process\.\w+\(/g,
      /process\.exec\(/g,
      /import.*child_process/g,
      /require\(['"`]child_process['"`]\)/g
    ];

    patterns.forEach(pattern => {
      const matches = Array.from(content.matchAll(pattern));
      for (const match of matches) {
        const lineNumber = this.getLineNumber(content, match.index!);
        const snippet = lines[lineNumber - 1]?.trim();
        const severity = this.isUnboundedExec(snippet) && !this.isExtractedArtifactFile(file) ? 'critical' : 'high';

        this.addFinding({
          severity: this.adjustSeverity(severity, file, match.index),
          category: 'Command Execution',
          title: 'Shell command execution detected',
          description: 'Code can execute shell commands, which could be used to run arbitrary system commands.',
          file: file.name,
          line: lineNumber,
          snippet: snippet,
          remediation: 'Ensure command parameters are validated and sanitized. Consider using safer alternatives.'
        });
      }
    });
  }

  private checkNetworkRequests(content: string, file: GitHubFile, lines: string[]): void {
    const patterns = [
      /(?:fetch|axios|http\.get|http\.post|http\.request|https\.get|https\.post|https\.request)\s*\(/g,
      /requests\.(?:get|post|put|patch|request)\s*\(/g,
      /urllib\.request\.(?:urlopen|Request)\s*\(/g,
      /new\s+(?:XMLHttpRequest|WebSocket)\s*\(/g,
      /import.*(?:axios|node-fetch|request)/g,
      /require\(['"`](?:axios|node-fetch|request|http|https)['"`]\)/g
    ];

    patterns.forEach(pattern => {
      const matches = Array.from(content.matchAll(pattern));
      for (const match of matches) {
        const lineNumber = this.getLineNumber(content, match.index!);
        const snippet = lines[lineNumber - 1]?.trim();

        // Skip if the URL in the snippet is a safe/example URL
        if (this.isSafeUrl(snippet)) continue;

        const severity = this.hasSuspiciousDomain(snippet) ? 'critical' : 'medium';

        this.addFinding({
          severity: this.adjustSeverity(severity, file, match.index),
          category: 'Network Access',
          title: 'Network request detected',
          description: 'Code makes network requests which could be used for data exfiltration or downloading malicious content.',
          file: file.name,
          line: lineNumber,
          snippet: snippet,
          remediation: 'Ensure URLs are validated and requests are to trusted domains only.'
        });
      }
    });
  }

  private checkFileSystemAccess(content: string, file: GitHubFile, lines: string[]): void {
    const patterns = [
      /fs\.(?:readFile|writeFile|readdir|mkdir|rmdir|unlink|stat|access|createReadStream|createWriteStream)/g,
      /path\.(?:join|resolve).*\.\./g,
    ];

    patterns.forEach(pattern => {
      const matches = Array.from(content.matchAll(pattern));
      for (const match of matches) {
        const lineNumber = this.getLineNumber(content, match.index!);
        const snippet = lines[lineNumber - 1]?.trim();
        const severity: Severity = snippet.includes('..') ? 'high' : 'medium';

        this.addFinding({
          severity: this.adjustSeverity(severity, file, match.index),
          category: 'File System Access',
          title: 'File system operation detected',
          description: 'Code accesses the file system, which could be used to read sensitive files or modify system files.',
          file: file.name,
          line: lineNumber,
          snippet: snippet,
          remediation: 'Restrict file operations to a sandbox directory and validate all file paths.'
        });
      }
    });
  }

  private checkEnvironmentAccess(content: string, file: GitHubFile, lines: string[]): void {
    const patterns = [
      /process\.env\[?['"`]?(\w+)['"`]?\]?/g,
      /os\.environ(?:\.get)?\(\s*['"`]([A-Z0-9_]+)['"`]/g,
    ];

    patterns.forEach(pattern => {
      const matches = Array.from(content.matchAll(pattern));
      for (const match of matches) {
        const lineNumber = this.getLineNumber(content, match.index!);
        const snippet = lines[lineNumber - 1]?.trim();
        
        const envVar = match[1] || '';
        const severity: Severity = this.isSensitiveEnvVar(envVar) ? 'high' : 'medium';
        const adjustedSeverity: Severity = envVar.startsWith('NEXT_PUBLIC_') || envVar.startsWith('PUBLIC_')
          ? 'info'
          : severity;

        this.addFinding({
          severity: this.adjustSeverity(adjustedSeverity, file, match.index),
          category: 'Environment Access',
          title: 'Environment variable access detected',
          description: 'Code reads environment variables, which could expose sensitive configuration or secrets.',
          file: file.name,
          line: lineNumber,
          snippet: snippet,
          remediation: 'Ensure only necessary environment variables are accessed and sensitive data is properly protected.'
        });
      }
    });
  }

  private checkDynamicExecution(content: string, file: GitHubFile, lines: string[]): void {
    const patterns = [
      /(?:^|[\s\[\(,=])eval\s*\(/g,
      /new\s+Function\s*\(/g,
      /Function\s*\(\s*['"`]/g,
      /setTimeout\s*\(\s*['"`]/g,
      /setInterval\s*\(\s*['"`]/g
    ];

    patterns.forEach(pattern => {
      const matches = Array.from(content.matchAll(pattern));
      for (const match of matches) {
        const lineNumber = this.getLineNumber(content, match.index!);
        const snippet = lines[lineNumber - 1]?.trim();

        this.addFinding({
          severity: this.adjustSeverity(this.isExtractedArtifactFile(file) ? 'high' : 'critical', file, match.index),
          category: 'Dynamic Execution',
          title: 'Dynamic code execution detected',
          description: 'Code uses eval() or Function constructor which can execute arbitrary code strings.',
          file: file.name,
          line: lineNumber,
          snippet: snippet,
          remediation: 'Avoid dynamic code execution. Use safer alternatives like JSON.parse() for data or predefined function mappings.'
        });
      }
    });
  }

  private checkBase64Encoding(content: string, file: GitHubFile, lines: string[]): void {
    const patterns = [
      /(?:btoa|atob)\s*\(/g,
      /Buffer\.(?:from|toString)\s*\(.*['"`]base64['"`]/g,
      /\.toString\s*\(\s*['"`]base64['"`]\s*\)/g,
    ];

    patterns.forEach(pattern => {
      const matches = Array.from(content.matchAll(pattern));
      for (const match of matches) {
        const lineNumber = this.getLineNumber(content, match.index!);
        const snippet = lines[lineNumber - 1]?.trim();

        this.addFinding({
          severity: this.adjustSeverity('medium', file, match.index),
          category: 'Data Encoding',
          title: 'Base64 encoding detected',
          description: 'Code uses Base64 encoding which could be used to obfuscate data exfiltration.',
          file: file.name,
          line: lineNumber,
          snippet: snippet,
          remediation: 'Review Base64 usage to ensure it is not being used to hide malicious data transmission.'
        });
      }
    });
  }

  private checkObfuscatedCode(content: string, file: GitHubFile, lines: string[]): void {
    // Only check for hex-encoded strings and very long string literals
    // Skip doc files entirely for obfuscation (long lines in docs are normal)
    if (this.isDocFile(file.name)) return;
    if (file.name.endsWith('.json')) return;

    const hexPattern = /['"`]\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){3,}/g;
    const longStringPattern = /['"`][^'"`\n]{500,}['"`]/g;

    const patterns = [hexPattern, longStringPattern];

    patterns.forEach(pattern => {
      const matches = Array.from(content.matchAll(pattern));
      for (const match of matches) {
        const lineNumber = this.getLineNumber(content, match.index!);
        const snippet = lines[lineNumber - 1]?.trim().substring(0, 100) + '...';

        this.addFinding({
          severity: this.isExtractedArtifactFile(file) ? 'medium' : 'high',
          category: 'Code Obfuscation',
          title: 'Obfuscated code detected',
          description: 'Code contains obfuscated strings or patterns that could hide malicious functionality.',
          file: file.name,
          line: lineNumber,
          snippet: snippet,
          remediation: 'Review obfuscated code sections and ensure they are legitimate and necessary.'
        });
      }
    });
  }

  private checkPromptInjection(content: string, file: GitHubFile, lines: string[]): void {
    const patterns = [
      /ignore\s+(?:previous|all|prior|above)\s+(?:instruction|prompt|context|system)/gi,
      /forget\s+(?:previous|all|prior|above)/gi,
      /you\s+are\s+now\s+(?:a|an|the)/gi,
      /disregard\s+(?:all|any|previous)/gi,
    ];

    patterns.forEach(pattern => {
      const matches = Array.from(content.matchAll(pattern));
      for (const match of matches) {
        const lineNumber = this.getLineNumber(content, match.index!);
        const snippet = lines[lineNumber - 1]?.trim();

        this.addFinding({
          severity: this.isDocFile(file.name) ? 'medium' : 'high',
          category: 'Prompt Injection',
          title: 'Potential prompt injection detected',
          description: 'Content contains patterns commonly used in prompt injection attacks.',
          file: file.name,
          line: lineNumber,
          snippet: snippet,
          remediation: 'Review prompt construction and ensure user input is properly sanitized.'
        });
      }
    });
  }

  private checkCredentialPatterns(content: string, file: GitHubFile, lines: string[]): void {
    const patterns = [
      // Only match things that look like REAL secrets (long random strings)
      /(?:api_key|apikey|access_key|secret_key|private_key)\s*[:=]\s*['"`]([^'"`\s]{20,})['"`]/gi,
      /(?:password|passwd|pwd)\s*[:=]\s*['"`]([^'"`\s]{8,})['"`]/gi,
    ];

    patterns.forEach(pattern => {
      const matches = Array.from(content.matchAll(pattern));
      for (const match of matches) {
        const value = match[1] || '';
        // Skip obvious placeholders
        if (this.isPlaceholderValue(value)) continue;
        
        const lineNumber = this.getLineNumber(content, match.index!);
        const snippet = lines[lineNumber - 1]?.trim().replace(/['"`][^'"`\s]{10,}['"`]/, '"[REDACTED]"');

        this.addFinding({
          severity: this.adjustSeverity('high', file, match.index),
          category: 'Credentials Exposure',
          title: 'Potential hardcoded credentials detected',
          description: 'Code appears to contain hardcoded credentials or API keys.',
          file: file.name,
          line: lineNumber,
          snippet: snippet,
          remediation: 'Use environment variables or secure credential storage instead of hardcoding sensitive values.'
        });
      }
    });
  }

  private isPlaceholderValue(value: string): boolean {
    const lower = value.toLowerCase();
    return lower.includes('xxx') || 
           lower.includes('your') || 
           lower.includes('example') ||
           lower.includes('placeholder') ||
           lower.includes('change_me') ||
           lower.includes('todo') ||
           lower.startsWith('sk-xxx') ||
           lower.startsWith('pk_test') ||
           lower.startsWith('sk_test') ||
           /^[x]+$/i.test(value) ||
           /^(test|demo|sample|fake|mock)/i.test(value);
  }

  private checkSuspiciousUrls(content: string, file: GitHubFile, lines: string[]): void {
    // Only flag genuinely suspicious exfiltration endpoints
    const exfiltrationDomains = [
      'pastebin.com',
      'hastebin.com',
      'webhook.site',
      'requestbin.com',
      'pipedream.com',
      'ngrok.io',
      'ngrok-free.app',
      'serveo.net',
      'burpcollaborator.net',
    ];

    // Webhook patterns that suggest data exfiltration
    const webhookPatterns = [
      /discord\.com\/api\/webhooks\//gi,
      /hooks\.slack\.com\/services\//gi,
    ];

    const urlPattern = /https?:\/\/[^\s\)'">\]]+/gi;
    const matches = Array.from(content.matchAll(urlPattern));

    for (const match of matches) {
      const url = match[0];
      
      // Skip safe/example URLs
      if (this.isSafeUrl(url)) continue;

      const lineNumber = this.getLineNumber(content, match.index!);
      const snippet = lines[lineNumber - 1]?.trim();

      const isExfiltration = exfiltrationDomains.some(domain => 
        url.toLowerCase().includes(domain.toLowerCase())
      );

      const isWebhook = webhookPatterns.some(pattern => pattern.test(url));

      if (isExfiltration || isWebhook) {
        const title = isWebhook ? 'Data exfiltration webhook detected' : 'Suspicious exfiltration URL detected';
        const description = isWebhook 
          ? 'Code contains webhook URLs commonly used for data exfiltration.'
          : 'Code contains URLs to services commonly used for data exfiltration.';

        this.addFinding({
          severity: this.adjustSeverity('critical', file, match.index),
          category: 'Data Exfiltration',
          title,
          description,
          file: file.name,
          line: lineNumber,
          snippet: snippet,
          remediation: isWebhook 
            ? 'Remove webhook URLs. Legitimate integrations should use official APIs with proper authentication.'
            : 'Review the purpose of external URLs and ensure they are legitimate and necessary.'
        });
      }
    }
  }

  private checkApiTokenStealing(content: string, file: GitHubFile, lines: string[]): void {
    // ONLY flag actual exfiltration patterns, not documentation mentioning APIs
    // Real token theft = reading a token AND sending it somewhere
    
    const exfiltrationPatterns = [
      // Sending env vars via network
      /fetch\(.*process\.env/gi,
      /axios\.\w+\(.*process\.env/gi,
      /http\.(?:get|post|request)\(.*process\.env/gi,
      
      // Logging secrets
      /console\.log\(.*(?:api_key|apikey|secret|token|password)/gi,
      
      // Encoding secrets for transmission
      /(?:btoa|Buffer\.from)\(.*(?:api_key|apikey|secret|token)/gi,
      
      // Writing secrets to external URLs
      /fetch\(.*webhook.*(?:key|token|secret)/gi,
    ];

    exfiltrationPatterns.forEach(pattern => {
      const matches = Array.from(content.matchAll(pattern));
      for (const match of matches) {
        const lineNumber = this.getLineNumber(content, match.index!);
        const snippet = lines[lineNumber - 1]?.trim();

        this.addFinding({
          severity: 'critical',
          category: 'API Token Theft',
          title: 'Potential API token exfiltration detected',
          description: 'Code appears to read secrets and transmit them externally.',
          file: file.name,
          line: lineNumber,
          snippet: snippet,
          remediation: 'Remove any attempts to access and transmit API keys or tokens.'
        });
      }
    });
  }

  private checkSecretExfiltrationFlow(content: string, file: GitHubFile, lines: string[]): void {
    const jsEnvReads = Array.from(content.matchAll(/process\.env(?:\.([A-Z0-9_]+)|\[['"`]([A-Z0-9_]+)['"`]\])/gi));
    const pythonEnvReads = Array.from(content.matchAll(/os\.environ(?:\.get)?\(\s*['"`]([A-Z0-9_]+)['"`]/gi));
    const sensitiveEnvReads = [...jsEnvReads, ...pythonEnvReads]
      .filter(match => this.isSensitiveEnvVar(match[1] || match[2] || ''));

    if (sensitiveEnvReads.length === 0) return;

    const outboundPatterns = [
      /fetch\s*\(\s*['"`]https?:\/\//gi,
      /axios\.(?:post|put|patch|request)\s*\(\s*['"`]https?:\/\//gi,
      /https?\.request\s*\(/gi,
      /https?\.post\s*\(/gi,
      /requests\.(?:post|put|patch|request)\s*\(\s*['"`]https?:\/\//gi,
      /urllib\.request\.(?:urlopen|Request)\s*\(/gi,
      /discord\.com\/api\/webhooks\//gi,
      /hooks\.slack\.com\/services\//gi,
      /webhook\.site/gi,
      /requestbin\.com/gi,
      /pipedream\.com/gi,
      /api\.github\.com\/repos\//gi,
    ];

    const hasOutbound = outboundPatterns.some(pattern => pattern.test(content));
    if (!hasOutbound) return;

    const firstSecret = sensitiveEnvReads[0];
    const lineNumber = this.getLineNumber(content, firstSecret.index!);
    const snippet = lines[lineNumber - 1]?.trim();

    this.addFinding({
      severity: 'critical',
      category: 'Secret Exfiltration Flow',
      title: 'Secret read and outbound transmission detected',
      description: 'Code reads sensitive environment variables and also performs outbound network transmission in the same file.',
      file: file.name,
      line: lineNumber,
      snippet,
      remediation: 'Separate secret handling from outbound transmission, and verify no secret value can reach a network request or webhook.'
    });
  }

  private checkPersistenceAndSystemModification(content: string, file: GitHubFile, lines: string[]): void {
    const patterns: Array<{ pattern: RegExp; category: string; title: string; severity: Severity; remediation: string }> = [
      {
        pattern: /(?:crontab|launchctl|systemctl|schtasks|reg\s+add)\b/gi,
        category: 'Persistence',
        title: 'Persistence mechanism detected',
        severity: 'critical',
        remediation: 'Remove persistence hooks. Developer tools should not create startup jobs unless the behavior is explicit and user-approved.'
      },
      {
        pattern: /(?:authorized_keys|\.ssh\/config|id_rsa|id_ed25519|known_hosts)/gi,
        category: 'SSH Access',
        title: 'SSH credential or access file touched',
        severity: 'critical',
        remediation: 'Do not read or modify SSH keys or authorized_keys from installable skills or MCP servers.'
      },
      {
        pattern: /(?:curl|wget)\b[^|\n]*(?:\|\s*(?:bash|sh|zsh)|>\s*\/tmp\/|-o\s+\/tmp\/|--output\s+\/tmp\/)/gi,
        category: 'Remote Code Execution',
        title: 'Remote script execution pattern detected',
        severity: 'critical',
        remediation: 'Avoid curl-pipe-shell patterns. Pin, verify, and inspect downloaded artifacts before execution.'
      },
      {
        pattern: /github\.com\/[^/\s]+\/[^/\s]+\/releases\/download\/[^\s]+|\bbun(?:-linux|-darwin|-windows)?\b|router_runtime\.js|execution\.js/gi,
        category: 'Runtime Downloader',
        title: 'Incident-style runtime downloader detected',
        severity: 'critical',
        remediation: 'Block packages that download runtimes or second-stage payloads from GitHub Releases during install or import.'
      },
      {
        pattern: /rm\s+-rf\s+(?:~|\/|\$HOME|process\.env\.HOME)/gi,
        category: 'Destructive File Operation',
        title: 'Destructive recursive delete detected',
        severity: 'critical',
        remediation: 'Remove broad recursive delete operations or constrain them to a verified temporary workspace.'
      },
      {
        pattern: /chmod\s+(?:\+x|777)|chown\s+-R/gi,
        category: 'Permission Modification',
        title: 'Broad permission modification detected',
        severity: 'high',
        remediation: 'Avoid changing executable bits or ownership recursively unless the target path is fixed and trusted.'
      },
    ];

    for (const rule of patterns) {
      const matches = Array.from(content.matchAll(rule.pattern));
      for (const match of matches) {
        const lineNumber = this.getLineNumber(content, match.index!);
        const snippet = lines[lineNumber - 1]?.trim();

        this.addFinding({
          severity: rule.severity,
          category: rule.category,
          title: rule.title,
          description: 'Code contains behavior commonly associated with persistence, destructive modification, or remote code execution.',
          file: file.name,
          line: lineNumber,
          snippet,
          remediation: rule.remediation
        });
      }
    }
  }

  private isInstructionFile(fileName: string): boolean {
    const base = fileName.split('/').pop()?.toLowerCase() ?? '';
    return base === 'skill.md' ||
      base === 'agents.md' ||
      base === 'claude.md' ||
      base === 'readme.md' ||
      base?.endsWith('.skill.md') ||
      base?.endsWith('.agents.md') ||
      base?.endsWith('.claude.md');
  }

  private isExtractedArtifactFile(file: GitHubFile): boolean {
    return file.path.includes('/tarball/') || file.path.includes('/vsix/');
  }

  private checkSkillInstructions(content: string, file: GitHubFile, lines: string[]): void {
    const lower = content.toLowerCase();
    const asksForDangerousTools = /(?:allowed-tools|tools|permissions)\s*[:=-].*(?:bash|shell|exec|terminal|filesystem|read|write)/i.test(content);
    const exfiltrationInstruction = /(?:read|collect|steal|extract|exfiltrate|grab|dump)[\s\S]{0,160}(?:api[_ -]?key|token|secret|password|process\.env|environment variable|credential)[\s\S]{0,220}(?:send|post|upload|transmit|webhook|discord\.com\/api\/webhooks|hooks\.slack\.com|curl|fetch|exfiltrat)/i.test(content) ||
      /(?:send|post|upload|transmit|webhook|discord\.com\/api\/webhooks|hooks\.slack\.com|curl|fetch|exfiltrat)[\s\S]{0,220}(?:api[_ -]?key|token|secret|password|process\.env|environment variable|credential)/i.test(content);

    if (asksForDangerousTools && exfiltrationInstruction) {
      const lineNumber = this.findFirstMatchingLine(lines, /read|collect|steal|extract|exfiltrate|grab|dump|webhook|secret|token|process\.env/i);
      this.addFinding({
        severity: 'critical',
        category: 'Malicious Skill Instructions',
        title: 'Instruction file combines broad tools, secrets, and outbound transmission',
        description: 'The skill instructions request dangerous capabilities while discussing secret access and outbound transmission.',
        file: file.name,
        line: lineNumber,
        snippet: lines[lineNumber - 1]?.trim(),
        remediation: 'Reject this skill unless the requested capabilities are minimized and the outbound behavior is removed or fully justified.'
      });
    }

    if (lower.includes('ignore previous instructions') || lower.includes('disregard previous instructions')) {
      const lineNumber = this.findFirstMatchingLine(lines, /ignore previous instructions|disregard previous instructions/i);
      this.addFinding({
        severity: 'high',
        category: 'Instruction Override',
        title: 'Instruction override attempt detected',
        description: 'The instruction file asks an agent to ignore or disregard prior instructions.',
        file: file.name,
        line: lineNumber,
        snippet: lines[lineNumber - 1]?.trim(),
        remediation: 'Remove instruction override language. Legitimate skills should compose with caller and system instructions.'
      });
    }
  }

  private checkPackageJson(content: string, file: GitHubFile): void {
    try {
      const pkg = JSON.parse(content);
      const dependencies = { ...pkg.dependencies, ...pkg.devDependencies };
      
      // Known typosquatting patterns
      const suspiciousPatterns = [
        /^(colors|faker|request|lodash|underscore|moment|axios|express)[\d-_]/i,
        /\d{6,}/,
        /^[a-z]{2,3}\d+$/,
      ];

      Object.keys(dependencies || {}).forEach(name => {
        const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(name));
        
        if (isSuspicious) {
          this.addFinding({
            severity: 'high',
            category: 'Package Dependencies',
            title: 'Suspicious package dependency detected',
            description: `Package "${name}" has patterns similar to typosquatting or malicious packages.`,
            file: file.name,
            remediation: 'Verify package authenticity and check for typos in package names.'
          });
        }
      });

      // Install hooks
      const scripts = pkg.scripts || {};
      ['preinstall', 'install', 'postinstall', 'prepare', 'preuninstall', 'postuninstall'].forEach(hook => {
        if (scripts[hook]) {
          const script = String(scripts[hook]);
          const severity: Severity = this.isDangerousLifecycleScript(script) ? 'critical' : 'medium';
          this.addFinding({
            severity,
            category: 'Install Hooks',
            title: `${hook} script detected`,
            description: 'Package has install/uninstall hooks that run automatically during npm operations.',
            file: file.name,
            snippet: `"${hook}": "${script}"`,
            remediation: severity === 'critical'
              ? 'Remove network, shell, or filesystem-modifying behavior from lifecycle scripts before installation.'
              : 'Review install hook scripts to ensure they perform only necessary setup tasks.'
          });
        }
      });

      this.checkNpmPackageMetadata(pkg, file);
      this.checkOptionalDependencyRisk(pkg, file);
      this.checkVsCodeManifest(pkg, file);

    } catch {
      this.addFinding({
        severity: 'low',
        category: 'Package Configuration',
        title: 'Invalid package.json',
        description: 'package.json file contains invalid JSON.',
        file: file.name,
        remediation: 'Fix JSON syntax errors in package.json.'
      });
    }
  }

  private checkNpmPackageMetadata(pkg: Record<string, unknown>, file: GitHubFile): void {
    const name = String(pkg.name || '');
    const repository = pkg.repository;
    const scripts = pkg.scripts && typeof pkg.scripts === 'object' ? pkg.scripts as Record<string, unknown> : {};
    const bin = pkg.bin;
    const dependencies = {
      ...(pkg.dependencies && typeof pkg.dependencies === 'object' ? pkg.dependencies as Record<string, unknown> : {}),
      ...(pkg.devDependencies && typeof pkg.devDependencies === 'object' ? pkg.devDependencies as Record<string, unknown> : {}),
    };

    if (!repository && !pkg.homepage) {
      this.addFinding({
        severity: 'low',
        category: 'Package Provenance',
        title: 'Package has no repository or homepage metadata',
        description: 'Package metadata does not point to auditable source code or project context.',
        file: file.name,
        remediation: 'Prefer packages with clear source repositories, maintainers, provenance, and release history.'
      });
    }

    if (bin && Object.keys(scripts).some(script => ['preinstall', 'install', 'postinstall', 'prepare'].includes(script))) {
      this.addFinding({
        severity: 'high',
        category: 'Package Install Surface',
        title: 'CLI package also runs install-time scripts',
        description: 'Packages with command-line entrypoints and lifecycle hooks have a larger execution surface during install and runtime.',
        file: file.name,
        remediation: 'Review lifecycle scripts and CLI entrypoints before installing globally or running through npx/pnpm dlx.'
      });
    }

    for (const depName of Object.keys(dependencies)) {
      if (this.looksLikeTyposquat(name, depName)) {
        this.addFinding({
          severity: 'high',
          category: 'Package Dependencies',
          title: 'Dependency name looks close to the package name',
          description: `Dependency "${depName}" may indicate dependency confusion, typosquatting, or self-referential package confusion.`,
          file: file.name,
          remediation: 'Verify dependency identity, publisher, and purpose before installation.'
        });
      }
    }
  }

  private checkOptionalDependencyRisk(pkg: Record<string, unknown>, file: GitHubFile): void {
    const optionalDependencies = pkg.optionalDependencies && typeof pkg.optionalDependencies === 'object'
      ? pkg.optionalDependencies as Record<string, unknown>
      : {};

    for (const [name, spec] of Object.entries(optionalDependencies)) {
      const value = String(spec);
      const isGitDependency = /github:|git\+https?:|https:\/\/github\.com/i.test(value);
      const isRuntimeName = /bun|runtime|loader|install|setup/i.test(name);

      if (isGitDependency || isRuntimeName) {
        this.addFinding({
          severity: isGitDependency ? 'high' : 'medium',
          category: 'Optional Dependencies',
          title: 'Optional dependency can expand install-time execution surface',
          description: 'Recent supply-chain campaigns used optional dependencies and GitHub-hosted payloads to execute malware during installation.',
          file: file.name,
          snippet: `"${name}": "${value}"`,
          remediation: 'Review optional dependencies carefully, especially GitHub-hosted specs or runtime/bootstrap packages.'
        });
      }
    }
  }

  private checkVsCodeManifest(pkg: Record<string, unknown>, file: GitHubFile): void {
    const isVsCodeExtension = Boolean(
      pkg.activationEvents ||
      pkg.contributes ||
      pkg.publisher ||
      (pkg.engines && typeof pkg.engines === 'object' && 'vscode' in pkg.engines)
    );

    if (!isVsCodeExtension) return;

    const activationEvents = Array.isArray(pkg.activationEvents) ? pkg.activationEvents.map(String) : [];
    const hasStartupActivation = activationEvents.some(event =>
      event === '*' ||
      event === 'onStartupFinished' ||
      event.startsWith('workspaceContains:') ||
      event.startsWith('onLanguage:')
    );

    if (hasStartupActivation) {
      this.addFinding({
        severity: activationEvents.includes('*') ? 'high' : 'medium',
        category: 'VS Code Activation',
        title: 'Broad extension activation detected',
        description: 'The extension can activate automatically or across broad workspace contexts, increasing the blast radius of malicious code.',
        file: file.name,
        snippet: `"activationEvents": ${JSON.stringify(activationEvents)}`,
        remediation: 'Prefer narrow activation events tied to explicit commands or specific languages.'
      });
    }

    const contributes = pkg.contributes && typeof pkg.contributes === 'object'
      ? pkg.contributes as Record<string, unknown>
      : {};

    if (contributes.configuration && hasStartupActivation) {
      this.addFinding({
        severity: 'medium',
        category: 'VS Code Configuration',
        title: 'Extension contributes settings and activates broadly',
        description: 'Extensions that both activate broadly and control configuration deserve closer review.',
        file: file.name,
        remediation: 'Review configuration defaults and make sure settings do not silently enable network, shell, or credential access.'
      });
    }
  }

  private checkVsCodeExtensionBehavior(content: string, file: GitHubFile, lines: string[]): void {
    if (!/from ['"`]vscode['"`]|require\(['"`]vscode['"`]\)|vscode\./i.test(content)) return;

    const rules: Array<{ pattern: RegExp; severity: Severity; category: string; title: string; remediation: string }> = [
      {
        pattern: /(?:vscode\.)?window\.createTerminal|terminal\.sendText/gi,
        severity: 'high',
        category: 'VS Code Terminal',
        title: 'Extension can run terminal commands',
        remediation: 'Terminal execution should require explicit user action and visible commands.'
      },
      {
        pattern: /(?:vscode\.)?workspace\.fs\.|workspace\.findFiles|workspace\.openTextDocument/gi,
        severity: 'medium',
        category: 'VS Code Workspace Access',
        title: 'Extension can access workspace files',
        remediation: 'Constrain workspace file access and avoid reading secrets, dotfiles, or unrelated project files.'
      },
      {
        pattern: /(?:vscode\.)?env\.clipboard|clipboard\.readText|clipboard\.writeText/gi,
        severity: 'high',
        category: 'VS Code Clipboard',
        title: 'Extension can access clipboard data',
        remediation: 'Clipboard access should be explicit and scoped to user-initiated commands.'
      },
    ];

    for (const rule of rules) {
      const matches = Array.from(content.matchAll(rule.pattern));
      for (const match of matches) {
        const lineNumber = this.getLineNumber(content, match.index!);
        const snippet = lines[lineNumber - 1]?.trim();
        this.addFinding({
          severity: rule.severity,
          category: rule.category,
          title: rule.title,
          description: 'VS Code extensions run with developer-workstation access and can inspect or modify local project state.',
          file: file.name,
          line: lineNumber,
          snippet,
          remediation: rule.remediation
        });
      }
    }
  }

  private isGitHubActionsWorkflow(file: GitHubFile): boolean {
    const normalizedPath = file.path.toLowerCase();
    const normalizedName = file.name.toLowerCase();
    return normalizedName.endsWith('.workflow.yml') ||
      normalizedName.endsWith('.workflow.yaml') ||
      normalizedPath.includes('.github/workflows/') &&
        (normalizedPath.endsWith('.yml') || normalizedPath.endsWith('.yaml'));
  }

  private checkGitHubActionsWorkflow(content: string, file: GitHubFile, lines: string[]): void {
    const hasPullRequestTarget = /\bpull_request_target\b/.test(content);
    const hasWriteAll = /permissions\s*:\s*write-all/i.test(content);
    const hasIdTokenWrite = /id-token\s*:\s*write/i.test(content);
    const hasContentsWrite = /contents\s*:\s*write/i.test(content);
    const hasSecrets = /\$\{\{\s*secrets\./i.test(content);
    const hasCheckout = /uses\s*:\s*actions\/checkout@/i.test(content);
    const hasPackagePublish = /\b(npm\s+publish|pnpm\s+publish|yarn\s+npm\s+publish|npm\s+run\s+release|semantic-release)\b/i.test(content);

    if (hasPullRequestTarget) {
      const lineNumber = this.findFirstMatchingLine(lines, /\bpull_request_target\b/);
      const severity: Severity = hasSecrets || hasContentsWrite || hasWriteAll ? 'critical' : 'high';
      this.addFinding({
        severity,
        category: 'GitHub Actions',
        title: 'pull_request_target workflow detected',
        description: 'pull_request_target can run with elevated repository context on code influenced by external pull requests.',
        file: file.path,
        line: lineNumber,
        snippet: lines[lineNumber - 1]?.trim(),
        remediation: 'Avoid pull_request_target unless the job never checks out or executes untrusted PR code. Prefer pull_request with read-only permissions.'
      });
    }

    if (hasWriteAll || hasContentsWrite || hasIdTokenWrite) {
      const lineNumber = this.findFirstMatchingLine(lines, /permissions\s*:\s*write-all|contents\s*:\s*write|id-token\s*:\s*write/i);
      this.addFinding({
        severity: hasPackagePublish || hasSecrets ? 'high' : 'medium',
        category: 'GitHub Actions Permissions',
        title: 'Broad write-capable workflow permissions detected',
        description: 'Write permissions and OIDC tokens increase blast radius if the workflow or an action dependency is compromised.',
        file: file.path,
        line: lineNumber,
        snippet: lines[lineNumber - 1]?.trim(),
        remediation: 'Use least-privilege permissions at workflow and job scope. Grant write or id-token only to the exact publish job.'
      });
    }

    if (hasPackagePublish && hasSecrets) {
      const lineNumber = this.findFirstMatchingLine(lines, /npm\s+publish|pnpm\s+publish|yarn\s+npm\s+publish|semantic-release/i);
      this.addFinding({
        severity: 'high',
        category: 'Release Pipeline',
        title: 'Package publish workflow has secret access',
        description: 'Recent supply-chain attacks turned package release pipelines into credential exfiltration and republishing paths.',
        file: file.path,
        line: lineNumber,
        snippet: lines[lineNumber - 1]?.trim(),
        remediation: 'Use trusted publishing with scoped OIDC, short-lived credentials, protected environments, and manual approval for high-impact packages.'
      });
    }

    if (hasPullRequestTarget && hasCheckout) {
      const lineNumber = this.findFirstMatchingLine(lines, /actions\/checkout@/i);
      this.addFinding({
        severity: 'critical',
        category: 'GitHub Actions',
        title: 'pull_request_target workflow checks out code',
        description: 'Checking out code in a pull_request_target workflow is a common path to running untrusted code with elevated repository permissions.',
        file: file.path,
        line: lineNumber,
        snippet: lines[lineNumber - 1]?.trim(),
        remediation: 'Do not checkout or execute PR-controlled code in pull_request_target workflows.'
      });
    }

    const usesPattern = /uses\s*:\s*([^@\s]+)@([^\s#]+)/gi;
    for (const match of Array.from(content.matchAll(usesPattern))) {
      const action = match[1];
      const ref = match[2].replace(/^['"]|['"]$/g, '');
      const isDockerAction = action.startsWith('docker://');
      const isLocalAction = action.startsWith('./');
      const isThirdParty = !isDockerAction && !isLocalAction && !action.startsWith('actions/');
      const isPinned = SHA_PIN.test(ref);

      if (isThirdParty && !isPinned) {
        const lineNumber = this.getLineNumber(content, match.index!);
        this.addFinding({
          severity: hasPackagePublish || hasSecrets ? 'high' : 'medium',
          category: 'GitHub Actions Pinning',
          title: 'Third-party action is not pinned to a commit SHA',
          description: 'Tag-based action references can move after review, as seen in recent GitHub Actions supply-chain incidents.',
          file: file.path,
          line: lineNumber,
          snippet: lines[lineNumber - 1]?.trim(),
          remediation: 'Pin third-party actions to a full commit SHA and update them through reviewable dependency automation.'
        });
      }
    }
  }

  private checkNpmRegistryMetadata(content: string, file: GitHubFile): void {
    try {
      const metadata = JSON.parse(content) as {
        name?: string;
        version?: string;
        time?: Record<string, string>;
        dist?: { integrity?: string; shasum?: string; tarball?: string };
        maintainers?: Array<{ name?: string; email?: string }>;
      };

      const name = metadata.name || this.extractPackageNameFromPath(file.path);
      const version = metadata.version || this.extractPackageVersionFromPath(file.path);
      const packageVersion = name && version ? `${name}@${version}` : '';

      if (packageVersion && KNOWN_COMPROMISED_NPM.has(packageVersion)) {
        this.addFinding({
          severity: 'critical',
          category: 'Known Compromised Package',
          title: 'Package version is listed in incident intelligence',
          description: KNOWN_COMPROMISED_NPM.get(packageVersion) || 'This package version has been associated with a public supply-chain incident.',
          file: file.path,
          snippet: packageVersion,
          remediation: 'Do not install this version. Pin to a known safe version, remove it from lockfiles, and rotate secrets on any machine or runner that installed it.'
        });
      }

      const publishedAt = version ? metadata.time?.[version] : undefined;
      if (publishedAt) {
        const ageHours = (Date.now() - Date.parse(publishedAt)) / 36e5;
        if (Number.isFinite(ageHours) && ageHours >= 0) {
          const isHighValue = name ? HIGH_VALUE_PACKAGE_NAMES.has(name) || name.startsWith('@tanstack/') : false;
          if (ageHours < 24 || isHighValue && ageHours < 168) {
            this.addFinding({
              severity: ageHours < 24 ? 'high' : 'medium',
              category: 'Registry Freshness',
              title: ageHours < 24 ? 'Package version published in the last 24 hours' : 'High-impact package version is less than 7 days old',
              description: 'Recent incidents show malicious versions can be detected and removed within hours, after they have already reached automated installs.',
              file: file.path,
              snippet: `${packageVersion || 'package'} published ${publishedAt}`,
              remediation: 'Apply a cooldown before auto-installing fresh versions, especially for high-download packages or release/publish tooling.'
            });
          }
        }
      }

      if (metadata.dist && !metadata.dist.integrity) {
        this.addFinding({
          severity: 'medium',
          category: 'Package Integrity',
          title: 'Registry metadata is missing Subresource Integrity',
          description: 'Integrity metadata helps package managers verify downloaded artifacts.',
          file: file.path,
          remediation: 'Prefer packages with integrity metadata and lockfiles that preserve tarball hashes.'
        });
      }

      if (!metadata.maintainers || metadata.maintainers.length === 0) {
        this.addFinding({
          severity: 'medium',
          category: 'Package Maintainers',
          title: 'Package metadata has no maintainers',
          description: 'Missing maintainer metadata weakens provenance review and incident response.',
          file: file.path,
          remediation: 'Review package ownership and release history before installing.'
        });
      }
    } catch {
      this.addFinding({
        severity: 'low',
        category: 'Registry Metadata',
        title: 'Invalid npm registry metadata',
        description: 'npm metadata could not be parsed.',
        file: file.path,
        remediation: 'Retry the scan or inspect the registry response manually.'
      });
    }
  }

  private getLineNumber(content: string, index: number): number {
    return content.substring(0, index).split('\n').length;
  }

  private findFirstMatchingLine(lines: string[], pattern: RegExp): number {
    const index = lines.findIndex(line => pattern.test(line));
    return index >= 0 ? index + 1 : 1;
  }

  private isUnboundedExec(snippet: string): boolean {
    return snippet.includes('process.argv') || 
           snippet.includes('input') || 
           snippet.includes('${') ||
           snippet.includes('`') ||
           !snippet.includes('"') && !snippet.includes("'");
  }

  private hasSuspiciousDomain(snippet: string): boolean {
    const suspiciousDomains = ['pastebin.com', 'webhook.site', 'ngrok.io'];
    return suspiciousDomains.some(domain => snippet.includes(domain));
  }

  private isSensitiveEnvVar(envVar: string): boolean {
    const sensitivePatterns = ['KEY', 'TOKEN', 'SECRET', 'PASSWORD', 'AUTH', 'PRIVATE'];
    return sensitivePatterns.some(pattern => envVar.toUpperCase().includes(pattern));
  }

  private extractPackageNameFromPath(pathValue: string): string | undefined {
    const match = pathValue.match(/^npm:(.+)@([^@/]+)\/npm-metadata\.json$/);
    return match?.[1];
  }

  private extractPackageVersionFromPath(pathValue: string): string | undefined {
    const match = pathValue.match(/^npm:(.+)@([^@/]+)\/npm-metadata\.json$/);
    return match?.[2];
  }

  private looksLikeTyposquat(packageName: string, dependencyName: string): boolean {
    if (!packageName || !dependencyName) return false;
    const normalize = (value: string) => value.replace(/^@[^/]+\//, '').replace(/[-_.]/g, '').toLowerCase();
    const pkg = normalize(packageName);
    const dep = normalize(dependencyName);
    if (pkg.length < 5 || dep.length < 5 || pkg === dep) return false;
    return dep.includes(pkg) || pkg.includes(dep);
  }

  private isDangerousLifecycleScript(script: string): boolean {
    return /(?:curl|wget).*(?:\|\s*(?:bash|sh|zsh)|https?:\/\/)/i.test(script) ||
      /(?:node\s+-e|python\s+-c|ruby\s+-e)/i.test(script) ||
      /(?:process\.env|\.ssh|authorized_keys|crontab|launchctl|rm\s+-rf)/i.test(script);
  }

  private calculateScore(): number {
    let score = 100;
    
    for (const finding of this.findings) {
      switch (finding.severity) {
        case 'critical':
          score -= 35;
          break;
        case 'high':
          score -= 15;
          break;
        case 'medium':
          score -= 7;
          break;
        case 'low':
          score -= 2;
          break;
        case 'info':
          // Info findings don't affect score
          score -= 0;
          break;
      }
    }

    const criticalCount = this.findings.filter(f => f.severity === 'critical').length;
    const highCount = this.findings.filter(f => f.severity === 'high').length;

    if (criticalCount > 0) {
      score = Math.min(score, criticalCount >= 2 ? 20 : 35);
    } else if (highCount >= 3) {
      score = Math.min(score, 55);
    }

    if (criticalCount === 0) {
      score = Math.max(score, highCount > 0 ? 45 : 65);
    }

    return Math.max(0, Math.min(100, score));
  }

  private calculateGrade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
    if (this.findings.some(f => f.severity === 'critical')) return 'F';
    if (score >= 92) return 'A';
    if (score >= 80) return 'B';
    if (score >= 65) return 'C';
    if (score >= 45) return 'D';
    return 'F';
  }

  private calculateRiskLevel(score: number): 'pass' | 'review' | 'block' {
    if (this.findings.some(f => f.severity === 'critical')) return 'block';
    if (score < 80 || this.findings.some(f => f.severity === 'high')) return 'review';
    return 'pass';
  }

  private calculateSeverityCounts(): Record<Severity, number> {
    return this.findings.reduce(
      (counts, finding) => {
        counts[finding.severity] += 1;
        return counts;
      },
      { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>,
    );
  }

  private generateSummary(): string {
    // Only count non-info findings
    const realFindings = this.findings.filter(f => f.severity !== 'info');
    const criticalCount = realFindings.filter(f => f.severity === 'critical').length;
    const highCount = realFindings.filter(f => f.severity === 'high').length;
    const mediumCount = realFindings.filter(f => f.severity === 'medium').length;
    const infoCount = this.findings.filter(f => f.severity === 'info').length;

    if (criticalCount > 0) {
      return `Install blocked: found ${criticalCount} critical security ${criticalCount === 1 ? 'issue' : 'issues'}. Review the evidence before running this code.`;
    }
    
    if (highCount > 0) {
      return `Manual review required: found ${highCount} high-risk ${highCount === 1 ? 'issue' : 'issues'}. Do not auto-install.`;
    }
    
    if (mediumCount > 0) {
      return `Review suggested: found ${mediumCount} medium-risk ${mediumCount === 1 ? 'issue' : 'issues'}. No install-blocking behavior detected.`;
    }

    if (infoCount > 0) {
      return `${infoCount} informational ${infoCount === 1 ? 'note' : 'notes'}. No actionable security issues found.`;
    }
    
    return 'No significant security issues detected. Appears safe to install.';
  }
}
