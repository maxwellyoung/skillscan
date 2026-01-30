import { Finding, ScanResult, GitHubFile } from './types';

type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

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

  async scan(files: GitHubFile[]): Promise<ScanResult> {
    this.findings = [];
    this.scannedFiles = files.length;
    this.linesAnalyzed = 0;
    this.seenFindings = new Set();

    for (const file of files) {
      this.linesAnalyzed += file.content.split('\n').length;
      await this.scanFile(file);
    }

    const score = this.calculateScore();
    const grade = this.calculateGrade(score);
    const summary = this.generateSummary();

    return {
      score,
      grade,
      findings: this.findings,
      summary,
      scannedFiles: this.scannedFiles,
      linesAnalyzed: this.linesAnalyzed
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
    const key = `${finding.file}:${finding.line || 0}:${finding.category}`;
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
    }

    // 10. Credential patterns (hardcoded secrets — check all files)
    this.checkCredentialPatterns(content, file, lines);

    // 11. Suspicious URLs — check all files but filter safe URLs
    this.checkSuspiciousUrls(content, file, lines);

    // 12. Package.json analysis
    if (file.name === 'package.json') {
      this.checkPackageJson(content, file);
    }
  }

  private checkExecCalls(content: string, file: GitHubFile, lines: string[]): void {
    const patterns = [
      /(?:exec|spawn|execSync|spawnSync|execFile|execFileSync)\s*\(/g,
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
        const severity = this.isUnboundedExec(snippet) ? 'critical' : 'high';

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
    ];

    patterns.forEach(pattern => {
      const matches = Array.from(content.matchAll(pattern));
      for (const match of matches) {
        const lineNumber = this.getLineNumber(content, match.index!);
        const snippet = lines[lineNumber - 1]?.trim();
        
        const envVar = match[1] || '';
        const severity: Severity = this.isSensitiveEnvVar(envVar) ? 'high' : 'medium';

        this.addFinding({
          severity: this.adjustSeverity(severity, file, match.index),
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
          severity: this.adjustSeverity('critical', file, match.index),
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

    const hexPattern = /['"`]\\x[0-9a-fA-F]{2}(?:\\x[0-9a-fA-F]{2}){3,}/g;
    const longStringPattern = /['"`][^'"`\n]{500,}['"`]/g;

    const patterns = [hexPattern, longStringPattern];

    patterns.forEach(pattern => {
      const matches = Array.from(content.matchAll(pattern));
      for (const match of matches) {
        const lineNumber = this.getLineNumber(content, match.index!);
        const snippet = lines[lineNumber - 1]?.trim().substring(0, 100) + '...';

        this.addFinding({
          severity: 'high',
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
      ['preinstall', 'postinstall', 'preuninstall', 'postuninstall'].forEach(hook => {
        if (scripts[hook]) {
          this.addFinding({
            severity: 'medium',
            category: 'Install Hooks',
            title: `${hook} script detected`,
            description: 'Package has install/uninstall hooks that run automatically during npm operations.',
            file: file.name,
            snippet: `"${hook}": "${scripts[hook]}"`,
            remediation: 'Review install hook scripts to ensure they perform only necessary setup tasks.'
          });
        }
      });

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

  private getLineNumber(content: string, index: number): number {
    return content.substring(0, index).split('\n').length;
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

  private calculateScore(): number {
    let score = 100;
    
    for (const finding of this.findings) {
      switch (finding.severity) {
        case 'critical':
          score -= 20;
          break;
        case 'high':
          score -= 10;
          break;
        case 'medium':
          score -= 5;
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

    return Math.max(0, Math.min(100, score));
  }

  private calculateGrade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
    if (score >= 90) return 'A';
    if (score >= 75) return 'B';
    if (score >= 60) return 'C';
    if (score >= 40) return 'D';
    return 'F';
  }

  private generateSummary(): string {
    // Only count non-info findings
    const realFindings = this.findings.filter(f => f.severity !== 'info');
    const criticalCount = realFindings.filter(f => f.severity === 'critical').length;
    const highCount = realFindings.filter(f => f.severity === 'high').length;
    const mediumCount = realFindings.filter(f => f.severity === 'medium').length;
    const infoCount = this.findings.filter(f => f.severity === 'info').length;

    if (criticalCount > 0) {
      return `Found ${criticalCount} critical security ${criticalCount === 1 ? 'issue' : 'issues'}. Immediate attention required.`;
    }
    
    if (highCount > 0) {
      return `Found ${highCount} high-risk ${highCount === 1 ? 'issue' : 'issues'}. Review recommended before installation.`;
    }
    
    if (mediumCount > 0) {
      return `Found ${mediumCount} medium-risk ${mediumCount === 1 ? 'issue' : 'issues'}. Generally safe but worth reviewing.`;
    }

    if (infoCount > 0) {
      return `${infoCount} informational ${infoCount === 1 ? 'note' : 'notes'}. No actionable security issues found.`;
    }
    
    return 'No significant security issues detected. Appears safe to install.';
  }
}
