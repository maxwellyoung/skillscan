import { Finding, ScanResult, GitHubFile } from './types';

export class SecurityScanner {
  private findings: Finding[] = [];
  private scannedFiles = 0;
  private linesAnalyzed = 0;

  async scan(files: GitHubFile[]): Promise<ScanResult> {
    this.findings = [];
    this.scannedFiles = files.length;
    this.linesAnalyzed = 0;

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

  private async scanFile(file: GitHubFile): Promise<void> {
    const content = file.content;
    const lines = content.split('\n');

    // 1. exec/spawn calls
    this.checkExecCalls(content, file, lines);

    // 2. Network requests
    this.checkNetworkRequests(content, file, lines);

    // 3. File system access
    this.checkFileSystemAccess(content, file, lines);

    // 4. Environment variable access
    this.checkEnvironmentAccess(content, file, lines);

    // 5. Eval/Function constructor
    this.checkDynamicExecution(content, file, lines);

    // 6. Base64 encoding
    this.checkBase64Encoding(content, file, lines);

    // 7. Obfuscated code
    this.checkObfuscatedCode(content, file, lines);

    // 8. Prompt injection patterns
    this.checkPromptInjection(content, file, lines);

    // 9. API token stealing (ClawdHub specific)
    this.checkApiTokenStealing(content, file, lines);

    // 10. Credential patterns
    this.checkCredentialPatterns(content, file, lines);

    // 10. Suspicious URLs
    this.checkSuspiciousUrls(content, file, lines);

    // 11. Package.json analysis
    if (file.name === 'package.json') {
      this.checkPackageJson(content, file);
    }

    // 12. Excessive permissions
    if (file.name === 'SKILL.md' || file.name === 'package.json') {
      this.checkPermissions(content, file, lines);
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

        // Check if it's bounded/safe
        const severity = this.isUnboundedExec(snippet) ? 'critical' : 'high';

        this.findings.push({
          severity,
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

        const severity = this.hasSuspiciousDomain(snippet) ? 'critical' : 'medium';

        this.findings.push({
          severity,
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
      /process\.cwd\(\)/g,
      /\.\.\/|\.\.\\/g
    ];

    patterns.forEach(pattern => {
      const matches = Array.from(content.matchAll(pattern));
      for (const match of matches) {
        const lineNumber = this.getLineNumber(content, match.index!);
        const snippet = lines[lineNumber - 1]?.trim();

        const severity = snippet.includes('..') ? 'high' : 'medium';

        this.findings.push({
          severity,
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
      /(?:process\.env\.|env\.)(\w*(?:KEY|TOKEN|SECRET|PASSWORD|PASS|AUTH))/gi
    ];

    patterns.forEach(pattern => {
      const matches = Array.from(content.matchAll(pattern));
      for (const match of matches) {
        const lineNumber = this.getLineNumber(content, match.index!);
        const snippet = lines[lineNumber - 1]?.trim();
        
        const envVar = match[1] || '';
        const severity = this.isSensitiveEnvVar(envVar) ? 'high' : 'medium';

        this.findings.push({
          severity,
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

        this.findings.push({
          severity: 'critical',
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
      /base64\s*[:=]/gi
    ];

    patterns.forEach(pattern => {
      const matches = Array.from(content.matchAll(pattern));
      for (const match of matches) {
        const lineNumber = this.getLineNumber(content, match.index!);
        const snippet = lines[lineNumber - 1]?.trim();

        this.findings.push({
          severity: 'medium',
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
    // Check for hex-encoded strings
    const hexPattern = /['"`]\\x[0-9a-fA-F]{2}/g;
    // Check for unicode escape sequences
    const unicodePattern = /\\u[0-9a-fA-F]{4}/g;
    // Check for very long string literals
    const longStringPattern = /['"`][^'"`\n]{200,}['"`]/g;

    const patterns = [hexPattern, unicodePattern, longStringPattern];

    patterns.forEach(pattern => {
      const matches = Array.from(content.matchAll(pattern));
      for (const match of matches) {
        const lineNumber = this.getLineNumber(content, match.index!);
        const snippet = lines[lineNumber - 1]?.trim().substring(0, 100) + '...';

        this.findings.push({
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
      /act\s+as\s+(?:if|though)/gi,
      /system\s*[:=]\s*['"`]/gi,
      /role\s*[:=]\s*['"`]system['"`]/gi,
      /new\s+(?:instruction|task|role|prompt)/gi
    ];

    patterns.forEach(pattern => {
      const matches = Array.from(content.matchAll(pattern));
      for (const match of matches) {
        const lineNumber = this.getLineNumber(content, match.index!);
        const snippet = lines[lineNumber - 1]?.trim();

        this.findings.push({
          severity: 'high',
          category: 'Prompt Injection',
          title: 'Potential prompt injection detected',
          description: 'Code contains patterns commonly used in prompt injection attacks.',
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
      /(?:api_key|apikey|access_key|secret_key|private_key)\s*[:=]\s*['"`][^'"`\s]{10,}['"`]/gi,
      /(?:password|passwd|pwd)\s*[:=]\s*['"`][^'"`\s]{6,}['"`]/gi,
      /(?:token|bearer)\s*[:=]\s*['"`][^'"`\s]{20,}['"`]/gi,
      /['"]\w*(?:key|token|secret|password)['"]:\s*['"`][^'"`\s]{10,}['"`]/gi
    ];

    patterns.forEach(pattern => {
      const matches = Array.from(content.matchAll(pattern));
      for (const match of matches) {
        const lineNumber = this.getLineNumber(content, match.index!);
        const snippet = lines[lineNumber - 1]?.trim().replace(/['"`][^'"`\s]{10,}['"`]/, '"[REDACTED]"');

        this.findings.push({
          severity: 'medium',
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

  private checkSuspiciousUrls(content: string, file: GitHubFile, lines: string[]): void {
    const suspiciousDomains = [
      'pastebin.com',
      'hastebin.com',
      'api.telegram.org',
      'discord.com/api/webhooks',
      'hooks.slack.com',
      'webhook.site',
      'requestbin.com',
      'ngrok.io',
      'bit.ly',
      'tinyurl.com',
      'localhost:',
      '127.0.0.1:',
      '0.0.0.0:'
    ];

    const urlPattern = /https?:\/\/[^\s\)'">\]]+/gi;
    const matches = Array.from(content.matchAll(urlPattern));

    for (const match of matches) {
      const url = match[0];
      const lineNumber = this.getLineNumber(content, match.index!);
      const snippet = lines[lineNumber - 1]?.trim();

      const isSuspicious = suspiciousDomains.some(domain => 
        url.toLowerCase().includes(domain.toLowerCase())
      );

      if (isSuspicious) {
        this.findings.push({
          severity: 'critical',
          category: 'Suspicious URLs',
          title: 'Suspicious URL detected',
          description: 'Code contains URLs to services commonly used for data exfiltration or command & control.',
          file: file.name,
          line: lineNumber,
          snippet: snippet,
          remediation: 'Review the purpose of external URLs and ensure they are legitimate and necessary.'
        });
      }
    }
  }

  private checkPackageJson(content: string, file: GitHubFile): void {
    try {
      const pkg = JSON.parse(content);
      
      // Check for suspicious package names (typosquatting)
      const dependencies = { ...pkg.dependencies, ...pkg.devDependencies };
      
      // Known malicious patterns or typosquatting
      const suspiciousPatterns = [
        /^(colors|faker|request|lodash|underscore|moment|axios|express)[\d-_]/i,
        /\d{6,}/,  // Random numbers
        /^[a-z]{2,3}\d+$/,  // Short name + numbers
      ];

      Object.keys(dependencies || {}).forEach(name => {
        const isSuspicious = suspiciousPatterns.some(pattern => pattern.test(name));
        
        if (isSuspicious) {
          this.findings.push({
            severity: 'high',
            category: 'Package Dependencies',
            title: 'Suspicious package dependency detected',
            description: `Package "${name}" has patterns similar to typosquatting or malicious packages.`,
            file: file.name,
            remediation: 'Verify package authenticity and check for typos in package names.'
          });
        }
      });

      // Check for pre/post install scripts
      const scripts = pkg.scripts || {};
      ['preinstall', 'postinstall', 'preuninstall', 'postuninstall'].forEach(hook => {
        if (scripts[hook]) {
          this.findings.push({
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
      // Invalid JSON
      this.findings.push({
        severity: 'low',
        category: 'Package Configuration',
        title: 'Invalid package.json',
        description: 'package.json file contains invalid JSON.',
        file: file.name,
        remediation: 'Fix JSON syntax errors in package.json.'
      });
    }
  }

  private checkPermissions(content: string, file: GitHubFile, lines: string[]): void {
    // Check for excessive tool permissions in SKILL.md or manifest
    const toolPatterns = [
      /tools?[:\s]*\[([^\]]+)\]/gi,
      /"tools?"[:\s]*\[([^\]]+)\]/gi
    ];

    toolPatterns.forEach(pattern => {
      const matches = Array.from(content.matchAll(pattern));
      for (const match of matches) {
        const toolsString = match[1];
        const tools = toolsString.split(',').map(t => t.trim().replace(/['"]/g, ''));
        
        if (tools.length > 5) {
          const lineNumber = this.getLineNumber(content, match.index!);
          const snippet = lines[lineNumber - 1]?.trim();

          this.findings.push({
            severity: 'medium',
            category: 'Permissions',
            title: 'Excessive tool permissions requested',
            description: `Skill requests access to ${tools.length} tools, which may be more than necessary.`,
            file: file.name,
            line: lineNumber,
            snippet: snippet,
            remediation: 'Review tool permissions and request only the minimum necessary tools.'
          });
        }

        // Check for particularly sensitive tools
        const sensitiveTools = ['exec', 'shell', 'file_system', 'network', 'system'];
        const requestedSensitive = tools.filter(tool => 
          sensitiveTools.some(sensitive => 
            tool.toLowerCase().includes(sensitive)
          )
        );

        if (requestedSensitive.length > 0) {
          const lineNumber = this.getLineNumber(content, match.index!);
          const snippet = lines[lineNumber - 1]?.trim();

          this.findings.push({
            severity: 'high',
            category: 'Sensitive Permissions',
            title: 'Sensitive tool permissions requested',
            description: `Skill requests sensitive tools: ${requestedSensitive.join(', ')}`,
            file: file.name,
            line: lineNumber,
            snippet: snippet,
            remediation: 'Ensure sensitive tool access is necessary and properly secured.'
          });
        }
      }
    });
  }

  private getLineNumber(content: string, index: number): number {
    return content.substring(0, index).split('\n').length;
  }

  private isUnboundedExec(snippet: string): boolean {
    // Check if exec call uses user input or variables that could be controlled
    return snippet.includes('process.argv') || 
           snippet.includes('input') || 
           snippet.includes('${') ||
           snippet.includes('`') ||
           !snippet.includes('"') && !snippet.includes("'");
  }

  private hasSuspiciousDomain(snippet: string): boolean {
    const suspiciousDomains = ['pastebin.com', 'webhook.site', 'ngrok.io', 'localhost'];
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
          score -= 25;
          break;
        case 'high':
          score -= 15;
          break;
        case 'medium':
          score -= 8;
          break;
        case 'low':
          score -= 3;
          break;
        case 'info':
          score -= 1;
          break;
      }
    }

    return Math.max(0, Math.min(100, score));
  }

  private calculateGrade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
  }

  private generateSummary(): string {
    const criticalCount = this.findings.filter(f => f.severity === 'critical').length;
    const highCount = this.findings.filter(f => f.severity === 'high').length;
    const mediumCount = this.findings.filter(f => f.severity === 'medium').length;

    if (criticalCount > 0) {
      return `Found ${criticalCount} critical security ${criticalCount === 1 ? 'issue' : 'issues'}. Immediate attention required.`;
    }
    
    if (highCount > 0) {
      return `Found ${highCount} high-risk ${highCount === 1 ? 'issue' : 'issues'}. Review recommended before installation.`;
    }
    
    if (mediumCount > 0) {
      return `Found ${mediumCount} medium-risk ${mediumCount === 1 ? 'issue' : 'issues'}. Generally safe but worth reviewing.`;
    }
    
    return 'No significant security issues detected. Appears safe to install.';
  }
}